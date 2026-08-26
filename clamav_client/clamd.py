"""A client for the ClamAV daemon (clamd), supporting both TCP and Unix socket
connections.

This module stays as close as possible to its original counterpart, the clamd
project on which this code is based, to maintain backward compatibility.
"""

import asyncio
import re
import struct
from collections.abc import Awaitable
from typing import Any
from typing import BinaryIO
from typing import Optional
from typing import TypeVar
from typing import Union

scan_response = re.compile(
    r"^(?P<path>[^:]+): ((?P<virus>.+?) )?(?P<status>(FOUND|OK|ERROR))$"
)


ScanStatus = str
ScanResult = tuple[ScanStatus, Optional[str]]
ScanResults = dict[str, ScanResult]
T = TypeVar("T")


class ClamdError(Exception):
    pass


class ResponseError(ClamdError):
    pass


class BufferTooLongError(ResponseError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class CommunicationError(ClamdError):
    """Class for errors communication with clamd"""


class ClamdNetworkSocket:
    """
    Class for using clamd with a network socket
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 3310, timeout: Optional[float] = None
    ) -> None:
        """
        class initialisation

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : socket timeout
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def _init_socket(self) -> None:
        """
        internal use only
        """
        try:
            connection = asyncio.open_connection(self.host, self.port)
            self.reader, self.writer = await self._with_timeout(connection)
        except (OSError, asyncio.TimeoutError) as err:
            raise CommunicationError(self._error_message(err)) from err

    async def _with_timeout(self, awaitable: Awaitable[T]) -> T:
        if self.timeout is None:
            return await awaitable
        return await asyncio.wait_for(awaitable, self.timeout)

    def _error_message(self, exception: BaseException) -> str:
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return f"Error connecting to {self.host}:{self.port}. {exception.args[0]}."
        else:
            return f"Error {exception.args[0]} connecting {self.host}:{self.port}. {exception.args[1]}."

    async def ping(self) -> str:
        return await self._basic_command("PING")

    async def version(self) -> str:
        return await self._basic_command("VERSION")

    async def reload(self) -> str:
        return await self._basic_command("RELOAD")

    async def shutdown(self) -> None:
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            await self._init_socket()
            await self._send_command("SHUTDOWN")
        finally:
            await self._close_socket()

    async def scan(self, file: str) -> ScanResults:
        return await self._file_system_scan("SCAN", file)

    async def contscan(self, file: str) -> ScanResults:
        return await self._file_system_scan("CONTSCAN", file)

    async def multiscan(self, file: str) -> ScanResults:
        return await self._file_system_scan("MULTISCAN", file)

    async def _basic_command(self, command: str) -> str:
        """
        Send a command to the clamav server, and return the reply.
        """
        await self._init_socket()
        try:
            await self._send_command(command)
            response = await self._recv_response()
            if response is None:
                raise ResponseError()
            error = response.rsplit("ERROR", 1)
            if len(error) > 1:
                raise ResponseError(error[0])
            else:
                return error[0]
        finally:
            await self._close_socket()

    async def _file_system_scan(self, command: str, file: str) -> ScanResults:
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            await self._init_socket()
            await self._send_command(command, file)
            dr = {}
            response = await self._recv_response_multiline()
            if response is None:
                raise ResponseError()
            for result in response.split("\n"):
                if result:
                    filename, reason, status = self._parse_response(result)
                    dr[filename] = (status, reason)
            return dr
        finally:
            await self._close_socket()

    async def instream(self, buff: BinaryIO) -> ScanResults:
        """
        Scan a buffer

        buff  filelikeobj: buffer to scan

        return:
          - (dict): {filename1: ("virusname", "status")}

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """
        try:
            await self._init_socket()
            await self._send_command("INSTREAM")
            assert self.writer is not None
            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf
            chunk = buff.read(max_chunk_size)
            while chunk:
                size = struct.pack(b"!L", len(chunk))
                self.writer.write(size + chunk)
                await self.writer.drain()
                chunk = buff.read(max_chunk_size)
            self.writer.write(struct.pack(b"!L", 0))
            await self.writer.drain()
            result = await self._recv_response()
            if len(result) > 0:
                if result == "INSTREAM size limit exceeded. ERROR":
                    raise BufferTooLongError(result)
                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}
            else:
                return {}
        finally:
            await self._close_socket()

    async def stats(self) -> str:
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        await self._init_socket()
        try:
            await self._send_command("STATS")
            return await self._recv_response_multiline()
        finally:
            await self._close_socket()

    async def _send_command(self, cmd: str, *args: str) -> None:
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        concat_args = ""
        if args:
            concat_args = " " + " ".join(args)
        send = f"n{cmd}{concat_args}\n".encode()
        assert self.writer is not None
        self.writer.write(send)
        await self.writer.drain()

    async def _recv_response(self) -> str:
        """
        receive line from clamd
        """
        try:
            assert self.reader is not None
            response = await self._with_timeout(self.reader.readline())
            return response.decode("utf-8").strip()
        except (OSError, asyncio.TimeoutError) as err:
            raise CommunicationError(
                f"Error while reading from socket: {err.args}"
            ) from err

    async def _recv_response_multiline(self) -> str:
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        try:
            assert self.reader is not None
            response = await self._with_timeout(self.reader.read())
            return response.decode("utf-8")
        except (OSError, asyncio.TimeoutError) as err:
            raise CommunicationError(
                f"Error while reading from socket: {err.args}"
            ) from err

    async def _close_socket(self) -> None:
        """
        close clamd socket
        """
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

    def _parse_response(self, msg: str) -> tuple[Union[str, Any], ...]:
        """
        parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
        """
        if match := scan_response.match(msg):
            return match.group("path", "virus", "status")
        else:
            raise ResponseError(msg.rsplit("ERROR", 1)[0])


class ClamdUnixSocket(ClamdNetworkSocket):
    """
    Class for using clamd with an unix socket
    """

    def __init__(
        self, path: str = "/var/run/clamav/clamd.ctl", timeout: Optional[int] = None
    ) -> None:
        """
        class initialisation

        path (string) : unix socket path
        timeout (float or None) : socket timeout
        """

        scheme = "unix://"
        if path.startswith(scheme):
            path = path[len(scheme) :]
        self.unix_socket = path
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def _init_socket(self) -> None:
        """
        internal use only
        """
        try:
            connection = asyncio.open_unix_connection(self.unix_socket)
            self.reader, self.writer = await self._with_timeout(connection)
        except (OSError, asyncio.TimeoutError) as err:
            raise CommunicationError(self._error_message(err)) from err

    def _error_message(self, exception: BaseException) -> str:
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return f"Error connecting to {self.unix_socket}. {exception.args[0]}."
        else:
            return f"Error {exception.args[0]} connecting {self.unix_socket}. {exception.args[1]}."
