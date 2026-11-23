from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncGenerator
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Coroutine
from contextlib import asynccontextmanager
from io import BytesIO
from pathlib import Path

import pytest

from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import ClamdUnixSocket
from clamav_client.clamd import ScanResults

Handler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter], Coroutine[None, None, None]
]


@pytest.fixture(params=["tcp", "unix"])
def transport(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@asynccontextmanager
async def serve_clamd(
    transport: str, tmp_path: Path, handler: Handler
) -> AsyncGenerator[ClamdNetworkSocket, None]:
    tasks: list[asyncio.Task[None]] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await handler(reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tasks.append(asyncio.create_task(handle(reader, writer)))

    if transport == "unix":
        path = str(tmp_path / "s")
        server = await asyncio.start_unix_server(accept, path=path)
        client: ClamdNetworkSocket = ClamdUnixSocket(path, timeout=2)
    else:
        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = ClamdNetworkSocket("127.0.0.1", port, timeout=2)
    try:
        yield client
    finally:
        server.close()
        await server.wait_closed()
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException) and not isinstance(
                result, asyncio.CancelledError
            ):
                raise result


async def read_stream(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while size := struct.unpack("!L", await reader.readexactly(4))[0]:
        body.extend(await reader.readexactly(size))
    return bytes(body)


async def test_concurrent_streams_keep_scan_results_separate(
    transport: str, tmp_path: Path
) -> None:
    slow_started = asyncio.Event()
    release_slow = asyncio.Event()

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        assert await reader.readline() == b"nINSTREAM\n"
        body = await read_stream(reader)
        if body == b"clean" * 1024:
            slow_started.set()
            await release_slow.wait()
            writer.write(b"stream: OK\n")
        else:
            assert body == b"infected" * 1024
            writer.write(b"stream: Test-Signature FOUND\n")
        await writer.drain()

    async with serve_clamd(transport, tmp_path, handle) as client:
        slow = asyncio.create_task(client.instream(BytesIO(b"clean" * 1024)))
        try:
            await asyncio.wait_for(slow_started.wait(), 1)
            result = await asyncio.wait_for(
                client.instream(BytesIO(b"infected" * 1024)), 1
            )
            assert result == {"stream": ("FOUND", "Test-Signature")}
            assert not slow.done()
            release_slow.set()
            assert await asyncio.wait_for(slow, 1) == {"stream": ("OK", None)}
        finally:
            release_slow.set()
            slow.cancel()
            await asyncio.gather(slow, return_exceptions=True)


@pytest.mark.parametrize(
    "command",
    ["ping", "version", "reload", "stats", "scan", "contscan", "multiscan", "shutdown"],
)
async def test_commands_do_not_close_another_scan(
    transport: str, tmp_path: Path, command: str
) -> None:
    slow_started = asyncio.Event()
    release_slow = asyncio.Event()
    replies = {
        b"nPING\n": b"PONG\n",
        b"nVERSION\n": b"ClamAV test\n",
        b"nRELOAD\n": b"RELOADING\n",
        b"nSTATS\n": b"POOLS: 1\nEND\n",
        b"nSCAN /file\n": b"/file: OK\n",
        b"nCONTSCAN /file\n": b"/file: OK\n",
        b"nMULTISCAN /file\n": b"/file: OK\n",
        b"nSHUTDOWN\n": b"",
    }

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request = await reader.readline()
        if request == b"nINSTREAM\n":
            assert await read_stream(reader) == b"clean"
            slow_started.set()
            await release_slow.wait()
            writer.write(b"stream: OK\n")
        else:
            writer.write(replies[request])
        await writer.drain()

    async with serve_clamd(transport, tmp_path, handle) as client:
        operations: dict[str, tuple[Callable[[], Awaitable[object]], object]] = {
            "ping": (client.ping, "PONG"),
            "version": (client.version, "ClamAV test"),
            "reload": (client.reload, "RELOADING"),
            "stats": (client.stats, "POOLS: 1\nEND\n"),
            "scan": (lambda: client.scan("/file"), {"/file": ("OK", None)}),
            "contscan": (lambda: client.contscan("/file"), {"/file": ("OK", None)}),
            "multiscan": (lambda: client.multiscan("/file"), {"/file": ("OK", None)}),
            "shutdown": (client.shutdown, None),
        }
        operation, expected = operations[command]
        slow = asyncio.create_task(client.instream(BytesIO(b"clean")))
        try:
            await asyncio.wait_for(slow_started.wait(), 1)
            assert await asyncio.wait_for(operation(), 1) == expected
            assert not slow.done()
            release_slow.set()
            assert await asyncio.wait_for(slow, 1) == {"stream": ("OK", None)}
        finally:
            release_slow.set()
            slow.cancel()
            await asyncio.gather(slow, return_exceptions=True)


async def test_cancelling_scan_does_not_close_another_connection(
    transport: str, tmp_path: Path
) -> None:
    survivor_started = asyncio.Event()
    cancelled_started = asyncio.Event()
    cancelled_closed = asyncio.Event()
    release_survivor = asyncio.Event()

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        assert await reader.readline() == b"nINSTREAM\n"
        body = await read_stream(reader)
        if body == b"survivor":
            survivor_started.set()
            await release_survivor.wait()
            writer.write(b"stream: OK\n")
            await writer.drain()
        else:
            assert body == b"cancelled"
            cancelled_started.set()
            assert await reader.read() == b""
            cancelled_closed.set()

    async with serve_clamd(transport, tmp_path, handle) as client:
        survivor = asyncio.create_task(client.instream(BytesIO(b"survivor")))
        cancelled: asyncio.Task[ScanResults] | None = None
        try:
            await asyncio.wait_for(survivor_started.wait(), 1)
            cancelled = asyncio.create_task(client.instream(BytesIO(b"cancelled")))
            await asyncio.wait_for(cancelled_started.wait(), 1)
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            await asyncio.wait_for(cancelled_closed.wait(), 1)
            assert not survivor.done()
            release_survivor.set()
            assert await asyncio.wait_for(survivor, 1) == {"stream": ("OK", None)}
        finally:
            release_survivor.set()
            survivor.cancel()
            if cancelled is not None:
                cancelled.cancel()
                await asyncio.gather(cancelled, return_exceptions=True)
            await asyncio.gather(survivor, return_exceptions=True)
