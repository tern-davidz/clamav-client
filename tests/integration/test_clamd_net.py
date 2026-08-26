from io import BytesIO
from typing import Callable
from typing import Optional

import pytest

from clamav_client.clamd import BufferTooLongError
from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import CommunicationError

EicarSignatureAsserter = Callable[[Optional[str]], None]


async def test_cannot_connect() -> None:
    with pytest.raises(CommunicationError):
        await ClamdNetworkSocket("127.0.0.1", 999).ping()


async def test_ping(clamd_net_client: ClamdNetworkSocket) -> None:
    await clamd_net_client.ping()


async def test_version(clamd_net_client: ClamdNetworkSocket) -> None:
    assert (await clamd_net_client.version()).startswith("ClamAV")


async def test_reload(clamd_net_client: ClamdNetworkSocket) -> None:
    assert await clamd_net_client.reload() == "RELOADING"


async def test_stats(clamd_net_client: ClamdNetworkSocket) -> None:
    assert "END" in await clamd_net_client.stats()


async def test_instream_found(
    clamd_net_client: ClamdNetworkSocket,
    eicar: bytes,
    assert_eicar_signature: EicarSignatureAsserter,
) -> None:
    result = await clamd_net_client.instream(BytesIO(eicar))
    assert "stream" in result
    status, signature = result["stream"]
    assert status == "FOUND"
    assert_eicar_signature(signature)


async def test_instream_ok(clamd_net_client: ClamdNetworkSocket) -> None:
    assert await clamd_net_client.instream(BytesIO(b"foo")) == {"stream": ("OK", None)}


@pytest.mark.xfail
async def test_instream_exceeded(
    clamd_net_client: ClamdNetworkSocket, really_big_file: BytesIO
) -> None:
    """TODO: this is raising BrokenPipeError instead of BufferTooLongError."""
    with pytest.raises(BufferTooLongError):
        await clamd_net_client.instream(really_big_file)
