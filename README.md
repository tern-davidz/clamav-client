# clamav-client

`clamav-client` is a portable Python module to use the ClamAV anti-virus engine
on Windows, Linux, MacOSX and other platforms. It requires a running instance
of the `clamd` daemon.

This is a fork of, [clamav-client], that is a fork of  [clamd]. It introduces
asyncio and paralell scans on a single event loop.

## Basic usage

The `clamav_client.clamd` module offers a client for the `clamd` daemon,
supporting both TCP and Unix sockets.

The `clamav_client.scanner` module provides a high-level file scanner that works
with both `clamd` and `clamscan`. Use `clamav_client.get_scanner()` to configure
it.


[clamd]: https://github.com/graingert/python-clamd
[clamav-client]: https://github.com/artefactual-labs/clamav-client