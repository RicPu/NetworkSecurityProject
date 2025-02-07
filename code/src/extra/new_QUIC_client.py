import asyncio
import logging
import ssl
import hashlib
from urllib.parse import urlparse
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived
from aioquic.quic.configuration import QuicConfiguration

URL = "https://localhost:4433/Winter_1.jpg"
UPLOAD_FILE = r"code\assets\client_directory\Winter_1.jpg"
INSECURE = True

logger = logging.getLogger("client")


class FileTransferClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._waiter = None

    async def upload_file(self, url: str, file_path: str):
        parsed = urlparse(url)
        with open(file_path, "rb") as f:
            data = f.read()

        # Calculate checksum
        client_checksum = hashlib.sha256(data).hexdigest()
        print(f"Client checksum: {client_checksum}")

        self._quic._loss._pacer = False
        stream_id = self._quic.get_next_available_stream_id()
        chunk_size = 1048576
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

        # Start throughput timer
        start_time = time.time()

        # Send headers
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", parsed.hostname.encode()),
                (b":path", parsed.path.encode()),
                (b"content-length", str(len(data)).encode()),
            ],
        )

        # Send chunks
        for i, chunk in enumerate(chunks):
            self._http.send_data(
                stream_id=stream_id, data=chunk, end_stream=(i == len(chunks) - 1)
            )
            self.transmit()

        # Wait for server confirmation
        self._waiter = self._loop.create_future()
        await self._waiter

        # Calculate throughput
        end_time = time.time()
        duration = end_time - start_time
        throughput = (len(data) * 8) / duration / 1e6  # Mbps
        print(f"Uploaded {file_path} | Throughput: {throughput:.2f} Mbps")

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, DataReceived):
                if http_event.stream_ended and self._waiter:
                    self._waiter.set_result(True)


async def main():
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        max_data=1_000_000_000,
        max_stream_data=100_000_000,
        quic_logger=None,
    )
    if INSECURE:
        configuration.verify_mode = ssl.CERT_NONE

    async with connect(
        "localhost",
        4433,
        configuration=configuration,
        create_protocol=FileTransferClient,
    ) as client:
        await client.upload_file(URL, UPLOAD_FILE)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
