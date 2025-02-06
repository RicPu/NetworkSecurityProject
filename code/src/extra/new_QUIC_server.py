import asyncio
import logging
import os
import time
import hashlib
import aiofiles
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.events import ProtocolNegotiated
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from utils import gen_key_cert  # Remove if not using custom certs

HOST = "::"
PORT = 4433
STORAGE_DIR = r"code\assets\server_directory"
CERT_FILE = r"code\assets\certificate.pem"
PRIVATE_KEY_FILE = r"code\assets\private_key.pem"

logger = logging.getLogger("server")

class FileTransferHandler(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._streams = {}

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    self._streams[http_event.stream_id] = {
                        "headers": http_event.headers,
                        "data": b"",
                        "start_time": None  # Added for timing
                    }
                elif isinstance(http_event, DataReceived):
                    stream_id = http_event.stream_id
                    if stream_id not in self._streams:
                        self._streams[stream_id] = {
                            "data": b"",
                            "start_time": time.time()  # First data arrival
                        }
                    else:
                        # Record first chunk arrival time
                        if self._streams[stream_id]["start_time"] is None:
                            self._streams[stream_id]["start_time"] = time.time()
                    
                    self._streams[stream_id]["data"] += http_event.data
                    
                    if http_event.stream_ended:
                        # Record end time when stream closes
                        self._streams[stream_id]["end_time"] = time.time()
                        asyncio.create_task(self.handle_request(stream_id))

    async def handle_request(self, stream_id):
        stream_data = self._streams[stream_id]
        headers = stream_data["headers"]
        data = stream_data["data"]
        
        # Calculate throughput
        duration = stream_data["end_time"] - stream_data["start_time"]
        throughput = (len(data) * 8) / duration / 1e6  # Mbps
        print(f"Server throughput: {throughput:.2f} Mbps")

        # Rest of existing code remains the same
        method = path = ""
        for header, value in headers:
            if header == b":method":
                method = value.decode()
            elif header == b":path":
                path = value.decode().lstrip("/")

        file_path = os.path.join(STORAGE_DIR, path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if method == "POST":
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(data)
            
            server_checksum = hashlib.sha256(data).hexdigest()
            print(f"Server checksum: {server_checksum}")
            
            self._http.send_headers(
                stream_id=stream_id,
                headers=[(b":status", b"200")]
            )
            self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)
            print(f"Saved {len(data)} bytes | Throughput: {throughput:.2f} Mbps")

async def main():
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_data=1_000_000_000,
        max_stream_data=100_000_000,
        quic_logger=None
    )
    configuration.load_cert_chain(CERT_FILE, PRIVATE_KEY_FILE)

    await serve(
        HOST,
        PORT,
        configuration=configuration,
        create_protocol=FileTransferHandler
    )
    print(f"Server running on {HOST}:{PORT}")
    await asyncio.Future()

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    try:
        gen_key_cert()  # Remove if using real certificates
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped")