import os
import ssl
import json
import asyncio
import logging
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.client import connect


logging.basicConfig(level=logging.INFO)


class FileTransferClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connected_event = asyncio.Event()

    # For debugging purposes
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            logging.info("Handshake completed!")
            self.connected_event.set()
        elif isinstance(event, StreamDataReceived):
            logging.info(f"Stream data received: {len(event.data)} bytes on stream {event.stream_id}")
        elif isinstance(event, ConnectionTerminated):
            logging.info(f"Connection terminated: {event.error_code}, reason: {event.frame_type}")
    
    def close(self):
        logging.info("Closing connection.")
        super().close()


async def send_file(host: str, port: int, file_path: str, configuration: QuicConfiguration):
    async with connect(
        host, port, configuration=configuration, create_protocol=FileTransferClient
    ) as protocol:
        
        await protocol.wait_connected()

        file_name = file_path.split("/")[-1]
        file_size = os.path.getsize(file_path)

        metadata = json.dumps({
            "file_name": file_name,
            "file_size": file_size
        }).encode()

        stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
        reader, writer = await protocol.create_stream(stream_id)

        try:
            writer.write(metadata + b'\n')
            await writer.drain()

            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    writer.write(chunk)
                    await writer.drain()
            logging.info(f"File {file_path} sent successfully.")
        finally:
            writer.close()
            await writer.wait_closed()

        protocol.close()
        await protocol.wait_closed()


if __name__ == "__main__":
    host = "localhost"
    port = 4433
    image_path = "code/assets/Summer_1.jpg"

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    asyncio.run(send_file(host, port, image_path, configuration))
