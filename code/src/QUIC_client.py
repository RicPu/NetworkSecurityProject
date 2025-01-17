import ssl
import asyncio
import logging
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted

logging.basicConfig(level=logging.INFO)


class FileTransferClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connected_event = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            logging.info("Handshake completed!")
            self.connected_event.set()


async def send_image(host: str, port: int, image_path: str, configuration: QuicConfiguration):
    async with connect(
        host, port, configuration=configuration, create_protocol=FileTransferClient
    ) as protocol:
        
        await protocol.wait_connected()

        stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
        reader, writer = await protocol.create_stream(stream_id)

        try:
            with open(image_path, "rb") as f:
                while chunk := f.read(8192):
                    writer.write(chunk)
                    await writer.drain()
            logging.info(f"Image {image_path} sent successfully.")
        finally:
            writer.close()
            await writer.wait_closed()

        protocol.close()
        await protocol.wait_closed()


if __name__ == "__main__":
    host = "localhost"
    port = 4433
    image_path = "code/assets/Summer_1.png"

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    asyncio.run(send_image(host, port, image_path, configuration))
