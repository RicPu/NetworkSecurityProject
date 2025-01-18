import asyncio
import logging
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from utils import gen_key_cert


logging.basicConfig(level=logging.INFO)


class FileTransferProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_data = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            logging.info(f"Received chunk of size {len(data)} on stream {stream_id}")

            if stream_id not in self.stream_data:
                self.stream_data[stream_id] = bytearray()
            self.stream_data[stream_id].extend(data)

            if event.end_stream:
                with open(f"received_image_{stream_id}.jpg", "wb") as file:
                    file.write(self.stream_data[stream_id])

                logging.info(f"Image received and saved as 'received_image_{stream_id}.jpg'")
                del self.stream_data[stream_id]


async def main(host: str, port: int, configuration: QuicConfiguration):
    await serve(
        host, port, configuration=configuration,
        create_protocol=FileTransferProtocol
    )
    logging.info("Server running...")
    await asyncio.Future()


if __name__ == "__main__":
    host = "::"
    port = 4433
    gen_key_cert() # Generate private key and certificate

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(
        certfile="code/assets/certificate.pem", 
        keyfile="code/assets/private_key.pem"
    )

    asyncio.run(main(host, port, configuration))
