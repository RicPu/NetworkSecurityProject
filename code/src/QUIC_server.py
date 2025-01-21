import os
import json
import logging
import asyncio
from aioquic.asyncio.server import serve
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol

from utils import gen_key_cert


logging.basicConfig(level=logging.INFO)


class FileTransferServer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_data = {}
        self.logger = logging.getLogger(__name__)

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            self.logger.info("Handshake completed!")
        elif isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if stream_id not in self.stream_data:
                request = json.loads(data.decode())
                action = request.get("action")

                if action == "request_file":
                    file_name = request.get("file_name")
                    asyncio.create_task(self.request_file(file_name))
                else:
                    self.logger.error("Unknown action received from client.")

            else:
                self.stream_data[stream_id]["data"].extend(data)

            if event.end_stream:
                self.stream_data.pop(stream_id, None)

    async def request_file(self, file_name: str):
        self.logger.info(f"Client is requesting file: {file_name}")
        file_path = os.path.join("code/assets/server_directory", file_name)

        if os.path.exists(file_path) and os.path.isfile(file_path):
            stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
            reader, writer = await self.create_stream(stream_id)

            file_size = os.path.getsize(file_path)
            metadata = json.dumps(
                {"file_name": file_name, "file_size": file_size}
            ).encode()

            try:
                writer.write(metadata + b"\n")
                await writer.drain()

                with open(file_path, "rb") as file:
                    while chunk := file.read(4096):
                        writer.write(chunk)
                        await writer.drain()
                    writer.write_eof()
                    await writer.drain()

                self.logger.info("File sent.")

            finally:
                writer.close()
                await writer.wait_closed()


async def main(host: str, port: int, configuration: QuicConfiguration):
    await serve(
        host, port, configuration=configuration, create_protocol=FileTransferServer
    )

    logging.info("Server running...")
    await asyncio.Future()


if __name__ == "__main__":
    host = "::"
    port = 4433
    gen_key_cert()

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(
        certfile="code/assets/certificate.pem", keyfile="code/assets/private_key.pem"
    )

    asyncio.run(main(host, port, configuration))
