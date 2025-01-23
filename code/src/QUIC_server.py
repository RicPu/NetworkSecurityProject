import os
import json
import logging
import asyncio
from aioquic.asyncio.server import serve
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol

from utils import gen_key_cert, save_file


logging.basicConfig(level=logging.INFO)


class FileTransferServer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_data = {}
        self.logger = logging.getLogger(__name__)
    
    async def download_file(self, file_name: str):
        self.logger.info(f"Client is requesting file: {file_name}")
        file_path = os.path.join("code/assets/server_directory", file_name)

        if os.path.exists(file_path) and os.path.isfile(file_path):
            reader, writer = await self.create_stream()

            file_size = os.path.getsize(file_path)
            metadata = json.dumps({
                "file_name": file_name,
                "file_size": file_size
            }).encode()

            try:
                writer.write(metadata + b'\n')
                await writer.drain()
                self.transmit()

                with open(file_path, "rb") as file:
                    while chunk := file.read(4096):
                        writer.write(chunk)
                        await writer.drain()
                writer.write_eof()
                await writer.drain()
                self.transmit()
                self.logger.info(f"File {file_name} sent.")
            finally:
                writer.close()
                await writer.wait_closed()


    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            self.logger.info("Handshake completed!")
        elif isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if stream_id not in self.stream_data:
                self.stream_data[stream_id] = {
                    "action": None,
                    "buffer": b"",
                    "file_name": None
                }
            
            stream_context = self.stream_data[stream_id]

            if stream_context["action"] is None:
                request = json.loads(data.decode())

                if request.get("action") == "upload_file":
                    stream_context["action"] = "upload_file"
                    stream_context["file_name"] = request.get("file_name")
                    self.logger.info(f"Client wants to upload file: {stream_context['file_name']}")

                elif request.get("action") == "download_file":
                    stream_context["action"] = "download_file"
                    stream_context["file_name"] = request.get("file_name")
                    self.logger.info("Client requested to download a file.")
                    
                else:
                    self.logger.error("Unknown request.")
                    self.stream_data.pop(stream_id)
                    return
            else:
                if stream_context["action"] == "upload_file":
                    stream_context["buffer"] += data
                    if event.end_stream:
                        save_file(stream_context["file_name"], stream_context["buffer"], is_client=False)
                        self.stream_data.pop(stream_id)

                elif stream_context["action"] == "download_file":
                    asyncio.create_task(self.download_file(stream_context["file_name"]))


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
