import os
import json
import logging
import asyncio
from aioquic.asyncio.server import serve
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol

from utils import gen_key_cert, parse_metadata, save_file


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
                file_name = request.get("file_name")
                print(action)

                if action == "request_file":
                    asyncio.create_task(self.send_file(file_name))
                elif action == "send_file":
                    asyncio.create_task(self.receive_file(file_name, event))
                else:
                    self.logger.error("Unknown action received from client.")

            else:
                self.stream_data[stream_id]["data"].extend(data)

            if event.end_stream:
                self.logger.info("Stream ended.")
                self.stream_data.pop(stream_id, None)

    async def send_file(self, file_name: str):
        self.logger.info(f"Client is requesting file: {file_name}")
        file_path = os.path.join("code/assets/server_directory", file_name)

        if os.path.exists(file_path) and os.path.isfile(file_path):
            reader, writer = await self.create_stream()

            file_size = os.path.getsize(file_path)
            metadata = json.dumps(
                {"file_name": file_name, "file_size": file_size}
            ).encode()

            try:
                writer.write(metadata + b"\n")
                await writer.drain()
                self.transmit()

                with open(file_path, "rb") as file:
                    while chunk := file.read(4096):
                        writer.write(chunk)
                        await writer.drain()

                writer.write_eof()
                await writer.drain()
                self.transmit()
                self.logger.info(f"Finished sending file {file_name}")

            finally:
                self.logger.info("Attempting to close the writer.")
                writer.close()
                await (
                    writer.wait_closed()
                )  # there's a bug where, for some reason, this hangs indefinitely

    async def receive_file(self, file_name: str, event: StreamDataReceived):
        self.logger.info(f"Client wants to send the file: {file_name}")
        stream_id = event.stream_id
        data = event.data

        if stream_id not in self.stream_data:
            metadata, remaining_data = parse_metadata(data)

            file_name = metadata.get("file_name")
            file_size = metadata.get("file_size")

            self.stream_data[stream_id] = {
                "data": bytearray(remaining_data),
                "file_name": file_name,
                "file_size": file_size,
            }
        else:
            self.stream_data[stream_id]["data"].extend(data)

        if event.end_stream:
            file_name = self.stream_data[stream_id]["file_name"]
            save_file(file_name, self.stream_data[stream_id]["data"], is_client=False)
            self.stream_data.pop(stream_id, None)


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
