import os
import ssl
import json
import asyncio
import logging
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived

from utils import save_file, parse_metadata


logging.basicConfig(level=logging.INFO)


class FileTransferClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_data = {}
        self.logger = logging.getLogger(__name__)

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            self.logger.info("Handshake completed!")
        if isinstance(event, StreamDataReceived):
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
                save_file(file_name, self.stream_data[stream_id]["data"])
                self.stream_data.pop(stream_id, None)


async def send_request(client: QuicConnectionProtocol, request: bytes):
    reader, writer = await client.create_stream()

    try:
        writer.write(request)
        await writer.drain()
        client.transmit()
    finally:
        writer.close()
        await writer.wait_closed()


async def send_file(client: QuicConnectionProtocol, file_name: str):
    file_path = os.path.join("code/assets/client_directory", file_name)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        reader, writer = await client.create_stream()

        file_size = os.path.getsize(file_path)
        metadata = json.dumps(
            {
                "file_name": file_name,
                "file_size": file_size
            }
        ).encode()

        try:
            writer.write(metadata + b'\n')
            client.transmit()

            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    writer.write(chunk)
                    await writer.drain()

            writer.write_eof()
            await writer.drain()

        finally:
            writer.close()
            await writer.wait_closed()


async def main(
    host: str, port: int, configuration: QuicConfiguration, action: str
):
    async with connect(
        host, port, configuration=configuration, create_protocol=FileTransferClient
    ) as client:
        await client.wait_connected()

        request = json.dumps({"action": action, "file_name": "Summer_1.jpg"}).encode()

        #await send_file(client, "Winter_1.jpg")
        await send_request(client, request)


if __name__ == "__main__":
    host = "localhost"
    port = 4433

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    asyncio.run(main(host, port, configuration, "request_file"))
