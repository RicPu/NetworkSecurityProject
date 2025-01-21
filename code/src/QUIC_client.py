import os
import ssl
import json
import asyncio
import logging
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived


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
                metadata, remaining_data = self.parse_metadata(data)

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
                self.save_file(file_name, self.stream_data[stream_id]["data"])
                self.stream_data.pop(stream_id, None)

    def parse_metadata(self, data: bytes):
        try:
            metadata, remaining_data = data.split(b"\n", 1)
            return json.loads(metadata.decode()), remaining_data

        except Exception as e:
            self.logger.error(f"Error parsing metadata: {e}")
            return None, data

    def save_file(self, file_name: str, file_data: bytes):
        try:
            save_path = os.path.join("code/assets/client_directory", file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, "wb") as file:
                file.write(file_data)
            self.logger.info(f"File saved as '{save_path}'")

        except Exception as e:
            self.logger.error(f"Error saving file '{file_name}': {e}")


async def send_request(client: QuicConnectionProtocol, request: bytes):
    stream_id = client._quic.get_next_available_stream_id(is_unidirectional=True)
    reader, writer = await client.create_stream(stream_id)

    try:
        writer.write(request)
        await writer.drain()
        writer.write_eof()
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main(host: str, port: int, configuration: QuicConfiguration, action: str):
    async with connect(
        host, port, configuration=configuration, create_protocol=FileTransferClient
    ) as client:
        await client.wait_connected()

        request = json.dumps(
            {"action": "request_file", "file_name": "Summer_1.jpg"}
        ).encode()
        await send_request(client, request)


if __name__ == "__main__":
    host = "localhost"
    port = 4433

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    asyncio.run(main(host, port, configuration, None))
