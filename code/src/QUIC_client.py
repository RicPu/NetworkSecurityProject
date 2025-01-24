import os
import ssl
import json
import asyncio
import logging
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import QuicEvent, HandshakeCompleted, StreamDataReceived

from utils import parse_metadata, save_file


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
                    "file_size": file_size
                }
            else:
                self.stream_data[stream_id]["data"].extend(data)
            
            if event.end_stream:
                file_name = self.stream_data[stream_id]["file_name"]
                save_file(file_name, self.stream_data[stream_id]["data"], is_client=True)
                self.stream_data.pop(stream_id)


async def upload_file(client: FileTransferClient, file_path: str):
    file_name = os.path.basename(file_path)
    
    upload_request = json.dumps({
        "action": "upload_file",
        "file_name": file_name
    }).encode()

    reader, writer = await client.create_stream()
    try:
        writer.write(upload_request)
        await writer.drain()
        client.transmit()

        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                writer.write(chunk)
                await writer.drain()
                client.transmit()
        writer.write_eof()
        await writer.drain()
        client.logger.info(f"File {file_name} sent.")
    finally:
        writer.close()
        await writer.wait_closed()


async def download_file(client: FileTransferClient, file_name: str):
    download_request = json.dumps({
        "action": "download_file",
        "file_name": file_name
    }).encode()

    reader, writer = await client.create_stream()
    try:
        writer.write(download_request)
        await writer.drain()
        client.transmit()

        writer.write_eof()
        await writer.drain()
        client.transmit()
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

        if action == "upload_file":
            await upload_file(client, file_path="code/assets/client_directory/Winter_1.jpg")
        elif action == "download_file":
            await download_file(client, "Summer_1.jpg")
        else:
            logging.info("No other actions.")
        
        client.close()


if __name__ == "__main__":
    host = "localhost"
    port = 4433

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    asyncio.run(main(host, port, configuration, "download_file"))
