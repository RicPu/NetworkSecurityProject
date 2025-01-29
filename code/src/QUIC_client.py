import os
import ssl
import asyncio
import logging
from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quic-client")


class FileTransferClientProtocol(QuicConnectionProtocol):
    async def upload(self, local_path: str):
        """
        Upload a file to the server.
        """
        file_name = os.path.basename(local_path)
        logger.info(f"Starting upload of {local_path}")
        try:
            reader, writer = await self.create_stream()

            command = f"upload {file_name}\n"
            writer.write(command.encode())
            logger.debug(f"Sent upload command: {command.strip()}")

            with open(local_path, "rb") as file:
                content = file.read()
                writer.write(content)
                logger.info(f"Sent {len(content)} bytes for {file_name}")

            await writer.drain()
            writer.write_eof()

            response = await reader.read()
            logger.error(f"Server response: {response.decode()}")

        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            raise

    async def download(self, file_name: str, local_path: str):
        """
        Download a file from the server.
        """
        logger.info(f"Starting download of {file_name} to {local_path}")
        try:
            reader, writer = await self.create_stream()

            command = f"download {file_name}\n"
            writer.write(command.encode())
            logger.debug(f"Sent download command: {command.strip()}")
            writer.write_eof()

            data = await reader.read()
            if data == b"File not found":
                logger.warning(f"File not found on server: {file_name}")
            else:
                file_path = os.path.join(local_path, file_name)
                with open(file_path, "wb") as file:
                    file.write(data)
                logger.info(f"Received {len(data)} bytes, saved to {file_path}")

        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            raise


async def main():
    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    try:
        logger.info("Connecting to QUIC server at localhost:4433")
        async with connect(
            "localhost",
            4433,
            configuration=configuration,
            create_protocol=FileTransferClientProtocol,
        ) as protocol:
            await protocol.wait_connected()
            logger.info("Successfully connected to server")

            # Example upload
            # await protocol.upload("code/assets/client_directory/Winter_1.jpg")

            # Example download
            await protocol.download("Summer_1.jpg", "code/assets/client_directory")

            protocol.close()
            await protocol.wait_closed()
            logger.info("Connection closed")

    except Exception as e:
        logger.error(f"Client error: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())
