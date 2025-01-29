import os
import asyncio
import logging
from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from utils import gen_key_cert


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quic-server")


class FileTransferServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_handlers = {}
        logger.info("New client connection established")

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            logger.debug(
                f"Received data on stream {event.stream_id} ({len(event.data)} bytes)"
            )
            if event.stream_id not in self.stream_handlers:
                logger.info(f"Creating new handler for stream {event.stream_id}")
                reader, writer = self._create_stream(event.stream_id)
                handler = asyncio.create_task(
                    self.handle_stream(reader, writer, event.stream_id)
                )
                self.stream_handlers[event.stream_id] = handler
            self._stream_readers[event.stream_id].feed_data(event.data)
            
            if event.end_stream:
                logger.debug(f"End of stream {event.stream_id}")
                self._stream_readers[event.stream_id].feed_eof()

    async def handle_stream(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream_id: int
    ):
        """
        Handle file transfer stream.
        """
        try:
            logger.info(f"Processing stream {stream_id}")
            command = await reader.readuntil(b"\n")
            cmd, _, filename = command.decode().strip().partition(" ")
            logger.info(f"Received command: {cmd.upper()} {filename}")

            if cmd == "upload":
                logger.info(f"Starting upload to {filename}")
                content = await reader.read()
                
                file_path = os.path.join("code/assets/server_directory", filename)
                with open(file_path, "wb") as file:
                    file.write(content)

                logger.info(f"File {filename} saved ({len(content)} bytes)")
                writer.write(b"File uploaded successfully")

            elif cmd == "download":
                logger.info(f"Processing download request for {filename}")
                try:
                    file_path = os.path.join("code/assets/server_directory", filename)
                    with open(file_path, "rb") as file:
                        content = file.read()
                        writer.write(content)
                        logger.info(f"Sent {len(content)} bytes for {filename}")

                except FileNotFoundError:
                    logger.warning(f"File not found: {filename}")
                    writer.write(b"File not found")

            await writer.drain()
            logger.info(f"Completed processing stream {stream_id}")

        except Exception as e:
            logger.error(f"Error handling stream {stream_id}: {str(e)}")
        finally:
            writer.close()
            del self.stream_handlers[stream_id]
            logger.debug(f"Closed stream {stream_id}")


async def main():
    configuration = QuicConfiguration(is_client=False)
    try:
        configuration.load_cert_chain(
            certfile="code/assets/certificate.pem",
            keyfile="code/assets/private_key.pem",
        )
        logger.info("SSL certificates loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load certificates: {str(e)}")
        return

    logger.info("Starting QUIC server on [::]:4433")
    await serve(
        "::",
        4433,
        configuration=configuration,
        create_protocol=FileTransferServerProtocol,
    )
    logger.info("Server is ready to accept connections")

    await asyncio.Future()


if __name__ == "__main__":
    gen_key_cert()
    asyncio.run(main())
