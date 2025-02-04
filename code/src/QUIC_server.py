import os
import asyncio
import logging
import time  # Import time module to measure durations
import json  # For sending responses in JSON format
from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from utils import gen_key_cert

# Configure logging for the QUIC server
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quic-server")


class FileTransferServerProtocol(QuicConnectionProtocol):
    """
    Custom protocol to handle file transfer operations over QUIC.
    This class processes commands for uploading, downloading, and pinging.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_handlers = {}  # Dictionary to track stream handler tasks by stream_id
        logger.info("New client connection established")

    def quic_event_received(self, event: QuicEvent):
        """
        Callback invoked when a QUIC event is received.

        Parameters:
            event (QuicEvent): The event received from the QUIC connection.

        Handles data received on streams and delegates processing to individual stream handlers.
        """
        if isinstance(event, StreamDataReceived):
            logger.debug(f"Received data on stream {event.stream_id} ({len(event.data)} bytes)")
            # If there is no handler for this stream, create one
            if event.stream_id not in self.stream_handlers:
                logger.info(f"Creating new handler for stream {event.stream_id}")
                reader, writer = self._create_stream(event.stream_id)
                handler = asyncio.create_task(self.handle_stream(reader, writer, event.stream_id))
                self.stream_handlers[event.stream_id] = handler
            # Feed the incoming data into the appropriate stream reader
            self._stream_readers[event.stream_id].feed_data(event.data)
            if event.end_stream:
                logger.debug(f"End of stream {event.stream_id}")
                self._stream_readers[event.stream_id].feed_eof()

    async def handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream_id: int):
        """
        Handle file transfer commands on a given stream.

        Parameters:
            reader (asyncio.StreamReader): Stream reader for the connection.
            writer (asyncio.StreamWriter): Stream writer for the connection.
            stream_id (int): The identifier for the QUIC stream.
        """
        try:
            logger.info(f"Processing stream {stream_id}")
            # Read the command until a newline character
            command = await reader.readuntil(b"\n")
            parts = command.decode().strip().split(" ", 1)
            cmd = parts[0].lower()
            filename = parts[1] if len(parts) > 1 else ""
            logger.info(f"Received command: {cmd.upper()} {filename}")

            if cmd == "upload":
                logger.info(f"Starting upload to {filename}")
                # Start measuring server-side upload time
                start_time = time.perf_counter()
                # Read the entire content of the file from the client
                content = await reader.read()
                file_path = os.path.join("code/assets/server_directory", filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # Write the received content to a file on disk
                with open(file_path, "wb") as file:
                    file.write(content)
                    file.flush()
                    os.fsync(file.fileno())
                end_time = time.perf_counter()
                upload_time = end_time - start_time
                file_size = len(content)
                throughput = (file_size / (1024 * 1024)) / upload_time  # Throughput in MB/s
                logger.info(f"File {filename} saved ({file_size} bytes) on disk in {upload_time:.6f} s")
                # Prepare a JSON response with the upload metrics
                response_data = {
                    "status": "success",
                    "upload_time": upload_time,
                    "throughput": throughput
                }
                writer.write(json.dumps(response_data).encode())

            elif cmd == "download":
                logger.info(f"Processing download request for {filename}")
                try:
                    file_path = os.path.join("code/assets/server_directory", filename)
                    # Read the requested file and send its content back to the client
                    with open(file_path, "rb") as file:
                        content = file.read()
                        writer.write(content)
                        logger.info(f"Sent {len(content)} bytes for {filename}")
                except FileNotFoundError:
                    logger.warning(f"File not found: {filename}")
                    writer.write(b"File not found")

            elif cmd == "ping":
                # For a ping command, simply reply with "pong"
                writer.write(b"pong")

            else:
                logger.error("Unrecognized command")
                writer.write(b"Unrecognized command")

            # Ensure that all data is sent before closing the stream
            await writer.drain()
            logger.info(f"Completed processing stream {stream_id}")

        except Exception as e:
            logger.error(f"Error handling stream {stream_id}: {str(e)}")
        finally:
            writer.close()
            # Remove the stream handler once the stream is closed
            if stream_id in self.stream_handlers:
                del self.stream_handlers[stream_id]
            logger.debug(f"Closed stream {stream_id}")


async def main():
    """
    Main function to start the QUIC server.
    Loads the SSL certificate and key, starts the server on port 4433, and keeps it running.
    """
    configuration = QuicConfiguration(is_client=False)
    try:
        # Load SSL certificate and private key for the server
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
        "::", 4433,
        configuration=configuration,
        create_protocol=FileTransferServerProtocol,
    )
    logger.info("Server is ready to accept connections")
    # Keep the server running indefinitely
    await asyncio.Future()


if __name__ == "__main__":
    # Generate key and certificate if needed before starting the server
    gen_key_cert()
    asyncio.run(main())
