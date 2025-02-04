"""implementing TCP-TLS with a similar interface to QUIC for further evaluations."""

import os
import asyncio
import json
import ssl
import time
import aiofiles
import logging

logging.basicConfig(level=logging.WARNING)  # Reduced log level to minimize overhead
logger = logging.getLogger("async_tcp_tls")

class AsyncTCPTLSServer:
    """
    An asynchronous TCP/TLS server that handles client requests for file transfer
    and ping actions over a secure TLS connection.
    """
    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        """
        Initializes the AsyncTCPTLSServer with the given host, port, and TLS certificate details.

        Parameters:
            host (str): The hostname or IP address to bind the server.
            port (int): The port number to listen on.
            certfile (str): Path to the TLS certificate file.
            keyfile (str): Path to the TLS private key file.
        """
        self.host = host
        self.port = port
        # Create the SSL context for TLS communication
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handles an incoming client connection, processing its request based on the JSON action provided.

        This method reads the initial JSON request line, determines the requested action
        (send_file, request_file, ping, or unknown), and dispatches the request accordingly.
        """
        try:
            # Read the first line (in JSON) specifying the action
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                await writer.wait_closed()
                return

            try:
                request_data = json.loads(request_line.decode().strip())
            except Exception:
                await self.send_error(writer, "Invalid JSON request")
                writer.close()
                await writer.wait_closed()
                return

            action = request_data.get("action")
            if action == "send_file":
                # Send "ready" response and receive the file
                writer.write((json.dumps({"status": "ready"}) + "\n").encode())
                await writer.drain()
                await self.receive_file(reader, writer)
            elif action == "request_file":
                file_name = request_data.get("file_name")
                file_path = os.path.join("code/assets/server_directory", file_name)
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    writer.write((json.dumps({"status": "ready"}) + "\n").encode())
                    await writer.drain()
                    await self.send_file(writer, file_path)
                else:
                    writer.write((json.dumps({"status": "not_found"}) + "\n").encode())
                    await writer.drain()
            elif action == "ping":
                writer.write(b"pong")
                await writer.drain()
            else:
                await self.send_error(writer, "Unknown action")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.error("Client handling error: %s", e)
            writer.close()
            await writer.wait_closed()

    async def receive_file(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Receives a file from the client over the secure connection.

        The method first reads the file metadata (including file_size and file_name)
        from a JSON-encoded line, then receives the file data in chunks and writes
        it to disk. It computes the upload time and throughput, sending back a JSON response.
        """
        try:
            # Receive the metadata (in JSON) containing file_size and file_name
            metadata_line = await reader.readline()
            if not metadata_line:
                await self.send_error(writer, "No metadata received")
                return

            metadata = json.loads(metadata_line.decode().strip())
            file_size = metadata.get("file_size")
            file_name = metadata.get("file_name")
            if not file_name or not file_size:
                await self.send_error(writer, "Invalid metadata")
                return

            file_path = os.path.join("code/assets/server_directory", file_name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            start_time = time.perf_counter()
            received = 0
            chunk_size = 4096

            async with aiofiles.open(file_path, "wb") as f:
                while received < file_size:
                    to_read = min(chunk_size, file_size - received)
                    chunk = await reader.read(to_read)
                    if not chunk:
                        break
                    await f.write(chunk)
                    received += len(chunk)
            end_time = time.perf_counter()

            if received == file_size:
                upload_time = end_time - start_time
                throughput = (file_size / (1024 * 1024)) / upload_time  # MB/s
                response = json.dumps({
                    "status": "success",
                    "upload_time": upload_time,
                    "throughput": throughput
                }) + "\n"
                writer.write(response.encode())
                await writer.drain()
            else:
                await self.send_error(writer, "File transfer incomplete")
        except Exception as e:
            logger.error("Receive file error: %s", e)
            await self.send_error(writer, str(e))

    async def send_file(self, writer: asyncio.StreamWriter, file_path: str):
        """
        Sends a file to the client over the secure connection.

        This method first sends a JSON-encoded metadata line containing the file name and size,
        then reads the file asynchronously in chunks and writes each chunk to the client.
        """
        try:
            file_size = os.path.getsize(file_path)
            metadata = json.dumps({
                "file_name": os.path.basename(file_path),
                "file_size": file_size
            }) + "\n"
            writer.write(metadata.encode())
            await writer.drain()

            async with aiofiles.open(file_path, "rb") as f:
                while True:
                    chunk = await f.read(4096)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
        except Exception as e:
            logger.error("Send file error: %s", e)

    async def send_error(self, writer: asyncio.StreamWriter, message: str):
        """
        Sends an error message to the client in JSON format.

        Parameters:
            writer (asyncio.StreamWriter): The stream writer for the client connection.
            message (str): The error message to be sent.
        """
        response = json.dumps({"status": "error", "message": message}) + "\n"
        writer.write(response.encode())
        await writer.drain()

    async def start(self):
        """
        Starts the asynchronous TCP/TLS server.

        The server listens on the configured host and port with TLS enabled.
        Once started, it handles client connections indefinitely.
        """
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port, ssl=self.ssl_context
        )
        addr = server.sockets[0].getsockname()
        logger.warning(f"Async TLS server listening on {addr}")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    from utils import gen_key_cert
    gen_key_cert()
    server = AsyncTCPTLSServer("127.0.0.1", 8443, "code/assets/certificate.pem", "code/assets/private_key.pem")
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.warning("Server interrupted by user.")
