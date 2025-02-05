"""Implementing the pyshark library for packet evaluation - QUIC"""

import os
import ssl
import asyncio
import logging
import time
import json
import threading
import pyshark

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

# Configure logging for the QUIC client
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quic-client")


def generate_test_file(file_path: str, size_mb: int):
    """
    Generate a test file with random bytes.

    Parameters:
        file_path (str): The path where the file will be created.
        size_mb (int): The size of the file in megabytes.
    """
    num_bytes = size_mb * 1024 * 1024
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(os.urandom(num_bytes))
    logger.info(f"File generated: {file_path} ({size_mb} MB)")


def start_pyshark_capture(
    interface=r"\Device\NPF_Loopback", display_filter="udp.port == 4433", packet_count=4
):
    """
    Start a PyShark live capture on a separate thread.
    Since QUIC uses UDP (port 4433), the filter is set to 'udp.port == 4433'.
    This function uses sniff_continuously to yield packets as soon as they are captured.
    Once 'packet_count' packets have been captured, it prints out basic information (timestamp and highest_layer)
    for each packet and then terminates, mostrando anche il numero totale di pacchetti catturati.
    """
    import asyncio

    # Create a new event loop for this thread and set it as the current loop.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Create the live capture with the specified interface and display filter.
    capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
    logger.info("Starting PyShark capture (sniff_continuously)...")

    # Use sniff_continuously to yield packets as soon as they arrive.
    captured_packets = []
    for i, pkt in enumerate(capture.sniff_continuously(packet_count=packet_count)):
        captured_packets.append(pkt)
        # Print the current packet immediately.
        try:
            logger.info(f"{pkt.sniff_time} - {pkt.highest_layer}")
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
        # Stop after we have captured the desired number of packets.
        if len(captured_packets) >= packet_count:
            break

    logger.info(f"PyShark capture finished. {len(captured_packets)} packets captured.")
    capture.close()
    # Close the event loop to ensure the thread terminates.
    loop.close()


class FileTransferClientProtocol(QuicConnectionProtocol):
    """
    Custom protocol for file transfer operations using QUIC.
    Inherits from aioquic's QuicConnectionProtocol.
    """

    async def create_stream(self):
        """
        Create a new bidirectional stream.

        Returns:
            tuple: A tuple (reader, writer) for the created stream.
        """
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        return self._create_stream(stream_id)

    async def upload(self, local_path: str):
        """
        Upload a file to the server.

        Parameters:
            local_path (str): The path of the local file to upload.
        """
        file_name = os.path.basename(local_path)
        logger.info(f"Starting upload of {local_path}")
        try:
            reader, writer = await self.create_stream()
            command = f"upload {file_name}\n"
            writer.write(command.encode())
            await writer.drain()

            with open(local_path, "rb") as file:
                while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            writer.write_eof()

            response = await reader.read()
            response_data = json.loads(response.decode())
            if response_data.get("status") == "success":
                server_upload_time = response_data.get("upload_time")
                server_throughput = response_data.get("throughput")
                logger.info(f"Upload completed for file: {file_name}")
                logger.info(f"Server measured Upload Time: {server_upload_time:.6f} s")
                logger.info(f"Server measured Throughput: {server_throughput:.2f} MB/s")
            else:
                logger.error("Server reported an error during upload.")
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")

    async def download(self, file_name: str, local_path: str):
        """
        Download a file from the server.

        Parameters:
            file_name (str): The name of the file to download.
            local_path (str): The directory where the downloaded file will be saved.
        """
        logger.info(f"Starting download of {file_name} to {local_path}")
        try:
            reader, writer = await self.create_stream()
            command = f"download {file_name}\n"
            writer.write(command.encode())
            writer.write_eof()
            start_time = time.perf_counter()
            data = await reader.read()
            end_time = time.perf_counter()
            transfer_time = end_time - start_time

            if data == b"File not found":
                logger.warning(f"File not found on server: {file_name}")
            else:
                file_path = os.path.join(local_path, file_name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "wb") as file:
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())
                file_size = len(data)
                throughput = (
                    file_size / (1024 * 1024)
                ) / transfer_time  # Calculate throughput in MB/s
                logger.info(f"Download completed for file: {file_name}")
                logger.info(f"Size: {file_size / (1024 * 1024):.2f} MB")
                logger.info(f"Download transfer time: {transfer_time:.6f} s")
                logger.info(f"Download throughput: {throughput:.2f} MB/s")
        except Exception as e:
            logger.error(f"Download failed: {str(e)}")
            raise

    async def ping(self):
        """
        Send a ping to measure the round-trip time (RTT).

        Returns:
            float or None: The measured RTT in seconds, or None if the ping failed.
        """
        try:
            reader, writer = await self.create_stream()
            start_time = time.perf_counter()
            writer.write(b"ping\n")
            writer.write_eof()
            await reader.read()
            end_time = time.perf_counter()
            rtt = end_time - start_time
            writer.close()
            logger.info(f"RTT (ping): {rtt:.6f} seconds")
            return rtt
        except Exception as e:
            logger.error(f"Ping failed: {str(e)}")
            return None


async def run_client():
    """
    Main routine that:
      - Generates a test file (if not already present)
      - For each ping, upload, and download operation, starts a PyShark capture in a separate thread,
        waits a short delay to ensure the capture is active, performs the operation, then joins the capture thread.
    """
    # Generate test file if not exists
    test_file = "code/assets/client_directory/test_upload.bin"
    if not os.path.exists(test_file):
        generate_test_file(test_file, 10)

    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = (
        ssl.CERT_NONE
    )  # Disable certificate verification for testing

    # Establish QUIC connection
    handshake_start = time.perf_counter()
    async with connect(
        "localhost",
        4433,
        configuration=configuration,
        create_protocol=FileTransferClientProtocol,
    ) as protocol:
        await protocol.wait_connected()
        handshake_end = time.perf_counter()
        handshake_time = handshake_end - handshake_start
        logger.info(f"Handshake completed in {handshake_time:.6f} seconds")

        # For each ping test, start a PyShark capture, wait briefly, perform the ping, then join the capture thread.
        for _ in range(1):
            ping_thread = threading.Thread(
                target=start_pyshark_capture,
                kwargs={
                    "interface": r"\Device\NPF_Loopback",
                    "display_filter": "udp.port == 4433",
                    "packet_count": 4,
                },
            )
            ping_thread.start()
            # Wait 1 second to ensure the capture is active
            await asyncio.sleep(1)
            await protocol.ping()
            await asyncio.sleep(0.1)
            ping_thread.join(timeout=3)

        # For each upload test, start a PyShark capture, wait briefly, perform the upload, then join the capture thread.
        for _ in range(1):
            upload_thread = threading.Thread(
                target=start_pyshark_capture,
                kwargs={
                    "interface": r"\Device\NPF_Loopback",
                    "display_filter": "udp.port == 4433",
                    "packet_count": 100,
                },
            )
            upload_thread.start()
            await asyncio.sleep(1)
            await protocol.upload(test_file)
            await asyncio.sleep(0.2)
            upload_thread.join(timeout=10)

        # For each download test, start a PyShark capture, wait briefly, perform the download, then join the capture thread.
        for _ in range(1):
            download_thread = threading.Thread(
                target=start_pyshark_capture,
                kwargs={
                    "interface": r"\Device\NPF_Loopback",
                    "display_filter": "udp.port == 4433",
                    "packet_count": 100,
                },
            )
            download_thread.start()
            await asyncio.sleep(1)
            await protocol.download("Summer_1.jpg", "code/assets/client_directory")
            await asyncio.sleep(0.2)
            download_thread.join(timeout=10)

        protocol.close()
        await protocol.wait_closed()


async def main():
    """
    Entry point for running the QUIC client operations.
    """
    await run_client()


if __name__ == "__main__":
    asyncio.run(main())
