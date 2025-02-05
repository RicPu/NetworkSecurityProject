"""
Implementing the pyshark library for packet evaluation
"""

import os
import ssl
import json
import socket
import logging
import time
import threading
import pyshark

# Configure logging for the TLS client
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tls-client")


class TLSClient:
    def __init__(self, host: str, port: int, certfile: str):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.logger = logging.getLogger(__name__)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(cafile=self.certfile)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect(self) -> ssl.SSLSocket:
        """
        Establishes a secure socket connection to the specified host and port.
        Returns:
            ssl.SSLSocket: A secure socket object connected to the specified host and port.
        """
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.logger.info(f"Connecting to {self.host}:{self.port}...")
            ssock = self.context.wrap_socket(raw_socket, server_hostname=self.host)
            ssock.connect((self.host, self.port))
            self.logger.info(f"Connected to {self.host}:{self.port}")
            return ssock
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise

    def close_connection(self, ssock: ssl.SSLSocket):
        """
        Closes a secure SSL/TLS socket connection.
        Parameters:
            ssock (ssl.SSLSocket): The secure socket to close.
        """
        try:
            self.logger.info("Closing connection...")
            ssock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            self.logger.warning(f"Error during shutdown: {e}")
        finally:
            ssock.close()
            self.logger.info("Connection closed.")

    def ping(self) -> float:
        """
        Sends a ping request to the server and measures the round-trip time (RTT).
        Returns:
            float: RTT in seconds, or None if ping fails.
        """
        ssock = None
        try:
            ssock = self.connect()
            start = time.perf_counter()
            request = json.dumps({"action": "ping"}).encode()
            ssock.sendall(request + b"\n")
            response = ssock.recv(4096).decode().strip()
            end = time.perf_counter()
            rtt = end - start
            self.logger.info(f"Ping response: {response}, RTT: {rtt:.6f} s")
            return rtt
        except Exception as e:
            self.logger.error(f"Ping failed: {e}")
            return None
        finally:
            if ssock:
                self.close_connection(ssock)

    def send_file(self, ssock: ssl.SSLSocket, file_path: str) -> (float, float):
        """
        Sends a file to a server over a secure SSL/TLS socket connection.
        Returns:
            tuple: (upload_time, throughput) if successful, otherwise (None, None).
        """
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            request = json.dumps({"action": "send_file"}).encode()
            ssock.sendall(request + b"\n")

            response = ssock.recv(4096).decode().strip()
            response_data = json.loads(response)
            if response_data.get("status") != "ready":
                self.logger.error("Server not ready for file upload.")
                return None, None

            metadata = json.dumps({"file_name": file_name, "file_size": file_size}).encode()
            ssock.sendall(metadata + b"\n")

            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    ssock.sendall(chunk)

            response = ssock.recv(4096).decode().strip()
            resp = json.loads(response)
            if resp.get("status") == "success":
                upload_time = resp.get("upload_time")
                throughput = resp.get("throughput")
                self.logger.info(f"Upload completed: {upload_time:.6f} s, Throughput: {throughput:.2f} MB/s")
                return upload_time, throughput
            else:
                self.logger.error("Error reported by server during upload.")
                return None, None
        except Exception as e:
            self.logger.error(f"Upload failed: {e}")
            return None, None

    def request_file(self, ssock: ssl.SSLSocket, file_name: str, save_dir: str) -> (float, float):
        """
        Requests a file from the server and saves it locally.
        Returns:
            tuple: (download_time, throughput) if successful, otherwise (None, None).
        """
        try:
            request = json.dumps({"action": "request_file", "file_name": file_name}).encode()
            ssock.sendall(request + b"\n")
            response = ssock.recv(4096).decode().strip()
            response_data = json.loads(response)
            if response_data.get("status") != "ready":
                self.logger.error("File not found on server or server not ready.")
                return None, None

            metadata_data = ssock.recv(4096).decode().strip()
            metadata = json.loads(metadata_data)
            expected_size = metadata.get("file_size")
            if not expected_size:
                self.logger.error("Missing file size in metadata.")
                return None, None

            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, file_name)
            received = 0
            start = time.perf_counter()
            with open(save_path, "wb") as file:
                while received < expected_size:
                    chunk = ssock.recv(min(4096, expected_size - received))
                    if not chunk:
                        break
                    file.write(chunk)
                    received += len(chunk)
            end = time.perf_counter()
            download_time = end - start
            throughput = (expected_size / (1024 * 1024)) / download_time
            self.logger.info(f"Download completed: {download_time:.6f} s, Throughput: {throughput:.2f} MB/s")
            return download_time, throughput
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            return None, None

    def handle_communication(self, file_path: str = None, request_type: str = None,
                             save_dir: str = "code/assets/client_directory"):
        """
        Handles communication with the server for sending or receiving a file.
        Parameters:
            file_path (str): For "send", the path to the file; for "receive", the file name.
            request_type (str): "send", "receive", or "ping".
            save_dir (str): Directory for saving the file (if receiving).
        Returns:
            Depending on the operation:
              - For "ping": the RTT (float).
              - For "send": a tuple (upload_time, throughput).
              - For "receive": a tuple (download_time, throughput).
            Returns None if an invalid request type is provided.
        """
        ssock = None
        try:
            if request_type == "ping":
                return self.ping()

            ssock = self.connect()
            if request_type == "send":
                return self.send_file(ssock, file_path)
            elif request_type == "receive":
                return self.request_file(ssock, os.path.basename(file_path), save_dir)
            else:
                self.logger.error("Invalid request type. Use 'send', 'receive', or 'ping'.")
                return None
        except Exception as e:
            self.logger.error(f"Error during communication: {e}")
            return None
        finally:
            if ssock:
                self.close_connection(ssock)


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
    logging.info(f"Test file generated: {file_path} ({size_mb} MB)")


def start_pyshark_capture(interface=r'\Device\NPF_Loopback', display_filter='tcp.port == 8443',
                          packet_count=4):
    """
    Starts a live PyShark capture on the specified interface using the given display filter.

    This function creates a new asyncio event loop for this thread, starts a live capture with PyShark,
    sniffs until 'packet_count' packets are captured, and logs the capture results, inclusa la stampa
    del numero totale di pacchetti catturati.

    Parameters:
        interface (str): The network interface on which to capture packets.
        display_filter (str): A filter expression to apply to captured packets.
        packet_count (int): Number of packets to capture.
    """
    import asyncio
    # Create a new event loop for this thread and set it as current.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
    logging.info("Starting PyShark capture...")
    capture.sniff(packet_count=packet_count)
    logging.info(f"PyShark capture finished. {len(capture)} packets captured:")
    for pkt in capture:
        try:
            logging.info(f"{pkt.sniff_time} - {pkt.highest_layer}")
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
    capture.close()
    loop.close()


def run_client():
    """
    Runs the TLS client operations:
      1. Measures handshake by connecting and disconnecting.
      2. Performs 5 ping tests.
      3. Performs 3 file upload tests.
      4. Performs 3 file download tests.
      For each operation, a PyShark capture is started in a parallel thread to capture packets,
      and after the operation, the capture results (including the total number of packets captured)
      are printed immediately.
    """
    client = TLSClient(host="127.0.0.1", port=8443, certfile="code/assets/certificate.pem")

    # Handshake test
    try:
        start = time.perf_counter()
        ssock = client.connect()
        client.close_connection(ssock)
        end = time.perf_counter()
        logger.info(f"Handshake completed in {end - start:.6f} s")
    except Exception as e:
        logger.error(f"Handshake test failed: {e}")

    # Ping tests: 5 pings, each preceded by a PyShark capture.
    for _ in range(1):
        ping_thread = threading.Thread(
            target=start_pyshark_capture,
            kwargs={'interface': r'\Device\NPF_Loopback', 'display_filter': "tcp.port == 8443", 'packet_count': 4}
        )
        ping_thread.start()
        # Wait 1 second to ensure the capture is active.
        time.sleep(1)
        client.ping()
        time.sleep(0.1)
        ping_thread.join(timeout=30)

    # Prepare test file for upload if it does not exist.
    test_upload_file = "code/assets/client_directory/test_upload.bin"
    if not os.path.exists(test_upload_file):
        generate_test_file(test_upload_file, 10)  # 10 MB

    # Upload tests: 3 uploads, each preceded by a PyShark capture.
    for _ in range(1):
        upload_thread = threading.Thread(
            target=start_pyshark_capture,
            kwargs={'interface': r'\Device\NPF_Loopback', 'display_filter': "tcp.port == 8443", 'packet_count': 100}
        )
        upload_thread.start()
        time.sleep(1)
        client.handle_communication(file_path=test_upload_file, request_type="send")
        time.sleep(0.2)
        upload_thread.join(timeout=100)

    # Download tests: 3 downloads, each preceded by a PyShark capture.
    for _ in range(1):
        download_thread = threading.Thread(
            target=start_pyshark_capture,
            kwargs={'interface': r'\Device\NPF_Loopback', 'display_filter': "tcp.port == 8443", 'packet_count': 100}
        )
        download_thread.start()
        time.sleep(1)
        client.handle_communication(file_path="code/assets/client_directory/Summer_1.jpg", request_type="receive")
        time.sleep(0.2)
        download_thread.join(timeout=100)


if __name__ == "__main__":
    run_client()
