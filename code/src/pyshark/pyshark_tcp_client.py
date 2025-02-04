"""
Implementing the pyshark library for packet evaluation
"""

import os
import ssl
import json
import socket
import logging
import time
import statistics
import threading
import pyshark
from tabulate import tabulate

logging.basicConfig(level=logging.INFO)


class BenchmarkStats:
    """
    Class to collect and calculate benchmark statistics such as handshake times,
    upload/download times, round-trip times (RTT), and throughputs.
    """
    def __init__(self):
        self.handshake_times = []
        self.upload_times = []
        self.upload_throughputs = []
        self.download_times = []
        self.download_throughputs = []
        self.rtt_samples = []

    def add_handshake_time(self, t):
        """Appends a new handshake time measurement to the list."""
        self.handshake_times.append(t)

    def add_upload_time(self, t):
        """Appends a new upload time measurement to the list."""
        self.upload_times.append(t)

    def add_download_time(self, t):
        """Appends a new download time measurement to the list."""
        self.download_times.append(t)

    def add_rtt(self, rtt):
        """Appends a new round-trip time (RTT) measurement to the list."""
        self.rtt_samples.append(rtt)

    def add_upload_throughput(self, thr):
        """Appends a new upload throughput measurement (in MB/s) to the list."""
        self.upload_throughputs.append(thr)

    def add_download_throughput(self, thr):
        """Appends a new download throughput measurement (in MB/s) to the list."""
        self.download_throughputs.append(thr)

    def report(self):
        """
        Computes and returns a summary report of all benchmark metrics.

        Returns:
            dict: A dictionary with average values for handshake time, upload time, download time,
                  RTT (and its standard deviation), upload throughput, and download throughput.
        """
        return {
            "Handshake Time": statistics.mean(self.handshake_times) if self.handshake_times else None,
            "Upload Time": statistics.mean(self.upload_times) if self.upload_times else None,
            "Download Time": statistics.mean(self.download_times) if self.download_times else None,
            "RTT": statistics.mean(self.rtt_samples) if self.rtt_samples else None,
            "RTT Std. Dev.": statistics.stdev(self.rtt_samples) if len(self.rtt_samples) > 1 else 0.0,
            "Upload Throughput": statistics.mean(self.upload_throughputs) if self.upload_throughputs else None,
            "Download Throughput": statistics.mean(self.download_throughputs) if self.download_throughputs else None
        }


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

        This method attempts to create a secure SSL/TLS connection to the host and port specified in the instance's attributes (`self.host` and `self.port`). It uses the SSL context (`self.context`) to wrap the socket for secure communication.

        Returns:
            socket.socket: A secure socket object connected to the specified host and port.
        """
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.logger.info(f"Connecting to {self.host}:{self.port}...")
            ssock = self.context.wrap_socket(raw_socket, server_hostname=self.host)
            ssock.connect((self.host, self.port))
            self.logger.info(f"Connected to {self.host}:{self.port}")
            return ssock
        except ssl.SSLError as ssl_err:
            self.logger.error(f"SSL error during connection: {ssl_err}")
            raise
        except socket.error as sock_err:
            self.logger.error(f"Socket error during connection: {sock_err}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during connection: {e}")
            raise

    def close_connection(self, ssock: ssl.SSLSocket):
        """
        Closes a secure SSL/TLS socket connection.

        This method safely shuts down and closes the provided secure socket, ensuring proper resource cleanup.

        Parameters:
            ssock (ssl.SSLSocket): The secure SSL/TLS socket to close.
        """
        try:
            self.logger.info("Closing connection...")
            ssock.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            self.logger.warning(f"Error during socket shutdown: {e}")
        finally:
            ssock.close()
            self.logger.info("Connection closed.")

    def ping(self) -> float:
        """
        Sends a ping request to the server and measures the round-trip time (RTT).

        Returns:
            float: The round-trip time in seconds, or None if the ping fails.
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

        This method sends a file to a server by:
        1. Initiating a "send_file" request.
        2. Sending file metadata (file name and size).
        3. Transmitting the file's content in chunks.

        Parameters:
            ssock (ssl.SSLSocket): A secure SSL/TLS socket connected to the server.
            file_path (str): The path to the file to be sent.
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

        This method sends a "request_file" action to the server along with the file name. If the server
        responds with readiness, it receives file metadata (including the expected file size) and then downloads
        the file in chunks, saving it to the specified directory.

        Parameters:
            ssock (ssl.SSLSocket): A secure SSL/TLS socket connected to the server.
            file_name (str): The name of the file to request.
            save_dir (str): The directory where the file should be saved.

        Returns:
            tuple: A tuple (download_time, throughput) where download_time is the time taken to download the file in seconds and throughput is the download speed in MB/s.
                   Returns (None, None) if the operation fails.
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

        This method establishes a secure SSL/TLS connection, then either sends or requests a file based on the specified request type. The connection is safely closed after the operation.

        Parameters:
            file_path (str): The path to the file for sending or the file name for requesting.
            request_type (str): The type of operation to perform:
                - "send": Sends the file at the specified `file_path` to the server.
                - "receive": Requests the file with the name derived from `file_path`.
            save_dir (str): Directory where a requested file will be saved.

        Returns:
            Depending on the operation, returns either:
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
    Generates a test file with random content.

    The file is created at the specified path with a size of size_mb megabytes.

    Parameters:
        file_path (str): The path where the file will be generated.
        size_mb (int): The size of the file in megabytes.
    """
    num_bytes = size_mb * 1024 * 1024
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(os.urandom(num_bytes))
    logging.info(f"Test file generated: {file_path} ({size_mb} MB)")


# Benchmark report printing functions
def print_benchmark_report(benchmark_stats: BenchmarkStats):
    """
    Prints a formatted summary report of the benchmark statistics.

    The report is divided into two sections:
      - Latency Metrics: Handshake time, RTT, and RTT standard deviation.
      - Throughput & Transfer Metrics: Upload/download times and throughputs.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    rep = benchmark_stats.report()
    latency_data = [
        ("Handshake Time", f"{rep['Handshake Time']:.6f} s" if rep["Handshake Time"] is not None else "N/A"),
        ("RTT", f"{rep['RTT']:.6f} s" if rep["RTT"] is not None else "N/A"),
        ("RTT Std. Dev.", f"{rep['RTT Std. Dev.']:.6f} s"),
    ]
    throughput_data = [
        ("Upload Time", f"{rep['Upload Time']:.6f} s" if rep["Upload Time"] is not None else "N/A"),
        ("Upload Throughput", f"{rep['Upload Throughput']:.2f} MB/s" if rep["Upload Throughput"] is not None else "N/A"),
        ("Download Time", f"{rep['Download Time']:.6f} s" if rep["Download Time"] is not None else "N/A"),
        ("Download Throughput", f"{rep['Download Throughput']:.2f} MB/s" if rep["Download Throughput"] is not None else "N/A"),
    ]
    print("\n" + "=" * 40)
    print("Benchmark Report - Latency Metrics")
    print("=" * 40)
    print(tabulate(latency_data, headers=["Latency", "Value"], tablefmt="grid"))
    print("\n" + "=" * 40)
    print("Benchmark Report - Throughput & Transfer Metrics")
    print("=" * 40)
    print(tabulate(throughput_data, headers=["Throughput", "Value"], tablefmt="grid"))


def print_detailed_upload_results(benchmark_stats: BenchmarkStats):
    """
    Prints a detailed table showing each iteration's upload time and throughput.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    if benchmark_stats.upload_times and benchmark_stats.upload_throughputs:
        upload_table = [
            (i + 1, f"{benchmark_stats.upload_times[i]:.6f} s", f"{benchmark_stats.upload_throughputs[i]:.2f} MB/s")
            for i in range(len(benchmark_stats.upload_times))
        ]
        print("\nDetailed Upload Results:")
        print(tabulate(upload_table, headers=["Iteration", "Upload Time", "Upload Throughput"], tablefmt="grid"))


def print_detailed_download_results(benchmark_stats: BenchmarkStats):
    """
    Prints a detailed table showing each iteration's download time and throughput.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    if benchmark_stats.download_times and benchmark_stats.download_throughputs:
        download_table = [
            (i + 1, f"{benchmark_stats.download_times[i]:.6f} s", f"{benchmark_stats.download_throughputs[i]:.2f} MB/s")
            for i in range(len(benchmark_stats.download_times))
        ]
        print("\nDetailed Download Results:")
        print(tabulate(download_table, headers=["Iteration", "Download Time", "Download Throughput"], tablefmt="grid"))


def print_detailed_ping_times(benchmark_stats: BenchmarkStats):
    """
    Prints a detailed table of individual ping times.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    if benchmark_stats.rtt_samples:
        ping_table = [(i + 1, f"{t:.6f} s") for i, t in enumerate(benchmark_stats.rtt_samples)]
        print("\nDetailed Ping Times:")
        print(tabulate(ping_table, headers=["Iteration", "Ping Time"], tablefmt="grid"))


def start_pyshark_capture(interface=r'\Device\NPF_Loopback', display_filter='tcp.port == 8443', duration=1):
    """
    Starts a live PyShark capture on the specified interface using the given display filter.

    This function creates a new asyncio event loop for this thread, starts a live capture with PyShark,
    sniffs a fixed number of packets, and logs the capture results.

    Parameters:
        interface (str): The network interface on which to capture packets.
        display_filter (str): A filter expression to apply to captured packets.
        duration (int): The duration for which to run the capture (currently unused; packet_count is fixed).
    """
    import asyncio
    # Create a new event loop for this thread and set it as current.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
    logging.info("Starting PyShark capture...")
    capture.sniff(packet_count=100)
    logging.info(f"PyShark capture finished. {len(capture)} packets captured:")
    for pkt in capture:
        try:
            logging.info(f"{pkt.sniff_time} - {pkt.highest_layer}")
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
    capture.close()


def run_benchmark():
    """
    Runs the TLS client benchmark:
      1. Measures handshake time by connecting and disconnecting.
      2. Performs 5 ping tests to measure RTT.
      3. Prepares a test file for upload.
      4. Performs 3 file upload tests.
      5. Performs 3 file download tests.
      6. Prints the summarized and detailed benchmark reports.
    """
    benchmark = BenchmarkStats()
    client = TLSClient(host="127.0.0.1", port=8443, certfile="code/assets/certificate.pem")

    # Start PyShark capture in a parallel thread to monitor TLS traffic
    capture_thread = threading.Thread(target=start_pyshark_capture, kwargs={'duration': 15})
    capture_thread.start()

    # Measure handshake time
    try:
        start = time.perf_counter()
        ssock = client.connect()
        client.close_connection(ssock)
        end = time.perf_counter()
        handshake_time = end - start
        benchmark.add_handshake_time(handshake_time)
        logging.info(f"Handshake completed in {handshake_time:.6f} s")
    except Exception as e:
        logging.error(f"Handshake test failed: {e}")

    # Ping test: 5 pings
    for _ in range(5):
        rtt = client.ping()
        if rtt is not None:
            benchmark.add_rtt(rtt)
        time.sleep(0.1)

    # Prepare test file for upload if it does not exist
    test_upload_file = "code/assets/client_directory/test_upload.bin"
    if not os.path.exists(test_upload_file):
        generate_test_file(test_upload_file, 10)  # 10 MB

    # Upload test: 3 uploads
    for _ in range(3):
        result = client.handle_communication(file_path=test_upload_file, request_type="send")
        if result is not None:
            upload_time, throughput = result
            if upload_time is not None and throughput is not None:
                benchmark.add_upload_time(upload_time)
                benchmark.add_upload_throughput(throughput)
        time.sleep(0.2)

    # Download test: 3 downloads
    for _ in range(3):
        result = client.handle_communication(file_path="code/assets/client_directory/Summer_1.jpg",
                                             request_type="receive")
        if result is not None:
            download_time, throughput = result
            if download_time is not None and throughput is not None:
                benchmark.add_download_time(download_time)
                benchmark.add_download_throughput(throughput)
        time.sleep(0.2)

    # Wait for the PyShark capture to finish
    capture_thread.join()

    print_benchmark_report(benchmark)
    print_detailed_upload_results(benchmark)
    print_detailed_download_results(benchmark)
    print_detailed_ping_times(benchmark)


if __name__ == "__main__":
    run_benchmark()
