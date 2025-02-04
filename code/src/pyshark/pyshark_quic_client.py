"""implementing the pyshark library for packet evaluation"""

import os
import ssl
import asyncio
import logging
import time
import statistics
import json
import threading
import pyshark
from tabulate import tabulate

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


class BenchmarkStats:
    """
    Class to collect and calculate benchmark statistics such as handshake times,
    upload/download times, round-trip times (RTT), and throughputs.
    """
    def __init__(self):
        self.handshake_times = []
        self.upload_times = []
        self.download_times = []
        self.rtt_samples = []
        self.upload_throughputs = []
        self.download_throughputs = []

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


def print_benchmark_report_separated(benchmark_stats: BenchmarkStats):
    """
    Print the benchmark report in two separate tables: one for latency metrics
    and one for throughput & transfer metrics.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    rep = benchmark_stats.report()

    # Prepare latency data
    latency_data = [
        ("Handshake Time", f"{rep['Handshake Time']:.6f} s" if rep['Handshake Time'] is not None else "N/A"),
        ("RTT", f"{rep['RTT']:.6f} s" if rep['RTT'] is not None else "N/A"),
        ("RTT Std. Dev.", f"{rep['RTT Std. Dev.']:.6f} s")
    ]
    latency_table = tabulate(latency_data, headers=["Latency", "Value"], tablefmt="grid")

    # Prepare throughput data
    throughput_data = [
        ("Upload Time", f"{rep['Upload Time']:.6f} s" if rep['Upload Time'] is not None else "N/A"),
        ("Upload Throughput", f"{rep['Upload Throughput']:.2f} MB/s" if rep['Upload Throughput'] is not None else "N/A"),
        ("Download Time", f"{rep['Download Time']:.6f} s" if rep['Download Time'] is not None else "N/A"),
        ("Download Throughput", f"{rep['Download Throughput']:.2f} MB/s" if rep['Download Throughput'] is not None else "N/A")
    ]
    throughput_table = tabulate(throughput_data, headers=["Throughput", "Value"], tablefmt="grid")

    print("\n" + "=" * 40)
    print("Benchmark Report - Latency Metrics")
    print("=" * 40)
    print(latency_table)
    print("\n" + "=" * 40)
    print("Benchmark Report - Throughput & Transfer Metrics")
    print("=" * 40)
    print(throughput_table)


def print_detailed_results(benchmark_stats: BenchmarkStats):
    """
    Print detailed results for each iteration of upload, download, and ping tests.

    Parameters:
        benchmark_stats (BenchmarkStats): The benchmark statistics object.
    """
    # Detailed upload results
    if benchmark_stats.upload_times:
        upload_table = [
            (i + 1, f"{benchmark_stats.upload_times[i]:.6f} s", f"{benchmark_stats.upload_throughputs[i]:.2f} MB/s")
            for i in range(len(benchmark_stats.upload_times))
        ]
        print("\nDetailed Upload Results:")
        print(tabulate(upload_table, headers=["Iteration", "Upload Time", "Upload Throughput"], tablefmt="grid"))

    # Detailed download results
    if benchmark_stats.download_times:
        download_table = [
            (i + 1, f"{benchmark_stats.download_times[i]:.6f} s", f"{benchmark_stats.download_throughputs[i]:.2f} MB/s")
            for i in range(len(benchmark_stats.download_times))
        ]
        print("\nDetailed Download Results:")
        print(tabulate(download_table, headers=["Iteration", "Download Time", "Download Throughput"], tablefmt="grid"))

    # Detailed ping results
    if benchmark_stats.rtt_samples:
        ping_table = [(i + 1, f"{t:.6f} s") for i, t in enumerate(benchmark_stats.rtt_samples)]
        print("\nDetailed Ping Times:")
        print(tabulate(ping_table, headers=["Iteration", "Ping Time"], tablefmt="grid"))


# --- PyShark Integration ---
def start_pyshark_capture(interface=r'\Device\NPF_Loopback', display_filter="quic", duration=15):
    """
    Start a PyShark live capture on a separate thread.
    Since QUIC uses UDP (port 4433), filter is set to 'udp.port == 4433'.
    """
    import asyncio
    # Creiamo un nuovo event loop per questo thread e lo impostiamo come corrente.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
    logger.info("Avvio cattura PyShark...")
    capture.sniff(timeout=duration, packet_count=100)
    logger.info(f"Cattura PyShark terminata. {len(capture)} pacchetti catturati:")
    # Puoi stampare solo i primi N pacchetti se il numero è elevato
    max_print = 10
    for i, pkt in enumerate(capture):
        if i >= max_print:
            break
        try:
            logger.info(f"{pkt.sniff_time} - {pkt.highest_layer}")
        except Exception as e:
            logger.error(f"Errore nell'analisi del pacchetto: {e}")
    capture.close()


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

    async def upload(self, local_path: str, benchmark: BenchmarkStats = None):
        """
        Upload a file to the server.

        Parameters:
            local_path (str): The path of the local file to upload.
            benchmark (BenchmarkStats, optional): Benchmark object to record metrics.
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
                if benchmark:
                    benchmark.add_upload_time(server_upload_time)
                    benchmark.add_upload_throughput(server_throughput)
            else:
                logger.error("Server reported an error during upload.")
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")

    async def download(self, file_name: str, local_path: str, benchmark: BenchmarkStats = None):
        """
        Download a file from the server.

        Parameters:
            file_name (str): The name of the file to download.
            local_path (str): The directory where the downloaded file will be saved.
            benchmark (BenchmarkStats, optional): Benchmark object to record metrics.
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
                throughput = (file_size / (1024 * 1024)) / transfer_time
                logger.info(f"Download completed for file: {file_name}")
                logger.info(f"Size: {file_size / (1024 * 1024):.2f} MB")
                logger.info(f"Download transfer time: {transfer_time:.6f} s")
                logger.info(f"Download throughput: {throughput:.2f} MB/s")
                if benchmark:
                    benchmark.add_download_time(transfer_time)
                    benchmark.add_download_throughput(throughput)
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
            response = await reader.read()
            end_time = time.perf_counter()
            rtt = end_time - start_time
            writer.close()
            logger.info(f"RTT (ping): {rtt:.6f} seconds")
            return rtt
        except Exception as e:
            logger.error(f"Ping failed: {str(e)}")
            return None


async def run_benchmark():
    """
    Main benchmarking routine that:
      - Generates a test file (if not already present)
      - Establishes a QUIC connection
      - Measures handshake time, RTT (ping), upload, and download performance
      - Prints summary and detailed reports of the benchmark metrics.
    """
    # Generate test file if not exists
    test_file = "code/assets/client_directory/test_upload.bin"
    if not os.path.exists(test_file):
        generate_test_file(test_file, 10)

    benchmark = BenchmarkStats()
    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE  # Disable certificate verification for testing

    # Start PyShark capture in a separate thread
    capture_thread = threading.Thread(
        target=start_pyshark_capture,
        kwargs={'interface': r'\Device\NPF_Loopback', 'display_filter': "udp.port == 4433", 'duration': 15}
    )
    capture_thread.start()

    # Measure handshake time
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
        benchmark.add_handshake_time(handshake_time)

        # Perform 5 ping tests
        for _ in range(5):
            rtt = await protocol.ping()
            if rtt:
                benchmark.add_rtt(rtt)
            await asyncio.sleep(0.1)

        # Perform 3 upload tests
        for _ in range(3):
            await protocol.upload(test_file, benchmark)
            await asyncio.sleep(0.2)

        # Perform 3 download tests for "Summer_1.jpg"
        for _ in range(3):
            await protocol.download("Summer_1.jpg", "code/assets/client_directory", benchmark)
            await asyncio.sleep(0.2)

        protocol.close()
        await protocol.wait_closed()

    capture_thread.join()

    # Print reports
    print("\n" + "=" * 40)
    print("Benchmark Report - Latency Metrics")
    print("=" * 40)
    latency_report = [
        ("Handshake Time", f"{statistics.mean(benchmark.handshake_times):.6f} s" if benchmark.handshake_times else "N/A"),
        ("RTT", f"{statistics.mean(benchmark.rtt_samples):.6f} s" if benchmark.rtt_samples else "N/A"),
        ("RTT Std. Dev.", f"{statistics.stdev(benchmark.rtt_samples):.6f} s" if len(benchmark.rtt_samples) > 1 else "0.000000 s")
    ]
    print(tabulate(latency_report, headers=["Latency", "Value"], tablefmt="grid"))

    print("\n" + "=" * 40)
    print("Benchmark Report - Throughput & Transfer Metrics")
    print("=" * 40)
    throughput_report = [
        ("Upload Time", f"{statistics.mean(benchmark.upload_times):.6f} s" if benchmark.upload_times else "N/A"),
        ("Upload Throughput", f"{statistics.mean(benchmark.upload_throughputs):.2f} MB/s" if benchmark.upload_throughputs else "N/A"),
        ("Download Time", f"{statistics.mean(benchmark.download_times):.6f} s" if benchmark.download_times else "N/A"),
        ("Download Throughput", f"{statistics.mean(benchmark.download_throughputs):.2f} MB/s" if benchmark.download_throughputs else "N/A")
    ]
    print(tabulate(throughput_report, headers=["Throughput", "Value"], tablefmt="grid"))

    print_detailed_results(benchmark)


async def main():
    await run_benchmark()


if __name__ == "__main__":
    asyncio.run(main())
