# NetworkSecurityProject
[[ Report ]](report/main.pdf) [[ Presentation ]](presentation/Presentation.pptx)

This project implements a comparison between traditional TCP/TLS and QUIC protocols through custom-build client-server applications, specifically designed for file transfer.

## ⚙️ Installation
To set up the project with a Conda environment, follow these steps:

- Create and activate the Conda environment:

    ```bash
    conda create --name protocol-comparison python=3.12.8
    conda activate protocol-comparison
    ```

- Clone the repository and install dependencies:

    ```bash
    git clone https://github.com/RicPu/NetworkSecurityProject
    cd NetworkSecurityProject
    pip install -r code/requirements.txt
    ```

## 🚀 Usage
To get started, run the servers first from this directory. The private key and certificate will be generated automatically when the server starts and they will be saved in `code/assets`.

- To start the TCP+TLS server, run the following:
    ```bash
    python code/src/TCP-TLS_server.py
    ```

- To start the QUIC server, run the following:

    ```bash
    python code/src/QUIC_server.py
    ```

### 📊 Benchmark
When executing the clients, the benchmark evaluates the performance of the two protocols by measuring key metrics such as handshake time, round-trip time (RTT), and file transfer throughput. Both the TLS and QUIC implementations follow a similar workflow, but they use diffent underlying protocols (TCP for TLS and UDP for QUIC).

#### Workflow
When you run either the TLS or QUIC benchmark script, the following steps are performed:

1. **Handshake Test**: Measures the initial connection setup time.

2. **Ping Tests**: Measures Round-Trip Time (RTT) for small payloads. Calculates average RTT and standard deviation.

3. **File Transfer Tests**: The client first sends a 10MB test file (`test_upload.bin`) to the server, measuring upload time and throughput. Then, it requests a sample file (`Summer_1.jpg`) from the server, measuring download time and throughput.

4. **Results Display**: Prints a summary report with average metrics for handshake time, RTT, upload/download times and throughput. This includes detailed breakdowns for each iteration of uploads, downloads, and ping tests.

#### Usage
To execute the benchmarks, run the clients from this directory.

- To start the TCP+TLS client, run the following:
    ```bash
    python code/src/TCP-TLS_client.py
    ```

- To start the QUIC client, run the following:

    ```bash
    python code/src/QUIC_client.py
    ```

### 📦 Packet Capture and Analysis
This project includes two scripts for benchmarking and analyzing network performance using the PyShark library. These scripts capture and analyze packets during QUIC and TCP+TLS communication, providing insights into handshake times, Round-Trip Times (RTT), and file transfer performance.

#### Usage
To execute the packet capture and analysis, run the modified clients from this directory.

- To start the TCP+TLS client, run the following:
    ```bash
    python code/src/pyshark/pyshark_tcp_client.py
    ```

- To start the QUIC client, run the following:

    ```bash
    python code/src/pyshark/pyshark_quic_client.py
    ```