# NetworkSecurityProject
This project implements a comparison between traditional TCP/TLS and QUIC protocols through custom-build client-server applications, specifically designed for file transfer.

## Installation
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

## Usage

### Using TCP + TLS
To use the file transfer application with the TCP/TLS protocol, you have to:

1. **Start the server**:

    Run the server from this directory with the cmd line below. The private key and certificate will be generated automatically when the server starts and they will be saved in `code/assets`.

    ```bash
    python code/src/TCP-TLS_server.py
    ```

2. **Run the client**:

    In a separate terminal, run the client to initiate the file transfer. As a default action, the client downloads an image stored in the server's directory. This can be changed in the function call.

    ```bash
    python code/src/TCP-TLS_client.py
    ```

### Using QUIC
To use the file transfer application with the QUIC protocol, you have to:

1. **Start the server**:
    
    Run the server from this directory with the cmd line below. The private key and certificate will be generate automatically when the server starts, and they will be saved in `code/assets`.

    ```bash
    python code/src/QUIC_server.py
    ```

2. **Run the client**:
    
    In a separate terminal, run the client to initiate the file transfer.


    ```bash
    python code/src/QUIC_client.py
    ```


## Benchmark
When executing the clients, the benchmark evaluates the performance of the two protocols by measuring key metrics such as handshake time, round-trip time (RTT), and file transfer throughput