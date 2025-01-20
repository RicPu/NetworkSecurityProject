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

### Using TCP + TLS protocols
To use the file transfer application with the TCP/TLS protocol, you have to:

1. Start the server:

    Navigate to the `code/src` directory and run the server:

    ```bash
    python TCP-TLS_server.py
    ```

2. Run the client:

    In a separate terminal, run the client to initiate the file transfer.

    ```bash
    python TCP-TLS_client.py
    ```