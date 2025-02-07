"""implementing threading to achieve similar speed to QUIC"""

import os
import socket
import ssl
import json
import logging
import threading
import time

from utils import gen_key_cert

# Configure logging for the TLS server.
logging.basicConfig(level=logging.INFO)


class TLSServer:
    """
    A simple TCP/TLS server that handles secure file transfers and ping requests.

    This server supports the following actions:
      - "send_file": Allows a client to upload a file to the server.
      - "request_file": Allows a client to download a file from the server.
      - "ping": Responds to a ping request with a "pong".
    """

    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        """
        Initialize the TLSServer with network parameters and SSL credentials.

        Parameters:
            host (str): The hostname or IP address on which the server listens.
            port (int): The port number on which the server listens.
            certfile (str): Path to the SSL certificate file.
            keyfile (str): Path to the SSL private key file.
        """
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        self.logger = logging.getLogger(__name__)

        # Create an SSL context for the server using TLS.
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

    def start(self):
        """
        Starts the TCP/TLS server and begins listening for incoming client connections.

        This method initializes a TCP socket and wraps it with TLS for secure communication.
        It binds the server socket to the specified host and port, then listens for incoming client
        connections. Upon accepting a connection, the server creates a TLS-encrypted socket for
        communication with the client.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                # Set a timeout on the socket to allow periodic checks for KeyboardInterrupt.
                server_socket.settimeout(1)
                self.logger.info(f"Server listening on {self.host}:{self.port}")

                # Wrap the TCP socket with TLS.
                with self.context.wrap_socket(
                    server_socket, server_side=True
                ) as tls_socket:
                    while True:
                        try:
                            client_socket, addr = tls_socket.accept()
                        except socket.timeout:
                            # Timeout expired; continue to check for interrupt signals.
                            continue
                        self.logger.info(f"Connection accepted from {addr}")
                        self.handle_client(client_socket)
        except KeyboardInterrupt:
            self.logger.info("Stopping server.")
        except Exception as e:
            self.logger.error(f"Error in server operation: {e}")

    def handle_client(self, client_socket: ssl.SSLSocket):
        """
        Handles communication with a connected client, processes requests, and sends appropriate responses.

        This method processes the incoming request from the client, determines the desired action (such as sending or
        requesting a file), and responds accordingly. The method handles three main types of actions:
          - "send_file": The client intends to upload a file to the server.
          - "request_file": The client requests a file from the server.
          - "ping": A simple ping request.

        Parameters:
            client_socket (ssl.SSLSocket): The secure socket through which the server communicates with the client.
        """
        try:
            with client_socket:
                request = client_socket.recv(4096).decode().strip()
                try:
                    request_data = json.loads(request)
                except Exception:
                    self.send_error(client_socket, "Invalid JSON request.")
                    return

                action = request_data.get("action")
                if action == "send_file":
                    self.logger.info("Client wants to send a file.")
                    # Notify client that the server is ready to receive the file.
                    response = json.dumps({"status": "ready"})
                    client_socket.sendall(response.encode() + b"\n")
                    self.receive_file(client_socket)
                elif action == "request_file":
                    file_name = request_data.get("file_name")
                    self.logger.info(f"Client is requesting file: {file_name}")
                    file_path = os.path.join("code/assets/server_directory", file_name)
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        response = json.dumps({"status": "ready"})
                        ready = True
                    else:
                        response = json.dumps({"status": "not_found"})
                        ready = False
                    client_socket.sendall(response.encode() + b"\n")
                    if ready:
                        self.send_file(client_socket, file_path)
                elif action == "ping":
                    self.logger.info("Received ping request.")
                    client_socket.sendall(b"pong")
                else:
                    self.logger.error("Unknown action received from client.")
                    self.send_error(client_socket, "Unknown action.")
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")

    def receive_file(self, client_socket: ssl.SSLSocket):
        """
        Receives a file from the client and saves it to the server's local directory.

        This method handles the file reception process by first receiving metadata (file size and name) from the client,
        and then receiving the file in chunks. It ensures that the entire file is received and saved. In case of any
        errors or an incomplete transfer, an error message is sent to the client.

        Parameters:
            client_socket (ssl.SSLSocket): The secure socket through which the server communicates with the client.
        """
        try:
            metadata_data = client_socket.recv(4096).decode().strip()
            metadata = json.loads(metadata_data)
            file_size = metadata.get("file_size")
            file_name = metadata.get("file_name")
            if not file_name or not file_size:
                self.logger.error("Invalid metadata received from the client.")
                self.send_error(client_socket, "Invalid metadata.")
                return

            self.logger.info(f"Receiving file: {file_name} ({file_size} bytes)")
            save_path = os.path.join("code/assets/server_directory", file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            start_time = time.perf_counter()
            received_size = 0
            with open(save_path, "wb") as file:
                while received_size < file_size:
                    chunk = client_socket.recv(min(4096, file_size - received_size))
                    if not chunk:
                        self.logger.error(
                            "Connection closed unexpectedly during file reception."
                        )
                        raise ConnectionError("Incomplete file transfer.")
                    file.write(chunk)
                    received_size += len(chunk)
                    self.logger.debug(f"Received {received_size}/{file_size} bytes")
            end_time = time.perf_counter()
            if received_size == file_size:
                upload_time = end_time - start_time
                throughput = (file_size / (1024 * 1024)) / upload_time
                self.logger.info(
                    f"File received successfully: {save_path} in {upload_time:.6f} s (Throughput: {throughput:.2f} MB/s)"
                )
                response = json.dumps(
                    {
                        "status": "success",
                        "upload_time": upload_time,
                        "throughput": throughput,
                    }
                )
                client_socket.sendall(response.encode() + b"\n")
            else:
                self.logger.error("File transfer incomplete.")
                self.send_error(client_socket, "File transfer incomplete.")
        except Exception as e:
            self.logger.error(f"Error during file reception: {e}")
            self.send_error(client_socket, f"Error during file reception: {str(e)}")

    def send_file(self, client_socket: ssl.SSLSocket, file_path: str):
        """
        Sends a file to the client over a secure TLS connection.

        This method sends a specified file to the client in chunks. It first sends metadata (file name and size)
        and then transmits the file content. It ensures that the file is fully sent and logs the status of the transfer.

        Parameters:
            client_socket (ssl.SSLSocket): The secure socket through which the server communicates with the client.
            file_path (str): The local path to the file that needs to be sent to the client.
        """
        try:
            file_size = os.path.getsize(file_path)
            self.logger.info(f"Sending file: {file_path} ({file_size} bytes)")
            metadata = json.dumps(
                {"file_name": os.path.basename(file_path), "file_size": file_size}
            ).encode()
            client_socket.sendall(metadata + b"\n")
            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    client_socket.sendall(chunk)
            self.logger.info(f"File {os.path.basename(file_path)} sent successfully.")
        except Exception as e:
            self.logger.error(f"Error during file send: {e}")

    def send_error(self, client_socket: ssl.SSLSocket, message: str):
        """
        Sends an error message to the client in JSON format.

        Parameters:
            client_socket (ssl.SSLSocket): The secure socket through which the server communicates with the client.
            message (str): The error message to be sent.
        """
        try:
            response = json.dumps({"status": "error", "message": message})
            client_socket.sendall(response.encode() + b"\n")
        except Exception as e:
            self.logger.error(f"Failed to send error message: {e}")


if __name__ == "__main__":
    gen_key_cert()
    server = TLSServer(
        host="127.0.0.1",
        port=8443,
        certfile="code/assets/certificate.pem",
        keyfile="code/assets/private_key.pem",
    )

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()

    try:
        while True:
            pass  # Mantiene il programma in esecuzione
    except KeyboardInterrupt:
        print("\nServer interrupted by user.")
