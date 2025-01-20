import os
import ssl
import json
import socket
import logging


logging.basicConfig(level=logging.INFO)


class TLSClient:
    def __init__(self, host: str, port: int, certfile):
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
            self.logger.info(f"Attempting to connect to {self.host}:{self.port}...")

            ssock = self.context.wrap_socket(raw_socket, server_hostname=self.host)

            ssock.connect((self.host, self.port))
            self.logger.info(f"Successfully connected to {self.host}:{self.port}")

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

    def send_file(self, ssock: ssl.SSLSocket, file_path: str):
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

            # Send action request to server
            request = json.dumps({"action": "send_file"}).encode()

            ssock.sendall(request + b"\n")

            # Wait for server acknowledgment
            response = ssock.recv(4096).decode().strip()
            response_data = json.loads(response)
            if response_data.get("status") != "ready":
                self.logger.error(
                    f"Server is not ready to receive file: {
                        response_data.get('message')
                    }"
                )
                return

            # Send the file data in chunks
            metadata = json.dumps(
                {"file_name": file_name, "file_size": file_size}
            ).encode()

            ssock.sendall(metadata + b"\n")

            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    ssock.sendall(chunk)
            self.logger.info(f"File {file_name} sent successfully.")

        except Exception as e:
            self.logger.error(f"Error in send_file: {e}")

    def receive_file(self, ssock: ssl.SSLSocket):
        """
        Receives a file from a secure SSL/TLS socket connection and saves it locally.

        This method listens for metadata (file name and size) from the sender and then receives the file content in chunks. The received file is saved to a predefined directory.

        Parameters:
            ssock (ssl.SSLSocket): A secure SSL/TLS socket connected to the sender.
        """

        try:
            # Receive metadata from the client
            metadata_data = ssock.recv(4096).decode().strip()
            metadata = json.loads(metadata_data)

            file_name = metadata.get("file_name")
            file_size = metadata.get("file_size")
            if not file_name or not file_size:
                self.logger.error("Received malformed metadata from server.")
                raise ValueError("Missing file metadata.")

            self.logger.info(f"Receiving file: {file_name} ({file_size} bytes)")

            # Prepare save path
            save_path = os.path.join("code/assets/client_directory", file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Receive the file in chunks and save
            received_size = 0
            with open(save_path, "wb") as file:
                while received_size < file_size:
                    chunk = ssock.recv(min(4096, file_size - received_size))
                    if not chunk:
                        self.logger.error(
                            "Connection closed unexpectedly while receiving file."
                        )
                        raise ConnectionError("Incomplete file transfer.")

                    file.write(chunk)
                    received_size += len(chunk)
                    self.logger.debug(f"Received {received_size}/{file_size} bytes")

            # Verify transfer completeness
            if received_size == file_size:
                self.logger.info(f"File received successfully: {save_path}")
            else:
                self.logger.error(
                    f"File transfer incomplete. Expected {file_size}, got {
                        received_size
                    } bytes."
                )

        except json.JSONDecodeError as json_err:
            self.logger.error(f"Error decoding metadata: {json_err}")
            raise
        except Exception as e:
            self.logger.error(f"Error during file reception: {e}")
            raise

    def request_file(self, ssock: ssl.SSLSocket, file_name: str):
        """
        Requests a file from the server and initiates its download if available.

        This method sends a file request to the server, specifying the desired file name. Based on the server's response, it either initiates file reception or logs an appropriate error.

        Parameters:
            ssock (ssl.SSLSocket): A secure SSL/TLS socket connected to the server.
            file_name (str): The name of the file to request from the server.
        """

        try:
            self.logger.info(f"Requesting file: {file_name}")
            request_data = json.dumps(
                {"action": "request_file", "file_name": file_name}
            ).encode()

            ssock.sendall(request_data + b"\n")

            response = ssock.recv(4096).decode().strip()
            response_data = json.loads(response)

            if response_data.get("status") == "ready":
                self.logger.info("Server is ready to send file.")
                self.receive_file(ssock)
            elif response_data.get("status") == "not_found":
                self.logger.error("File not found on server.")
            else:
                self.logger.error(f"Unexpected server response: {response_data}")

        except json.JSONDecodeError as json_err:
            self.logger.error(f"Error decoding server response: {json_err}")
            raise
        except Exception as e:
            self.logger.error(f"Error during file request: {e}")
            raise

    def handle_communication(self, file_path: str, request_type: str):
        """
        Handles communication with the server for sending or receiving a file.

        This method establishes a secure SSL/TLS connection, then either sends or requests a file based on the specified request type. The connection is safely closed after the operation.

        Parameters:
            file_path (str): The path to the file for sending or the file name for requesting.
            request_type (str): The type of operation to perform:
                - "send": Sends the file at the specified `file_path` to the server.
                - "receive": Requests the file with the name derived from `file_path`.
        """

        ssock = None
        try:
            ssock = self.connect()
            if request_type == "send":
                self.send_file(ssock, file_path)
            elif request_type == "receive":
                self.request_file(ssock, os.path.basename(file_path))

        except Exception as e:
            self.logger.error(f"Error during communication: {e}")
        finally:
            self.close_connection(ssock)

    def close_connection(self, ssock: ssl.SSLSocket):
        """
        Closes a secure SSL/TLS socket connection.

        This method safely shuts down and closes the provided secure socket, ensuring proper resource cleanup.

        Parameters:
            ssock (ssl.SSLSocket): The secure SSL/TLS socket to close.
        """

        try:
            self.logger.info("Closing the connection...")
            ssock.shutdown(socket.SHUT_RDWR)

        except OSError as e:
            self.logger.warning(f"Error during socket shutdown: {e}")
        finally:
            ssock.close()
            self.logger.info("Connection closed.")


if __name__ == "__main__":
    client = TLSClient(
        host="127.0.0.1", port=8443, certfile="code/assets/certificate.pem"
    )
    client.handle_communication(
        file_path="code/assets/client_directory/Summer_1.jpg", request_type="receive"
    )
