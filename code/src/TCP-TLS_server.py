import os
import socket
import ssl
import json
import logging

from utils import gen_key_cert


logging.basicConfig(level=logging.INFO)


class TLSServer:
    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        self.logger = logging.getLogger(__name__)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                self.logger.info(f"Server listening on {self.host}:{self.port}")

                with self.context.wrap_socket(server_socket, server_side=True) as tls_socket:
                    while True:
                        client_socket, addr = tls_socket.accept()
                        self.logger.info(f"Connection accepted from {addr}")
                        self.handle_client(client_socket)
                        
        except Exception as e:
            self.logger.error(f"Error in server operation: {e}")
    
    def handle_client(self, client_socket: ssl.SSLSocket):
        try:
            with client_socket:
                request = client_socket.recv(4096).decode().strip()
                request_data = json.loads(request)

                action = request_data.get("action")

                if action == "send_file":
                    self.logger.info("Client wants to send a file.")

                    response = json.dumps({"status": "ready"})
                    client_socket.sendall(response.encode() + b'\n')

                    self.receive_file(client_socket)
                elif action == "request_file":
                    file_name = request_data.get("file_name")
                    self.logger.info(f"Client is requesting file: {file_name}")
                    file_path = os.path.join("code/assets/server_directory", file_name)

                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        response = json.dumps({
                            "status": "ready"
                        })
                        ready = True
                    else:
                        response = json.dumps({
                            "status": "not_found"
                        })
                        ready = False

                    client_socket.sendall(response.encode() + b'\n')

                    if ready:
                        print("Preparing to send")
                        self.send_file(client_socket, file_path)
                else:
                    self.logger.error("Unknown action received from client.")
                    self.send_error(client_socket, "Unknown action.")

        except json.JSONDecodeError:
            self.logger.error("Invalid request format from client.")
            self.send_error(client_socket, "Invalid request format.")
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")

    def receive_file(self, client_socket: ssl.SSLSocket):
        try:
            # Receive metadata from the client
            metadata_data = client_socket.recv(4096).decode().strip()
            metadata = json.loads(metadata_data)
            
            file_size = metadata.get("file_size")
            file_name = metadata.get("file_name")
            if not file_name or not file_size:
                self.logger.error("Invalid metadata received from the client: Missing file size.")
                self.send_error(client_socket, "Invalid metadata: Missing file size.")
                return

            self.logger.info(f"Receiving file: {file_name} ({file_size} bytes)")

            # Prepare save path
            save_path = os.path.join("code/assets/server_directory", file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Receive the file in chunks and save
            received_size = 0
            with open(save_path, 'wb') as file:
                while received_size < file_size:
                    chunk = client_socket.recv(min(4096, file_size - received_size))
                    if not chunk:
                        self.logger.error("Connection closed unexpectedly during file reception.")
                        raise ConnectionError("Incomplete file transfer.")

                    file.write(chunk)
                    received_size += len(chunk)
                    self.logger.debug(f"Received {received_size}/{file_size} bytes")

            # Verify transfer completeness
            if received_size == file_size:
                self.logger.info(f"File received successfully: {save_path}")
                
                response = json.dumps({"status": "success", "message": f"File {file_name} received successfully."})
                client_socket.sendall(response.encode() + b'\n')
            else:
                self.logger.error(f"File transfer incomplete: Expected {file_size} bytes, received {received_size} bytes.")
                self.send_error(client_socket, "File transfer incomplete.")

        except Exception as e:
            self.logger.error(f"Error during file reception: {e}")
            self.send_error(client_socket, f"Error during file reception: {str(e)}")

    def send_file(self, client_socket: ssl.SSLSocket, file_path: str):
        try:
            file_size = os.path.getsize(file_path)
            self.logger.info(f"Sending file: {file_path} ({file_size} bytes)")

            metadata = json.dumps({
                "file_name": os.path.basename(file_path),
                "file_size": file_size
            }).encode()

            client_socket.sendall(metadata + b'\n')

            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    client_socket.sendall(chunk)

            self.logger.info(f"File {os.path.basename(file_path)} sent successfully.")

        except Exception as e:
            self.logger.error(f"Error during file send: {e}")
    
    def send_error(self, client_socket: ssl.SSLSocket, message: str):
        try:
            response = json.dumps({"status": "error", "message": message})
            client_socket.sendall(response.encode() + b'\n')

        except Exception as e:
            self.logger.error(f"Failed to send error message: {e}")


if __name__ == '__main__':
    gen_key_cert()
    server = TLSServer(
        host="127.0.0.1",
        port=8443,
        certfile="code/assets/certificate.pem",
        keyfile="code/assets/private_key.pem"
    )
    server.start()
