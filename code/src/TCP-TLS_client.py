import socket
import ssl
import os
import json
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
    
    def send_file(self, ssock: ssl.SSLSocket, file_path: str):
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        metadata = json.dumps({
            "file_name": file_name,
            "file_size": file_size
        }).encode()

        try:
            ssock.sendall(metadata + b'\n')

            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    ssock.sendall(chunk)
            self.logger.info(f"File {file_name} sent successfully.")
            
        except Exception as e:
            self.logger.error(f"Error sending file: {e}")

    def connect(self, file_path):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                try:
                    ssock.connect((self.host, self.port))
                    self.logger.info(f"Connected to {self.host}:{self.port}")

                    self.send_file(ssock, file_path)

                except ssl.SSL_ERROR_SSL as ssl_err:
                    self.logger.error(f"SSL error: {ssl_err}")
                except Exception as e:
                    self.logger.error(f"Error during communication: {e}")
                finally:
                    self.logger.info("Connection closed.")

if __name__ == '__main__':
    client = TLSClient(
        host="127.0.0.1",
        port=8443,
        certfile='code/assets/certificate.pem'
    )
    client.connect("code/assets/Summer_1.jpg")
