import socket
import ssl
import logging


logging.basicConfig(level=logging.INFO)


class TLSClient:
    def __init__(self, host: str, port: int, certfile):
        self.host = host
        self.port = port
        self.certfile = certfile

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(cafile=self.certfile)

        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                try:
                    ssock.connect((self.host, self.port))
                    self.logger.info(f"Connected to {self.host}:{self.port}")

                    ssock.sendall(b"Hello, TLS server!")

                    data = ssock.recv(1024)
                    self.logger.info(f"Received: {data.decode()}")
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
    client.connect()
