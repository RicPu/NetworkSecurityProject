import socket
import ssl
import logging


logging.basicConfig(level=logging.INFO)


class TLSServer:
    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            self.logger.info(f"Server listening on {self.host}:{self.port}...")

            with self.context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    conn, addr = ssock.accept()
                    self.logger.info(f"Connection established with {addr}")

                    self.handle_connection(conn)

    def handle_connection(self, conn: ssl.SSLSocket):
        try:
            data = conn.recv(1024)
            if data:
                self.logger.info(f"Received: {data.decode()}")
                conn.sendall(b"Hello, TLS client!")
        except Exception as e:
            self.logger.error(f"Error while handling connection: {e}")
        finally:
            conn.close()
            self.logger.info("Connection closed.")


if __name__ == '__main__':
    server = TLSServer(
        host="127.0.0.1",
        port=8443,
        certfile="code/assets/certificate.pem",
        keyfile="code/assets/private_key.pem"
    )
    server.start()
