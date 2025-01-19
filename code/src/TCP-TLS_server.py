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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            self.logger.info(f"Server listening on {self.host}:{self.port}...")

            with self.context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    conn, addr = ssock.accept()
                    self.logger.info(f"Connection established with {addr}")

                    self.handle_connection(conn)
    
    def parse_metadata(self, data):
        try:
            metadata, remaining_data = data.split(b'\n', 1)
            return json.loads(metadata.decode()), remaining_data
        
        except Exception as e:
            self.logger.error(f"Error parsing metadata: {e}")
            return None, data
    
    def save_file(self, file_name, file_data):
        try:
            os.makedirs("received_files", exist_ok=True)
            output_path = os.path.join("received_files", file_name)

            with open(output_path, "wb") as file:
                file.write(file_data)
            self.logger.info(f"File saved as '{output_path}'")
            
        except Exception as e:
            self.logger.error(f"Error saving file '{file_name}': {e}")

    def handle_connection(self, conn: ssl.SSLSocket):
        try:
            initial_data = conn.recv(4096)
            if not initial_data:
                self.logger.warning("No data received.")
                return

            metadata, file_data = self.parse_metadata(initial_data)
            if metadata:
                file_name = metadata.get("file_name", "received_file")
                file_size = metadata.get("file_size", None)
                self.logger.info(f"Receiving file: {file_name} (size: {file_size})")
            else:
                file_name = "received_file"
                self.logger.warning("Metadata missing. Using default filename.")
            
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                file_data += chunk
            
            self.save_file(file_name, file_data)
            conn.sendall(b"File received successfully.")
        
        except Exception as e:
            self.logger.error(f"Error while handling connection: {e}")
        finally:
            conn.close()
            self.logger.info("Connection closed.")


if __name__ == '__main__':
    gen_key_cert()
    server = TLSServer(
        host="127.0.0.1",
        port=8443,
        certfile="code/assets/certificate.pem",
        keyfile="code/assets/private_key.pem"
    )
    server.start()
