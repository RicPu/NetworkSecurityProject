import json
import asyncio
import logging
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted, ConnectionTerminated
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from utils import gen_key_cert


logging.basicConfig(level=logging.INFO)


class FileTransferProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_data = {}
        self.connected_event = asyncio.Event()

    def parse_metadata(self, data):
        try:
            metadata, remaining_data = data.split(b'\n', 1)
            return json.loads(metadata.decode()), remaining_data
        except Exception as e:
            logging.error(f"Error parsing metadata: {e}")
            return None, data

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            logging.info("Handshake completed!")
            self.connected_event.set()

        elif isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if stream_id not in self.stream_data:
                metadata, remaining_data = self.parse_metadata(data)
                if metadata:
                    file_name  = metadata.get("file_name", f"received_file_{stream_id}")
                    self.stream_data[stream_id] = {
                        "data": bytearray(remaining_data),
                        "file_name": file_name
                    }
                else:
                    self.stream_data[stream_id] = {
                        "data": bytearray(data),
                        "file_name": f"received_file_{stream_id}"
                    }
            
            else:
                self.stream_data[stream_id]["data"].extend(data)

            if event.end_stream:
                file_name = self.stream_data[stream_id]["file_name"]
                with open(file_name, "wb") as file:
                    file.write(self.stream_data[stream_id]["data"])
                logging.info(f"File saved as '{file_name}'")

                self.stream_data.pop(stream_id, None)
        elif isinstance(event, ConnectionTerminated):
            logging.info(f"Connection terminated: {event.error_code}, reason: {event.frame_type}")


async def main(host: str, port: int, configuration: QuicConfiguration):
    await serve(
        host, port, configuration=configuration,
        create_protocol=FileTransferProtocol
    )
    logging.info("Server running...")
    await asyncio.Future()


if __name__ == "__main__":
    host = "::"
    port = 4433
    gen_key_cert() # Generate private key and certificate

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(
        certfile="code/assets/certificate.pem", 
        keyfile="code/assets/private_key.pem"
    )

    asyncio.run(main(host, port, configuration))
