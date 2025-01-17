import asyncio
import ssl
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
import logging


logging.basicConfig(level=logging.DEBUG)

async def send_request():
    host = 'localhost'
    port = 4433
    configuration = QuicConfiguration(is_client=True)

    configuration.verify_mode = ssl.CERT_NONE

    try:
        async with connect(host, port, configuration=configuration):
            print("Connected to QUIC server!")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    asyncio.run(send_request())
