import asyncio
import logging
from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from key_cert_gen import gen_key_cert


async def main(host: str, port: int, configuration: QuicConfiguration):
    await serve(
        host, port, configuration=configuration,
        create_protocol=QuicConnectionProtocol
    )
    print("Server running...")
    await asyncio.Future()

if __name__ == "__main__":
    host = "::"
    port = 4433

    logging.basicConfig(level=logging.INFO)

    gen_key_cert()

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(
        certfile="code/assets/certificate.pem", 
        keyfile="code/assets/private_key.pem"
    )

    asyncio.run(main(host, port, configuration))
