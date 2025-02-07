## QUIC Client/Server Throughput Optimization Attempts
This section outlines the efforts made to achieve acceptable throughput for the QUIC client/server implementation. Despite these attempts, the desired performance levels were not met. Below is a summary of the approaches taken.

### QUIC Implementation with HTTP/3
A full reimplementation of the QUIC server and client was undertaken, leveraging HTTP/3 for file transfer.  This implementation successfully supports client file uploads.  However, the resulting throughput performance, while double that of the original server/client, proved unstable.  Specifically, throughput decreased as file size increased, with optimal performance observed only for smaller packets.

### Asynchronous TCP + TLS Server
A further investigation explored the use of `asyncio` for the TCP+TLS server, aiming to identify if the library's operational characteristics were contributing to performance issues.  While this modification resulted in reduced performance for the TCP+TLS implementation, its performance remained substantially superior to the QUIC implementation.

### Threaded TCP + TLS Server
An alternative approach explored using threading for the TCP+TLS server.  However, this implementation also failed to achieve throughput comparable to the QUIC implementation.