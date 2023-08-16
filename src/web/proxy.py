from typing import *

import asyncio
import socket

HEADER_MAX_SIZE = 1024 * 16 # 16KB

TE = b"\r\ntransfer-encoding:"
CL = b"\r\ncontent-length:"

BLOCKED_HEADER = (
    b"HTTP/1.0 403 Forbidden\r\n"
    b"Server: SSR Web Security\r\n"
    b"Content-Type: text/html\r\n"
)

class HttpProxy:
    async def _http(reader):
        data = b""
        mode = None

        i = 0
        while i < HEADER_MAX_SIZE:
            data += await reader.read(1)
            i += 1

            if (mode == None or mode == CL) and data[-len(TE):].lower() == TE:
                mode = TE
                save = i

                while i < HEADER_MAX_SIZE:
                    data += await reader.read(1)
                    i += 1
                    if data[-2:] == b"\r\n":
                        if data[save:].strip() == b"chunked":
                            break
                        else:
                            return False # Only chunked encoding is supported.
                else:
                    return False

            elif mode == None and data[-len(CL):].lower() == CL:
                mode = CL
                save = i

                while i < HEADER_MAX_SIZE:
                    data += await reader.read(1)
                    i += 1
                    if data[-2:] == b"\r\n":
                        length = int(data[save:].strip())
                        break
                else:
                    return False

            elif data[-4:] == b"\r\n\r\n":
                break

        if mode == None:
            return data
        elif mode == TE:
            while True:
                i = 0
                chunk = b""
                while i < HEADER_MAX_SIZE:
                    chunk += await reader.read(1)
                    i += 1
                    if chunk[-2:] == b"\r\n":
                        length = int(chunk.strip(), 16)
                        break
                else:
                    return False
                if length == 0:
                    return data
                data += await reader.read(length)
                await reader.read(2)
            return data
        elif mode == CL:
            data += await reader.read(length)
            return data
        else:
            return False # Unreachable

    async def _proxy(writer, client, data: bytes):
        client_reader, client_writer = client
        
        client_writer.write(data)
        await client_writer.drain()
        
        response = await HttpProxy._http(client_reader) 
        writer.write(response)

        client_writer.close()

    async def _block(block: bytes, writer):
        buf = b""
        buf += BLOCKED_HEADER
        buf += b"Content-Length: " + str(len(block)).encode("latin1") + b"\r\n"
        buf += b"\r\n"
        buf += block

        writer.write(buf)
        

    def __init__(self, handler, block: bytes, rhost: str, rport: int):
        self.handler = handler
        self.block = block
        self.rhost = rhost
        self.rport = rport

    async def _bind(self, lhost: str, lport: int):
        async def handler(reader, writer):
            try:
                ip, port = writer.get_extra_info("peername")

                data = await HttpProxy._http(reader)

                if(self.handler(data)):
                    client = await asyncio.open_connection(self.rhost, self.rport)
                    await HttpProxy._proxy(writer, client, data)
                else:
                    await HttpProxy._block(self.block, writer)

                await writer.drain()
 
                writer.close()
            except:
                try:
                    await HttpProxy._block(self.block, writer)
                    writer.close()
                except:
                    pass

        server = await asyncio.start_server(handler, host=lhost, port=lport)

        async with server:
            await server.serve_forever()

    def run(self, lhost: str, lport: int):
        asyncio.run(self._bind(lhost, lport))

def handler(data: bytes):
    return True

http = HttpProxy(handler, b"<h1>BLOCKED</h1>", "127.0.0.1", 8000)
http.run("0.0.0.0", 4000)
