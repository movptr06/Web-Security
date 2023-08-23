#!/usr/bin/env python3
from typing import *

import asyncio
import socket
import sys

HEADER_MAX_SIZE = 1024 * 4 # 4KB

SIZE = 1024

TE = b"\r\ntransfer-encoding:"
CL = b"\r\ncontent-length:"
XFF = b"\r\nx-forwarded-for:"

BLOCKED_HEADER = (
    b"HTTP/1.0 403 Forbidden\r\n"
    b"Server: Web-Security\r\n"
    b"Content-Type: text/html\r\n"
)

class Reader:
    def __init__(self, reader):
        self.reader = reader
        self.data = b""

    async def read(self, length):
        if len(self.data) >= length:
            result = self.data[:length]
            self.data = self.data[length:]
            return result
        else:
            size = SIZE if SIZE > length else length
            self.data += await self.reader.read(size)
            return await self.read(length)

class HttpProxy:
    async def _http(reader):
        data = b""
        mode = None

        r = Reader(reader)

        i = 0
        while i < HEADER_MAX_SIZE:
            data += await r.read(1)
            i += 1

            if (mode == None or mode == CL) and data[-len(TE):].lower() == TE:
                mode = TE
                save = i

                while i < HEADER_MAX_SIZE:
                    data += await r.read(1)
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
                    data += await r.read(1)
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
                    chunk += await r.read(1)
                    i += 1
                    if chunk[-2:] == b"\r\n":
                        length = int(chunk.strip(), 16)
                        break
                else:
                    return False
                if length == 0:
                    return data
                data += await r.read(length)
                await r.read(2)
            return data
        elif mode == CL:
            data += await r.read(length)
            return data
        else:
            return False # Unreachable

    def __init__(self, handler, block: bytes, rhost: str, rport: int):
        self.handler = handler
        self.block = block
        self.rhost = rhost
        self.rport = rport

    async def _proxy(self, writer, client, data: bytes, ip):
        client_reader, client_writer = client

        end = data.index(b"\r\n\r\n")
        xff = data[:end].lower().find(XFF)
        if xff != -1:
            xff += 2
            xff_end = xff + data[xff:].index(b"\r\n")
            xff_data = data[xff:xff_end]
            xff_data += b", " + ip.encode("latin1")

            data = data[:xff] + xff_data + data[xff_end:]
        else:
            xff_data = b"\r\nX-Forwarded-For: " + ip.encode("latin1")
            data = data[:end] + xff_data + data[end:]

        client_writer.write(data)
        await client_writer.drain()

        response = await HttpProxy._http(client_reader)
        writer.write(response)

        client_writer.close()

    async def _block(self, writer):
        buf = b""
        buf += BLOCKED_HEADER
        buf += b"Content-Length: " + str(len(self.block)).encode("latin1") + b"\r\n"
        buf += b"\r\n"
        buf += self.block

        writer.write(buf)

    async def _session(self, reader, writer):
        try:
            ip, port = writer.get_extra_info("peername")

            data = await HttpProxy._http(reader)
        except Exception as e:
            return

        result = self.handler(data, ip)

        try:
            if result:
                client = await asyncio.open_connection(self.rhost, self.rport)
                await self._proxy(writer, client, data, ip)
            else:
                await self._block(writer)

            await writer.drain()

            writer.close()
        except Exception as e:
            return

    async def _bind(self, lhost: str, lport: int):
        async def handler(reader, writer):
            await self._session(reader,writer)

        server = await asyncio.start_server(handler, host=lhost, port=lport)

        async with server:
            await server.serve_forever()

    def run(self, lhost: str, lport: int):
        asyncio.run(self._bind(lhost, lport))

def default_handler(data: bytes, ip):
    return True

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} LPORT RHOST RPORT")
        sys.exit(-1)

    LPORT = int(sys.argv[1])
    RHOST = sys.argv[2]
    RPORT = int(sys.argv[3])

    http = HttpProxy(default_handler, b"<h1>BLOCKED</h1>", RHOST, RPORT)
    http.run("0.0.0.0", LPORT)
