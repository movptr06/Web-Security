from ipaddress import IPv4Address, IPv6Address, AddressValueError
from http.server import BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
from io import BytesIO

import json

class HttpRequest(BaseHTTPRequestHandler):
    def _cookie(cookie: str):
        cookies = SimpleCookie()
        cookies.load(cookie)
        return {k: v.value for k, v in cookies.items()}

    def _query_parameter(query_string: str):
        query_parameter = {}
        for k, v in parse_qs(query_string).items():
            query_parameter[k] = tuple(v)
        return query_parameter

    def __init__(self, request_text, ip):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.parse_request()

        try:
            self.ipv4 = IPv4Address(ip)
            self.ipv6 = None
        except AddressValueError:
            self.ipv4 = None
            self.ipv6 = IPv6Address(ip)

        self.method = self.command
        self.header = self.headers

        if "cookie" in self.headers:
            self.cookie = HttpRequest._cookie(self.headers["cookie"])
        else:
            self.cookie = None

        self.url_resource = urlparse(self.path).path
        self.query_string = urlparse(self.path).query
       
        self.query_parameter = HttpRequest._query_parameter(self.query_string)

        self.body = self.rfile.read().decode("latin1")

        try:
            self.json_body = json.loads(self.body)
        except ValueError:
            self.json_body = None
