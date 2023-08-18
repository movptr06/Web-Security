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

        self.method = self.command
        self.header = self.headers

        self.ipv4 = []
        self.ipv6 = []

        ip_list = []

        if "x-forwarded-for" in self.headers:
            ip_list.extend([x.strip() for x in self.headers["x-forwarded-for"].split(",")])
        
        ip_list.append(ip)

        for ip_addr in ip_list:
            try:
                self.ipv4.append(IPv4Address(ip_addr))
            except:
                self.ipv6.append(IPv6Address(ip_addr))

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
