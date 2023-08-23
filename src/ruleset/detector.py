from typing import *
from dataclasses import dataclass

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from ruleset.validate import validate
from ruleset.definition import Definition

from web.request import HttpRequest

import re

@dataclass
class Detect:
    ipv4: IPv4Address
    ipv6: IPv6Address
    method: str
    header: List[Tuple[str, List[str]]]
    cookie: List[Tuple[str, List[str]]]
    url_resource: List[str]
    query_string: List[str]
    query_parameter: List[Tuple[str, List[str]]]
    body: List[str]
    json_body: List[Tuple[str, List[str]]]

    def logfmt(self):
        log = {}

        if self.ipv4:
            log["ipv4"] = str(self.ipv4)
        if self.ipv6:
            log["ipv6"] = str(self.ipv6)
        if self.method:
            log["method"] = self.method
        if self.header:
            log["header"] = self.header
        if self.cookie:
            log["cookie"] = self.cookie
        if self.url_resource:
            log["url_resource"] = self.url_resource
        if self.query_string:
            log["query_string"] = self.query_string
        if self.query_parameter:
            log["query_parameter"] = self.query_parameter
        if self.body:
            log["body"] = self.body
        if self.json_body:
            log["json_body"] = self.json_body

        return log

class Detector:
    def _ipv4(net: IPv4Network):
        def detect(data: List[IPv4Address]):
            if data == None: return False
            
            for ip_addr in data:
                if ip_addr in net: return ip_addr

            return False

        return detect

    def _ipv6(net: IPv6Network):
        def detect(data: List[IPv6Address]):
            if data == None: return False

            for ip_addr in data:
                if ip_addr in net: return ip_addr

            return False

        return detect

    def _text(text: str):
        def detect(data: str):
            if data == None: return False
            return data if data == text else False
        
        return detect

    def _regexp(regexp: str):
        if regexp[-1] == "\n":
            regexp = regexp[:-1]
        p = re.compile(regexp)

        def detect(data: str):
            if data == None: return False
            result = p.findall(data)
            return result if result != [] else False

        return detect

    def _group(group: dict):
        # key : text
        # value : regexp
        p = [(i[0], Detector._regexp(i[1])) for i in group.items()]

        def detect(data: Dict[str, str]):
            if data == None: return False
            result = []

            for name, regexp in p:
                if name in data:
                    if validate(data[name], tuple):
                        r = regexp("".join(data[name]))
                    else:
                        r = regexp(data[name])
                    if r:
                        result.append((name, r))
                elif name == "*":
                    for key, value in data.items():
                        if validate(data[key], tuple):
                            r = regexp("".join(data[key]))
                        else:
                            r = regexp(data[key])
                        if r:
                            result.append((key, r))

            return result if result else False

        return detect

    def _object(obj: dict):
        # key : text
        # value : regexp
        p = [(i[0], Detector._regexp(i[1])) for i in obj.items()]

        def detect(data: dict):
            if data == None: return False
            data = list(data.items())

            result = []

            for key, value in data:
                if validate(value, dict):
                    data += value.items()
                    continue
                for name, regexp in p:
                    if key == name or name == "*":
                        if validate(value, tuple):
                            r = regexp("".join(value))
                        else:
                            r = regexp(value)
                        if r:
                            result.append((key, r))

            return result if result else False

        return detect

    def __init__(self, definition: Definition):
        def PASS(data):
            # None != False
            return None
        self.none = PASS

        # ipv4 : ipv4
        if definition.ipv4 != None:
            self.ipv4 = Detector._ipv4(definition.ipv4)
        else:
            self.ipv4 = PASS

        # ipv6 : ipv6
        if definition.ipv6 != None:
            self.ipv6 = Detector._ipv6(definition.ipv6)
        else:
            self.ipv6 = PASS

        # method : text
        if definition.method != None:
            self.method = Detector._text(definition.method)
        else:
            self.method = PASS

        # header : group
        if definition.header != None:
            self.header = Detector._group(definition.header)
        else:
            self.header = PASS

        # cookie : group
        if definition.cookie != None:
            self.cookie = Detector._group(definition.cookie)
        else:
            self.cookie = PASS

        # url_resource : regexp
        if definition.url_resource != None:
            self.url_resource = Detector._regexp(definition.url_resource)
        else:
            self.url_resource = PASS

        # query_string : regexp
        if definition.query_string != None:
            self.query_string = Detector._regexp(definition.query_string)
        else:
            self.query_string = PASS

        # query_parameter : group
        if definition.query_parameter != None:
            self.query_parameter = Detector._group(definition.query_parameter)
        else:
            self.query_parameter = PASS

        # body : regexp
        if definition.body != None:
            self.body = Detector._regexp(definition.body)
        else:
            self.body = PASS

        # json_body : object
        if definition.json_body != None:
            self.json_body = Detector._object(definition.json_body)
        else:
            self.json_body = PASS

    def detect(self, http: HttpRequest):
        r = Detect(
            self.ipv4(http.ipv4),
            self.ipv6(http.ipv6),
            self.method(http.method),
            self.header(http.header),
            self.cookie(http.cookie),
            self.url_resource(http.url_resource),
            self.query_string(http.query_string),
            self.query_parameter(http.query_parameter),
            self.body(http.body),
            self.json_body(http.json_body)
        )

        if self.ipv4 != self.none and not r.ipv4:
            return False
        if self.ipv6 != self.none and not r.ipv6:
            return False
        if self.method != self.none and not r.method:
            return False
        if self.header != self.none and not r.header:
            return False
        if self.cookie != self.none and not r.cookie:
            return False
        if self.url_resource != self.none and not r.url_resource:
            return False
        if self.query_string != self.none and not r.query_string:
            return False
        if self.query_parameter != self.none and not r.query_parameter:
            return False
        if self.body != self.none and not r.body:
            return False
        if self.json_body != self.none and not r.json_body:
            return False

        return r
