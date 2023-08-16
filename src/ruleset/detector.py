from typing import *
from dataclasses import dataclass

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from ruleset.validate import validate
from ruleset.definition import Definition

from web.request import HttpRequest

import re

@dataclass
class Detect:
    ipv4: str
    ipv6: str
    method: str
    header: List[Tuple[str, List[str]]]
    cookie: List[Tuple[str, List[str]]]
    url_resource: List[str]
    query_string: List[str]
    query_parameter: List[Tuple[str, List[str]]]
    body: List[str]
    json_body: List[Tuple[str, List[str]]]

class Detector:
    def _ipv4(net: IPv4Network):
        def detect(data: IPv4Address):
            if data == None: return False
            return data if data in net else False
        return detect

    def _ipv6(net: IPv6Network):
        def detect(data: IPv6Address):
            if data == None: return False
            return data if data in net else False
        return detect

    def _text(text: str):
        def detect(data: str):
            if data == None: return False
            return data if data == text else False
        return detect

    def _regexp(regexp: str):
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
        return Detect(
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
