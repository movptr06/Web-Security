from ipaddress import IPv4Network, IPv6Network

from ruleset.validate import check, validate

class Definition:
    def _ipv4(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return IPv4Network(definition[name])
        else:
            return None

    def _ipv6(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return IPv6Network(definition[name])
        else:
            return None

    def _str(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return definition[name]
        else:
            return None

    def _group(definition: dict, name: str):
        if name in definition:
            assert check(definition, name, dict)
            
            for item in definition[name].items():
                assert validate(item[0], str)
                assert validate(item[1], str)
            
            return definition[name]
        else:
            return None

    def _header(definition: dict, name: str):
        if name in definition:
            assert check(definition, name, dict)

            result = {}

            for item in definition[name].items():
                assert validate(item[0], str)
                assert validate(item[1], str)
                
                result[item[0].lower()] = item[1]

            return result
        else:
            return None

    def __init__(self, definition: dict):
        self.ipv4 = Definition._ipv4(definition, "ipv4Network")
        self.ipv6 = Definition._ipv6(definition, "ipv6Network")
        self.method = Definition._str(definition, "method")
        self.header = Definition._header(definition, "header")
        self.cookie = Definition._group(definition, "cookie")
        self.url_resource = Definition._str(definition, "urlResource")
        self.query_string = Definition._str(definition, "queryString")
        self.query_parameter = Definition._group(definition, "queryParameter")
        self.body = Definition._str(definition, "body")
        self.json_body = Definition._group(definition, "jsonBody")
