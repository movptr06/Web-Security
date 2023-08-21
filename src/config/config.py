from typing import *
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

import yaml

class Config:
    def __init__(self, config_yaml):
        config = yaml.safe_load(config_yaml)

        self.forward = []

        for ip in config["x-forwarded-for"]:
            try:
                self.forward.append(IPv4Network(ip))
            except:
                self.forward.append(IPv6Network(ip))

        self.allowlist = [
            (
                IPv4Network(allow["ipv4Network"])
                if "ipv4Network" in allow else None,

                IPv6Network(allow["ipv6Network"])
                if "ipv6Network" in allow else None,

                allow["userAgent"]
                if "userAgent" in allow else None
            )
            for allow in config["allow"]
        ]

    def allow(self, ip, ipv4, ipv6, user_agent):
        for net in self.forward:
            if ip in net:
                forward = True

        if forward:
            ip_list = [ip] + ipv4 + ipv6
        else:
            ip_list = [ip]

        for addr in ip_list:
            for ipv4_, ipv6_, user_agent_ in self.allowlist:
                if user_agent_ == user_agent or not user_agent:
                    if not ipv4_ and not ipv6_:
                        return True
                    if ipv4_ and addr in ipv4_:
                        return True
                    if ipv6_ and addr in ipv6_:
                        return True

        return False
