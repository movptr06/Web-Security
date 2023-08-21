from typing import *
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

import os
import yaml

from ruleset.ruleset import RuleSet
from ruleset.action import Action
from ruleset.rule import Rule

class Config:
    def _load_rule(filename):
        filenames = []
        if os.path.isdir(filename):
            for path, subdirs, files in os.walk(filename):
                for fn in files:
                    filenames.append(path + "/" + fn)
        else:
            filenames += [filename]

        files = []
        for fn in filenames:
            with open(fn, "rt") as f:
                files.append(Rule(f.read()))

        return files

    def __init__(self, filename):
        with open(filename, "rt") as f:
            config = yaml.safe_load(f)

        self.forward = [IPv4Network("127.0.0.1"), IPv6Network("::1")]
        if "x-forwarded-for" in config:
            for ip in config["x-forwarded-for"]:
                try:
                    self.forward.append(IPv4Network(ip))
                except:
                    self.forward.append(IPv6Network(ip))

        if "allow" in config:
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

        self.rules = []
        for rule_config in config["rules"]:
            rule_list = Config._load_rule(rule_config["file"])
            for rule in rule_list:
                if "action" in rule_config.keys():
                    rule.action = Action.serialize(rule_config["action"])
            self.rules += rule_list

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
