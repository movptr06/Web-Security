#!/usr/bin/env python3

from config.config import Config

from log.logger import Logger

from con.handler import Handler

from web.proxy import HttpProxy

from argparse import ArgumentParser

import os

VERSION = "1.0"

OUTPUT = ""

def args():
    parser = ArgumentParser(
        description="Web Security " + VERSION
    )

    parser.add_argument(
        dest="RHOST",
        type=str,
        help="Remote web server host"
    )

    parser.add_argument(
        dest="RPORT",
        type=int,
        help="Remote web server port"
    )

    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        default=80,
        help="Port number"
    )

    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        type=str,
        default="waf-config.yml",
        help="Config file"
    )

    parser.add_argument(
        "-l",
        "--log",
        dest="log",
        type=str,
        default="waf-log.json",
        help="Log file"
    )

    return parser.parse_args()

def main():
    global OUTPUT
    argv = args()

    config = Config(argv.file)

    if os.path.isfile(argv.log):
        with open(argv.log, "rt") as f:
            OUTPUT = f.read()

    def output(data):
        global OUTPUT
        with open(argv.log, "wt") as f:
            if OUTPUT:
                OUTPUT += ",\n" + data
            else:
                OUTPUT = data
            f.write("[\n" + OUTPUT + "\n]\n")

    logger = Logger(output)
    
    handler = Handler(
        config.ruleset,
        config.allow,
        config.size,
        config.oversize,
        logger.detected
    )

    proxy = HttpProxy(
        handler.handler,
        config.block,
        argv.RHOST,
        argv.RPORT
    )
    
    proxy.run("0.0.0.0", argv.port)

if __name__ == "__main__":
    main()
