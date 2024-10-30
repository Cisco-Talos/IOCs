import logging
import struct

from enum import IntEnum

logger = logging.getLogger("BugSleep")


class BugSleepCmd(IntEnum):
    GET = 0x01
    PUT = 0x02
    SHELL = 0x03
    INC_TIMEOUT = 0x04
    KILL = 0x06
    TASK_DELETE = 0x09
    TASK_CHECK = 0x0A
    TASK_ADD = 0x0B
    UPDATE_HEARTBEAT = 0x61
    SOCK_TIMEOUT = 0x62
    PING = 0x63


def chr_to_byte(num):
    """Convert an integer to a byte string.

    Args:
        num (int): Integer to convert.

    Returns:
        bytes: Byte representation of int.
    """
    return int.to_bytes(num, 1, "little")


def unicode_bytes(b_str):
    """Convert ASCII byte string to Unicode byte string.

    Args:
        b_str (bytes): ASCII string to convert.

    Returns:
        bytes: Unicode form of ASCII string.
    """
    return b"".join([chr_to_byte(c) + b"\x00" for c in b_str])


def process_payload(payload, offset=3):
    """Decode data sent from BugSleep.

    Args:
        payload (bytes): BugSleep message.
        offset (int, optional): Static value to add to each byte. Defaults to 3.

    Returns:
        bytes: Encrypted byte string.
    """
    r = b""
    for c in payload:
        r += chr_to_byte((c + offset) & 0xFF)
    return r


def hexify_if_needed(buff):
    """Make a pretty hexadecimal string if needed.

    Args:
        buff (bytes): String to inspect and format.

    Returns:
        str: Pretty version of buff.
    """
    printable = True
    for c in buff:
        if c < 32 or c > 126:
            printable = False
            break

    if printable:
        return buff.decode()
    return " ".join(["{:02X}".format(c) for c in buff])


def truncate(msg, size=20):
    """Format a string to fit a certain width.

    Args:
        msg (bytes): String to format.
        size (int, optional): Maximum width of string. Defaults to 20.

    Returns:
        str: Pretty string.
    """
    if len(msg) <= size:
        return hexify_if_needed(msg)
    return (
        hexify_if_needed(msg[: size // 2]) + "..." + hexify_if_needed(msg[-size // 2 :])
    )


def send(conn, msg):
    """Send an encrypted message to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        msg (bytes): String to send out socket.
    """
    enc_msg = process_payload(msg)
    conn.sendall(enc_msg)
    logger.debug("Sent:")
    logger.debug("  plain(%s)", truncate(msg))
    logger.debug("  cipher(%s)", truncate(enc_msg))


def read(conn, amount=1024):
    """Read an encrypted message from BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        amount (int, optional): Number of bytes to read. Defaults to 1024.

    Returns:
        bytes: Message from BugSleep implant.
    """
    data = conn.recv(amount)
    dec_data = process_payload(data)
    logger.debug("Received:")
    logger.debug("  plain(%s)", truncate(dec_data))
    logger.debug("  cipher(%s)", truncate(data))
    return dec_data


def read_dword(conn):
    """Read a DWORD message from a socket.

    Args:
        conn (socket.socket): BugSleep socket.

    Returns:
        int: 4 byte integer
    """
    return upack_dword(read(conn, 4))


def read_qword(conn):
    """Read a QWORD message from a socket.

    Args:
        conn (socket.socket): BugSleep socket.

    Returns:
        int: 8 byte integer
    """
    return upack_qword(read(conn, 8))


def upack_dword(b):
    """Unpack 4-byte integer from byte string.

    Args:
        b (bytes): String to extract from.

    Raises:
        ValueError: When less than 4 bytes are provided.

    Returns:
        int: 4-byte integer.
    """
    if len(b) < 4:
        raise ValueError(f"Not enough bytes for an DWORD ({b})")
    return struct.unpack("<I", b)[0]


def upack_qword(b):
    """Unpack 8-byte integer from byte string.

    Args:
        b (bytes): String to extract from.

    Raises:
        ValueError: When less than 8 bytes are provided.

    Returns:
        int: 8-byte integer.
    """
    if len(b) < 4:
        raise ValueError(f"Not enough bytes for an QWORD ({b})")
    return struct.unpack("<Q", b)[0]
