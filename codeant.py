#!/usr/bin/env python3

import socket
import argparse
import ipaddress
import threading
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

VERSION = "0.5"

BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[33m"
ENDC = "\033[0m"

progress_lock = threading.Lock()
progress_counter = 0
total_hosts = 0


def display_banner():
    """Displays a styled banner indicating information about CVE-2024-6387 Vulnerability Checker.
    Parameters:
        - None
    Returns:
        - None
    Processing Logic:
        - Constructs a multi-line string using raw formatting to include escape sequences.
        - Inserts dynamic version number within the banner text.
        - The banner includes decorative ASCII art and author information."""
    banner = rf"""
{BLUE}
                                      _________ _________ ___ ___ .__
_______   ____   ___________   ____  /   _____//   _____//   |   \|__| ____   ____
\_  __ \_/ __ \ / ___\_  __ \_/ __ \ \_____  \ \_____  \/    ~    \  |/  _ \ /    \
 |  | \/\  ___// /_/  >  | \/\  ___/ /        \/        \    Y    /  (  <_> )   |  \
 |__|    \___  >___  /|__|    \___  >_______  /_______  /\___|_  /|__|\____/|___|  /
             \/_____/             \/        \/        \/       \/                \/
    CVE-2024-6387 Vulnerability Checker
    v{VERSION} / Alex Hagenah / @xaitax / ah@primepage.de
{ENDC}
"""
    print(banner)


def get_ssh_sock(ip, port, timeout):
    """Establish a socket connection to a given IP and port within a specified timeout.
    Parameters:
        - ip (str): The target IP address to connect to.
        - port (int): The target port number to connect to.
        - timeout (float): The maximum time in seconds to wait for the connection.
    Returns:
        - socket.socket or None: A connected socket object if the connection is successful; otherwise, None.
    Processing Logic:
        - Uses a TCP/IP socket to initiate the connection.
        - Sets a connection timeout to avoid indefinite blocking.
        - Handles exceptions by closing the socket and returning None if the connection fails."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return sock
    except:
        sock.close()
        return None


def get_ssh_banner(sock):
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception as e:
        return str(e)


def check_vulnerability(ip, port, timeout, result_queue):
    """Check the SSH server for known vulnerabilities based on its banner and update the result queue accordingly.
    Parameters:
        - ip (str): The IP address of the target server.
        - port (int): The port number where the SSH service is running.
        - timeout (int): The maximum time in seconds to wait for a connection.
        - result_queue (Queue): A thread-safe queue for storing the results of the vulnerability check.
    Returns:
        - None: This function updates the result_queue with the status and details of the vulnerability check.
    Processing Logic:
        - Attempts to establish an SSH connection to the specified IP and port.
        - Checks if the retrieved SSH banner starts with "SSH-2.0" and "SSH-2.0-OpenSSH".
        - Compares the banner against known vulnerable and excluded versions to determine status.
        - Updates a global progress counter in a thread-safe manner."""
    global progress_counter

    sshsock = get_ssh_sock(ip, port, timeout)
    if not sshsock:
        result_queue.put((ip, port, 'closed', "Port closed"))
        with progress_lock:
            progress_counter += 1
        return

    banner = get_ssh_banner(sshsock)
    if "SSH-2.0" not in banner:
        result_queue.put(
            (ip, port, 'failed', f"Failed to retrieve SSH banner: {banner}"))
        with progress_lock:
            progress_counter += 1
        return

    if "SSH-2.0-OpenSSH" not in banner:
        result_queue.put((ip, port, 'unknown', f"(banner: {banner})"))
        with progress_lock:
            progress_counter += 1
        return

    vulnerable_versions = [
        'SSH-2.0-OpenSSH_1',
        'SSH-2.0-OpenSSH_2',
        'SSH-2.0-OpenSSH_3',
        'SSH-2.0-OpenSSH_4.0',
        'SSH-2.0-OpenSSH_4.1',
        'SSH-2.0-OpenSSH_4.2',
        'SSH-2.0-OpenSSH_4.3',
        'SSH-2.0-OpenSSH_4.4',
        'SSH-2.0-OpenSSH_8.5',
        'SSH-2.0-OpenSSH_8.6',
        'SSH-2.0-OpenSSH_8.7',
        'SSH-2.0-OpenSSH_8.8',
        'SSH-2.0-OpenSSH_8.9',
        'SSH-2.0-OpenSSH_9.0',
        'SSH-2.0-OpenSSH_9.1',
        'SSH-2.0-OpenSSH_9.2',
        'SSH-2.0-OpenSSH_9.3',
        'SSH-2.0-OpenSSH_9.4',
        'SSH-2.0-OpenSSH_9.5',
        'SSH-2.0-OpenSSH_9.6',
        'SSH-2.0-OpenSSH_9.7'
    ]

    excluded_versions = [
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6',
        'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3',
        'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6',
        'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
        'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3'
    ]

    if any(version in banner for version in vulnerable_versions) and banner not in excluded_versions:
        result_queue.put((ip, port, 'vulnerable', f"(running {banner})"))
    else:
        result_queue.put((ip, port, 'not_vulnerable', f"(running {banner})"))

    with progress_lock:
        progress_counter += 1


def process_ip_list(ip_list_file):
    """Read IP addresses from a file and return them as a list.
    Parameters:
        - ip_list_file (str): The path to the file containing IP addresses, one per line.
    Returns:
        - list: A list of IP addresses as strings, with whitespace removed from each address.
    Processing Logic:
        - Handles IOError and prints an error message if the file cannot be read."""
    ips = []
    try:
        with open(ip_list_file, 'r') as file:
            ips.extend(file.readlines())
    except IOError:
        print(f"❌ [-] Could not read file: {ip_list_file}")
    return [ip.strip() for ip in ips]


def main():
    """Checks if servers are running a vulnerable version of OpenSSH (CVE-2024-6387).
    Parameters:
        - targets (list): IP addresses, domain names, file paths containing IP addresses, or CIDR network ranges.
        - port (int): Port number to check (default: 22).
        - timeout (float): Connection timeout in seconds (default: 1 second).
        - list (str): File containing a list of IP addresses to check.
    Returns:
        - None: Prints the results of the scan, including vulnerable and non-vulnerable servers.
    Processing Logic:
        - Parses input arguments and supports multiple types of target specifications.
        - Utilizes a thread pool executor to concurrently check for vulnerabilities.
        - Displays a progress update while scanning is in progress.
        - Processes scan results and categorizes servers based on their vulnerability status."""
    global total_hosts
    display_banner()

    parser = argparse.ArgumentParser(
        description="Check if servers are running a vulnerable version of OpenSSH (CVE-2024-6387).")
    parser.add_argument(
        "targets", nargs='*', help="IP addresses, domain names, file paths containing IP addresses, or CIDR network ranges.")
    parser.add_argument("--port", type=int, default=22,
                        help="Port number to check (default: 22).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1 second).")
    parser.add_argument(
        "-l", "--list", help="File containing a list of IP addresses to check.")

    args = parser.parse_args()
    targets = args.targets
    port = args.port
    timeout = args.timeout

    ips = []

    if args.list:
        ips.extend(process_ip_list(args.list))

    for target in targets:
        try:
            with open(target, 'r') as file:
                ips.extend(file.readlines())
        except IOError:
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    print(f"❌ [-] Invalid CIDR notation: {target}")
            else:
                ips.append(target)

    result_queue = Queue()

    total_hosts = len(ips)

    max_workers = 100

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_vulnerability, ip.strip(
        ), port, timeout, result_queue) for ip in ips]

        while any(future.running() for future in futures):
            with progress_lock:
                print(f"\rProgress: {progress_counter}/{total_hosts} hosts scanned", end="")
            time.sleep(1)

    for future in futures:
        future.result()

    print(f"\rProgress: {progress_counter}/{total_hosts} hosts scanned")

    total_scanned = len(ips)
    closed_ports = 0
    unknown = []
    not_vulnerable = []
    vulnerable = []

    while not result_queue.empty():
        ip, port, status, message = result_queue.get()
        if status == 'closed':
            closed_ports += 1
        elif status == 'unknown':
            unknown.append((ip, message))
        elif status == 'vulnerable':
            vulnerable.append((ip, message))
        elif status == 'not_vulnerable':
            not_vulnerable.append((ip, message))
        else:
            print(f"⚠️ [!] Server at {ip}:{port} is {message}")

    print(f"\n🛡️ Servers not vulnerable: {len(not_vulnerable)}\n")
    for ip, msg in not_vulnerable:
        print(f"   [+] Server at {GREEN}{ip}{ENDC} {msg}")
    print(f"\n🚨 Servers likely vulnerable: {len(vulnerable)}\n")
    for ip, msg in vulnerable:
        print(f"   [+] Server at {RED}{ip}{ENDC} {msg}")
    print(f"\n⚠️ Servers with unknown SSH version: {len(unknown)}\n")
    for ip, msg in unknown:
        print(f"   [+] Server at {ORANGE}{ip}{ENDC} {msg}")
    print(f"\n🔒 Servers with port {port} closed: {closed_ports}")
    print(f"\n📊 Total scanned targets: {total_scanned}\n")


if __name__ == "__main__":
    main()
