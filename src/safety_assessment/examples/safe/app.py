import ipaddress
import subprocess


def search_users(connection, username):
    return connection.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchall()


def inspect_host(hostname):
    address = str(ipaddress.ip_address(hostname))
    return subprocess.run(["ping", address], shell=False, capture_output=True, timeout=5)
