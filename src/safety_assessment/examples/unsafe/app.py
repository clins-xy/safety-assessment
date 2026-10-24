import subprocess


def search_users(connection, username):
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    return connection.execute(query).fetchall()


def inspect_host(hostname):
    return subprocess.run("ping " + hostname, shell=True, capture_output=True, timeout=5)
