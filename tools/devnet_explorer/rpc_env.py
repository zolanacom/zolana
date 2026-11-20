#!/usr/bin/env python3
"""Write the validators' current loopback RPC address to an environment file.

The local validators choose new loopback RPC ports at every start and record
them in their readiness file. The feed unit runs this helper before each start
so the feed always polls the port that is live now instead of a fixed one.

usage: rpc_env.py READY_JSON ENV_FILE
"""
import json
import os
import sys


def rpc_url(ready):
    """Return the RPC URL of the first peer in a readiness document."""
    peers = ready.get("peers") if isinstance(ready, dict) else None
    if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
        raise ValueError("readiness document has no peers")
    rpc = peers[0].get("rpc")
    if not isinstance(rpc, str) or rpc.count(":") != 1:
        raise ValueError("first peer has no host:port RPC address")
    host, port = rpc.split(":")
    if host != "127.0.0.1":
        raise ValueError("RPC address is not loopback")
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("RPC port is not a valid port number")
    return "http://127.0.0.1:" + str(int(port))


def main(argv):
    if len(argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    ready_path, env_path = argv[1], argv[2]
    try:
        with open(ready_path, encoding="utf-8") as handle:
            url = rpc_url(json.load(handle))
    except (OSError, ValueError) as error:
        sys.stderr.write("rpc_env: %s\n" % error)
        return 1
    temporary = env_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write("RPC_URL=" + url + "\n")
    os.replace(temporary, env_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
