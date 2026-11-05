#!/usr/bin/env python3
"""Opt-in HTTPS delivery of the existing browser-local wallet and signed ingress.

This is separate from the unchanged loopback preparation server. An exact
reviewed TLS policy binds the public origin, socket, certificate and key. The
existing BrowserHandler retains every Host/Origin/framing/access check; the
native upstream remains authoritative for membership, quotas and settlement.
"""
import argparse
import ipaddress
from pathlib import Path
import ssl
import threading
import time

from browser_gateway import BrowserGateway, BrowserHandler, assets, decode, pinned_json
from direct_tls import policy
from service_tls import TLSServer, context


class RequestBudget:
    """Ephemeral socket-IP gate, supplementing durable upstream membership quotas.

    Fixed per-IP64 burst/16 requests per second; global256 burst/64 per second.
    At most1024 IPs; reclaim only entries idle since acceptance for60 seconds.
    Rejections never reset an IP bucket; requests reaching the IP/table gate
    also consume global capacity. No proxy headers or persistence are used.
    """
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.peers = clock, threading.Lock(), {}
        self.tokens, self.updated = 256.0, clock()

    def allow(self, peer):
        try:
            if not isinstance(peer, str) or str(ipaddress.IPv4Address(peer)) != peer:
                return False
        except ipaddress.AddressValueError:
            return False
        with self.lock:
            now = max(self.updated, self.clock())
            self.tokens = min(256.0, self.tokens + (now - self.updated) * 64)
            self.updated = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            previous = self.peers.get(peer)
            if previous is None:
                if len(self.peers) >= 1024:
                    self.peers = {ip: row for ip, row in self.peers.items() if now - row[1] < 60}
                if len(self.peers) >= 1024:
                    return False
                tokens = 64.0
            else:
                tokens = min(64.0, previous[0] + (now - previous[1]) * 16)
            if tokens < 1:
                return False
            self.peers[peer] = (tokens - 1, now)
            return True


class HTTPSBrowserHandler(BrowserHandler):
    def allowed(self, post=False):
        if not super().allowed(post=post):
            return False
        if not self.server.request_budget.allow(self.client_address[0]):
            self.close_connection = True
            self.reply(429, {"error": "rate_limited", "automatic_retry": False}, retry="1")
            return False
        return True


def listener(origin, port, app, certificate, private_key, tls_policy, tls_sha256):
    """Bind only after verifying the explicitly selected HTTPS identity/policy."""
    value, authority, hostname, dns = policy(
        tls_policy, tls_sha256, origin, port, certificate, private_key)
    ctx = context(certificate, private_key)
    ctx.set_alpn_protocols(["http/1.1"])

    def sni(_connection, name, _context):
        if (dns and name != hostname) or (not dns and name is not None):
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    ctx.set_servername_callback(sni)
    # Do not use direct_tls.guarded: that native-only wrapper refuses all
    # browser Origins. BrowserHandler already checks the exact HTTPS origin.
    server = TLSServer((value["bind_ip"], port), HTTPSBrowserHandler, ctx)
    server.daemon_threads = True
    server.app, server.authority, server.origin = app, authority, origin
    server.request_budget = RequestBudget()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="Exact https://host[:port], without a path")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--tls-policy", type=Path, required=True)
    parser.add_argument("--tls-policy-sha256", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--assets-root", type=Path, required=True)
    parser.add_argument("--assets-manifest", type=Path, required=True)
    parser.add_argument("--assets-sha256", required=True)
    parser.add_argument("--allow-reviewed-blob-workers", action="store_true")
    args = parser.parse_args()
    profile = decode(pinned_json(args.profile, args.profile_sha256, 8192))
    manifest = pinned_json(args.assets_manifest, args.assets_sha256, 1024 * 1024)
    app = BrowserGateway(profile, assets(args.assets_root, manifest, args.assets_sha256),
                         allow_blob_workers=args.allow_reviewed_blob_workers)
    try:
        with listener(args.origin, args.port, app, args.certificate, args.private_key,
                      args.tls_policy, args.tls_policy_sha256) as server:
            print(f"Browser HTTPS ingress: {server.origin}/", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    finally:
        app.close()


if __name__ == "__main__":
    main()
