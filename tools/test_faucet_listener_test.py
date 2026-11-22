"""The shared listener bound on real loopback sockets; no faucet or wallet data."""
from http.server import BaseHTTPRequestHandler
import socket
import threading
import unittest

from test_faucet import BoundedServer

BOUND = 32


class ListenerBound(unittest.TestCase):
    def test_bound_connections_are_served_together_and_the_next_one_is_closed(self):
        release, entered, lock = threading.Event(), threading.Semaphore(0), threading.Lock()
        active = [0, 0]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                with lock:
                    active[0] += 1
                    active[1] = max(active)
                entered.release()
                release.wait(20)
                with lock:
                    active[0] -= 1
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        server = BoundedServer(("127.0.0.1", 0), Handler)
        self.assertEqual((server.slots._value, server.request_queue_size), (BOUND, 32))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        clients = []
        try:
            for _ in range(BOUND):
                client = socket.create_connection(server.server_address, timeout=10)
                client.sendall(b"GET / HTTP/1.0\r\n\r\n")
                clients.append(client)
            for _ in range(BOUND):
                self.assertTrue(entered.acquire(timeout=10))
            self.assertEqual(active[1], BOUND)
            extra = socket.create_connection(server.server_address, timeout=10)
            extra.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try:
                refused = extra.recv(1) == b""
            except ConnectionError:
                refused = True
            extra.close()
            self.assertTrue(refused)  # closed without a response, never queued
            self.assertFalse(entered.acquire(timeout=0.2))
            release.set()
            for client in clients:
                self.assertTrue(client.recv(4096).startswith(b"HTTP/1.0 200"))
            # Every slot is returned once its request ends.
            deadline = threading.Event()
            for _ in range(100):
                if server.slots._value == BOUND:
                    break
                deadline.wait(0.05)
            self.assertEqual(server.slots._value, BOUND)
        finally:
            release.set()
            for client in clients:
                client.close()
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == "__main__":
    unittest.main()
