"""Runs the devnet explorer suites under the repository check.

The tests of the explorer feed service, the puller and the port helper live
beside them in tools/devnet_explorer and are named test_*.py, so
`python3 -B -m unittest discover -s tools -p '*_test.py'` does not find them.
This module hands them to that run. They use the loopback interface and
temporary directories only.
"""
import importlib
import os
import sys
import unittest

SUITES = ("test_explorer_feed_v0", "test_explorer_pull_v0", "test_rpc_env")


def load_tests(loader, standard_tests, pattern):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "devnet_explorer"))
    suite = unittest.TestSuite()
    for name in SUITES:
        suite.addTests(loader.loadTestsFromModule(importlib.import_module(name)))
    return suite
