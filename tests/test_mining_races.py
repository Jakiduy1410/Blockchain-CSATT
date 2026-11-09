"""
Backward-compatible entrypoint for mining race tests.
Canonical implementation is now organized in tests.net01_net02_network.test_mining_races.
"""
from tests.net01_net02_network.test_mining_races import *

if __name__ == '__main__':
    import unittest
    unittest.main()
