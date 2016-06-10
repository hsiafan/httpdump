# coding=utf8
from __future__ import unicode_literals, print_function, division

import unittest

from httpcap import tcp_assembly


class TestTcpAssembly(unittest.TestCase):
    def test_seq_compare(self):
        self.assertTrue(tcp_assembly.seq_compare(100, 1) > 0)
        self.assertTrue(tcp_assembly.seq_compare(100, 200) < 0)
        self.assertTrue(tcp_assembly.seq_compare(100, 100) == 0)
        self.assertTrue(tcp_assembly.seq_compare(0xFFFFFFFE, 1) < 0)
        self.assertTrue(tcp_assembly.seq_compare(1, 0xFFFFFFFE) > 0)

if __name__ == '__main__':
    unittest.main()
