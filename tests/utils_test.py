from __future__ import unicode_literals, print_function, division

import unittest
from pcapparser import utils


class TestUtils(unittest.TestCase):
    def test_is_request(self):
        self.assertEqual('foo'.upper(), 'FOO')
        self.assertTrue(utils.is_request(b'GET /test'))
        self.assertTrue(utils.is_request(b'POST /test'))

    def test_is_response(self):
        self.assertTrue(utils.is_response(b'HTTP/1.1'))
        self.assertFalse(utils.is_response(b'HTTP1.1'))

if __name__ == '__main__':
    unittest.main()
