# coding=utf8
from __future__ import unicode_literals, print_function, division

import unittest
from httpcap import utils


class TestUtils(unittest.TestCase):
    def test_is_request(self):
        self.assertTrue(utils.is_request(b'GET /test'))
        self.assertTrue(utils.is_request(b'POST /test'))

    def test_is_response(self):
        self.assertTrue(utils.is_response(b'HTTP/1.1'))
        self.assertFalse(utils.is_response(b'HTTP1.1'))

    def test_decode_body(self):
        s = u'123456测试'
        b = s.encode('utf8')
        self.assertEqual(s, utils.decode_body(b, 'utf8'))
        self.assertEqual(s, utils.decode_body(b, b'utf8'))


if __name__ == '__main__':
    unittest.main()
