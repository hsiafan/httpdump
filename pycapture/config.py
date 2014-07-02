#coding=utf-8
from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'


class OutputLevel(object):
    ONLY_URL = 0
    HEADER = 1
    TEXT_BODY = 2
    ALL_BODY = 3


class ParseConfig(object):
    """ global settings """

    def __init__(self):
        self.level = OutputLevel.ONLY_URL
        self.pretty = False
        self.encoding = None