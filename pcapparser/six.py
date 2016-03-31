from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'

# deal with python2 and python2 compatibility

import sys

# check python version
major_version, minor_version, = sys.version_info[:2]

is_python2 = major_version == 2

unquote = None
if is_python2:
    import urllib

    unquote = urllib.unquote
else:
    import urllib.parse

    unquote = urllib.parse.unquote


def ensure_unicode(param):
    return param.decode('utf-8') if type(param) == type(b'') else param


def bytes_index(data, idx):
    if is_python2:
        return ord(data[idx])
    else:
        return data[idx]
