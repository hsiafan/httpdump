from __future__ import unicode_literals, print_function, division

# wrap libpcap using ctypes
import ctypes
from ctypes import cdll
from ctypes.util import find_library
import sys


def find_libpcap():
    if sys.platform == 'win32':
        return cdll.LoadLibrary(find_library('wpcap.dll'))
    else:
        return cdll.LoadLibrary(find_library('pcap'))


# find dynamic libpcap lib
_pcap = find_libpcap()


def has_libpcap():
    """If has pcap lib"""
    return _pcap is not None


pcap_lookupdev = _pcap.pcap_lookupdev
pcap_lookupdev.argtypes = [ctypes.c_char_p]
pcap_lookupdev.restype = ctypes.c_char_p


pcap_open_live = _pcap.pcap_open_live
pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
pcap_open_live.restype = pcap_t_ptr