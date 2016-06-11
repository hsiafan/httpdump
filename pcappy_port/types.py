#!/usr/bin/env python
import ctypes
from ctypes import *
from sys import platform

from pcappy_port.constants import PCAP_ERRBUF_SIZE

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

c_uint32_p = POINTER(c_uint32)

c_int_p = POINTER(c_int)

c_ubyte_p = POINTER(c_ubyte)

py_object_p = POINTER(py_object)


class pcap_t(Structure):
    pass


class pcap_stat(Structure):
    if platform == 'nt':
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint),
            ('bs_capt', c_uint)
        ]
    else:
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint)
        ]


pcap_stat_ptr = POINTER(pcap_stat)


class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long)
    ]


class pcap_pkthdr(Structure):
    if platform == 'darwin':
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32),
            ('comments', (c_char * 256))
        ]
    else:
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32)
        ]


pcap_pkthdr_ptr = POINTER(pcap_pkthdr)


class pcap_sf(Structure):
    _fields = [
        ('rfile', c_void_p),
        ('swapped', c_int),
        ('hdrsize', c_int),
        ('version_major', c_int),
        ('version_minor', c_int),
        ('base', c_ubyte_p)
    ]


class pcap_md(Structure):
    if platform.startswith('linux'):
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long),
            ('sock_packet', c_int),
            ('readlen', c_int),
            ('timeout', c_int),
            ('clear_promisc', c_int),
            ('cooked', c_int),
            ('lo_ifindex', c_int),
            ('*device', c_char),
            ('*next', pcap_t),
        ]
    else:
        _fields = [
            ('stat', pcap_stat),
            ('use_bpf', c_int),
            ('TotPkts', c_ulong),
            ('TotAccepted', c_ulong),
            ('TotDrops', c_ulong),
            ('TotMissed', c_long),
            ('OrigMissed', c_long)
        ]


class bpf_insn(Structure):
    _fields_ = [
        ('code', c_ushort),
        ('jt', c_ubyte),
        ('jf', c_ubyte),
        ('k', c_int)
    ]


bpf_insn_ptr = POINTER(bpf_insn)


class bpf_program(Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', POINTER(bpf_insn))
    ]


bpf_program_ptr = POINTER(bpf_program)


class sockaddr_in(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sin_len', c_ubyte),
            ('sin_family', c_ubyte),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]
    else:
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]


class sockaddr_in6(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sin6_len', c_ubyte),
            ('sin6_family', c_ubyte),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]
    else:
        _fields_ = [
            ('sin6_family', c_ushort),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]


class sockaddr_sa(Structure):
    _pack_ = 1
    if platform == 'darwin':
        _fields_ = [
            ('sa_len', c_ubyte),
            ('sa_family', c_ubyte),
            ('sa_data', c_char * 14)
        ]
    else:
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data', c_char * 14)
        ]


class sockaddr_dl(Structure):
    _pack_ = 1
    _fields_ = (
        ('sdl_len', c_ubyte),
        ('sdl_family', c_ubyte),
        ('sdl_index', c_ushort),
        ('sdl_type', c_ubyte),
        ('sdl_nlen', c_ubyte),
        ('sdl_alen', c_ubyte),
        ('sdl_slen', c_ubyte),
        ('sdl_data', (c_ubyte * 12)),
    )


class sockaddr_ll(Structure):
    _pack_ = 1
    _fields_ = (
        ('sll_family', c_ushort),
        ('sll_protocol', c_ushort),
        ('sll_ifindex', c_int),
        ('sll_hatype', c_ushort),
        ('sll_pkttype', c_ubyte),
        ('sll_halen', c_ubyte),
        ('sll_data', (c_ubyte * 8)),
    )


class sockaddr(Union):
    _pack_ = 1
    _fields_ = [
        ('sa', sockaddr_sa),
        ('sin', sockaddr_in),
        ('sin6', sockaddr_in6),
        ('sdl', sockaddr_dl),
        ('sll', sockaddr_ll),
    ]


sockaddr_ptr = POINTER(sockaddr)


class pcap_addr_t(Structure):
    _pack_ = 1


pcap_addr_t_ptr = POINTER(pcap_addr_t)

pcap_addr_t._fields_ = [
    ('next', pcap_addr_t_ptr),
    ('addr', sockaddr_ptr),
    ('netmask', sockaddr_ptr),
    ('broadaddr', sockaddr_ptr),
    ('dstaddr', sockaddr_ptr)
]


class pcap_if_t(Structure):
    _pack_ = 1


pcap_if_t_ptr = POINTER(pcap_if_t)

pcap_if_t._fields_ = [
    ('next', pcap_if_t_ptr),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', pcap_addr_t_ptr),
    ('flags', c_uint)
]

pcap_t._fields_ = [
    ('fd', c_int),
    ('snapshot', c_int),
    ('linktype', c_int),
    ('tzoff', c_int),
    ('offset', c_int),
    ('pcap_sf', pcap_sf),
    ('pcap_md', pcap_md),
    ('bufsize', c_int),
    ('buffer', c_ubyte_p),
    ('bp', c_ubyte_p),
    ('cc', c_int),
    ('pkt', c_char_p),
    ('fcode', bpf_program),
    ('errbuf', (c_char * PCAP_ERRBUF_SIZE))
]

pcap_t_ptr = POINTER(pcap_t)


class pcap_rmtauth(Structure):
    _fields_ = [
        ('type', c_int),
        ('username', c_char_p),
        ('password', c_char_p)
    ]


pcap_rmtauth_ptr = POINTER(pcap_rmtauth)


class pcap_dumper_t(Structure):
    pass


pcap_dumper_t_ptr = POINTER(pcap_dumper_t)


class pcap_stat_ex(Structure):
    _fields_ = [
        ('rx_packets', c_ulong),
        ('tx_packets', c_ulong),
        ('rx_bytes', c_ulong),
        ('tx_bytes', c_ulong),
        ('rx_errors', c_ulong),
        ('tx_errors', c_ulong),
        ('rx_dropped', c_ulong),
        ('tx_dropped', c_ulong),
        ('multicast', c_ulong),
        ('collisions', c_ulong),
        ('rx_length_errors', c_ulong),
        ('rx_over_errors', c_ulong),
        ('rx_crc_errors', c_ulong),
        ('rx_frame_errors', c_ulong),
        ('rx_fifo_errors', c_ulong),
        ('rx_missed_errors', c_ulong),
        ('tx_aborted_errors', c_ulong),
        ('tx_carrier_errors', c_ulong),
        ('tx_fifo_errors', c_ulong),
        ('tx_heartbeat_errors', c_ulong),
        ('tx_window_errors', c_ulong)
    ]


pcap_stat_ex_ptr = POINTER(pcap_stat_ex)

pcap_handler = CFUNCTYPE(None, POINTER(py_object), pcap_pkthdr_ptr, c_ubyte_p)

yield_ = CFUNCTYPE(None)


# Ripped from http://svn.python.org/projects/ctypes/trunk/ctypeslib/ctypeslib/contrib/pythonhdr.py
# class FILE(Structure):
#     pass
#
#
# FILE_ptr = POINTER(FILE)
# CLOSEFUNC = CFUNCTYPE(c_int, FILE_ptr)
#
# PyFile_FromFile = pythonapi.PyFile_FromFile
# PyFile_FromFile.restype = py_object
# PyFile_FromFile.argtypes = [
#     FILE_ptr,
#     c_char_p,
#     c_char_p,
#     c_void_p
# ]
#
# PyFile_AsFile = pythonapi.PyFile_AsFile
# PyFile_AsFile.restype = FILE_ptr
# PyFile_AsFile.argtypes = [py_object]
