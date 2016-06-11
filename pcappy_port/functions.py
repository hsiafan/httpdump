#!/usr/bin/env python

from ctypes.util import find_library

from pcappy_port.types import *

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PcapPy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

_pcap = cdll.LoadLibrary(find_library('pcap'))

pcap_functions = globals()


def load_func(name, restype=None, argtypes=[]):
    try:
        pcap_function = getattr(_pcap, name)
        pcap_function.argtypes = argtypes
        pcap_function.restype = restype
        return pcap_function
    except AttributeError:
        def _pcap_unsupported(*args, **kwargs):
            raise NotImplementedError('Libpcap not compiled with %s support.' % repr(name))

        return _pcap_unsupported


pcap_lookupdev = load_func('pcap_lookupdev', c_char_p, [c_char_p])
pcap_lookupnet = load_func('pcap_lookupnet', c_int, [c_char_p, c_uint32_p, c_uint32_p, c_char_p])
pcap_create = load_func('pcap_create', pcap_t_ptr, [c_char_p, c_char_p])
pcap_set_snaplen = load_func('pcap_set_snaplen', c_int, [pcap_t_ptr, c_int])
pcap_set_promisc = load_func('pcap_set_promisc', c_int, [pcap_t_ptr, c_int])
pcap_can_set_rfmon = load_func('pcap_can_set_rfmon', c_int, [pcap_t_ptr])
pcap_set_rfmon = load_func('pcap_set_rfmon', c_int, [pcap_t_ptr, c_int])
pcap_set_timeout = load_func('pcap_set_timeout', c_int, [pcap_t_ptr, c_int])
pcap_set_buffer_size = load_func('pcap_set_buffer_size', c_int, [pcap_t_ptr, c_int])
pcap_activate = load_func('pcap_activate', c_int, [pcap_t_ptr])
pcap_apple_set_exthdr = load_func('pcap_apple_set_exthdr', c_int, [pcap_t_ptr, c_int])  # Todo
pcap_open_live = load_func('pcap_open_live', pcap_t_ptr, [c_char_p, c_int, c_int, c_int, c_char_p])
pcap_open_dead = load_func('pcap_open_dead', pcap_t_ptr, [c_int, c_int])
pcap_open_offline = load_func('pcap_open_offline', pcap_t_ptr, [c_char_p, c_char_p])
pcap_hopen_offline = load_func('pcap_hopen_offline', pcap_t_ptr, [c_int_p, c_char_p])  # Todo
# pcap_fopen_offline = load_func('pcap_fopen_offline', pcap_t_ptr, [FILE_ptr, c_char_p])
pcap_close = load_func('pcap_close', argtypes=[pcap_t_ptr])
pcap_loop = load_func('pcap_loop', c_int, [pcap_t_ptr, c_int, pcap_handler, py_object_p])
pcap_dispatch = load_func('pcap_dispatch', c_int, [pcap_t_ptr, c_int, pcap_handler, py_object_p])
pcap_next = load_func('pcap_next', c_ubyte_p, [pcap_t_ptr, pcap_pkthdr_ptr])
pcap_next_ex = load_func('pcap_next_ex', c_int, [pcap_t_ptr, POINTER(pcap_pkthdr_ptr), POINTER(c_ubyte_p)])
pcap_breakloop = load_func('pcap_breakloop', argtypes=[pcap_t_ptr])
pcap_stats = load_func('pcap_stats', c_int, [pcap_t_ptr, pcap_stat_ptr])
pcap_setfilter = load_func('pcap_setfilter', c_int, [pcap_t_ptr, bpf_program_ptr])
pcap_setdirection = load_func('pcap_setdirection', c_int, [pcap_t_ptr, c_int])
pcap_getnonblock = load_func('pcap_getnonblock', c_int, [pcap_t_ptr, c_char_p])
pcap_setnonblock = load_func('pcap_setnonblock', c_int, [pcap_t_ptr, c_int, c_char_p])
pcap_inject = load_func('pcap_inject', c_int, [pcap_t_ptr, c_char_p, c_size_t])
pcap_sendpacket = load_func('pcap_sendpacket', c_int, [pcap_t_ptr, c_char_p, c_int])
pcap_statustostr = load_func('pcap_statustostr', c_char_p, [c_int])
pcap_strerror = load_func('pcap_strerror', c_char_p, [c_int])
pcap_geterr = load_func('pcap_geterr', c_char_p, [pcap_t_ptr])
pcap_perror = load_func('pcap_perror', argtypes=[pcap_t_ptr, c_char_p])
pcap_compile = load_func('pcap_compile', c_int, [pcap_t_ptr, bpf_program_ptr, c_char_p, c_int, c_uint32])
pcap_compile_nopcap = load_func('pcap_compile_nopcap', c_int, [c_int, c_int, bpf_program_ptr, c_char_p, c_int, c_uint32])
pcap_freecode = load_func('pcap_freecode', argtypes=[bpf_program_ptr])
pcap_offline_filter = load_func('pcap_offline_filter', c_int, [bpf_program_ptr, pcap_pkthdr_ptr, c_char_p])  # Todo
pcap_datalink = load_func('pcap_datalink', c_int, [pcap_t_ptr])
pcap_datalink_ext = load_func('pcap_datalink_ext', c_int, [pcap_t_ptr])
pcap_list_datalinks = load_func('pcap_list_datalinks', c_int, [pcap_t_ptr, POINTER(c_int_p)])
pcap_set_datalink = load_func('pcap_set_datalink', c_int, [pcap_t_ptr, c_int])
pcap_free_datalinks = load_func('pcap_free_datalinks', argtypes=[c_int_p])
pcap_datalink_name_to_val = load_func('pcap_datalink_name_to_val', c_int, [c_char_p])
pcap_datalink_val_to_name = load_func('pcap_datalink_val_to_name', c_char_p, [c_int])
pcap_datalink_val_to_description = load_func('pcap_datalink_val_to_description', c_char_p, [c_int])
pcap_snapshot = load_func('pcap_snapshot', c_int, [pcap_t_ptr])
pcap_is_swapped = load_func('pcap_is_swapped', c_int, [pcap_t_ptr])
pcap_major_version = load_func('pcap_major_version', c_int, [pcap_t_ptr])
pcap_minor_version = load_func('pcap_minor_version', c_int, [pcap_t_ptr])
# pcap_file =  load_func('pcap_file', FILE_ptr, [pcap_t_ptr])
pcap_fileno = load_func('pcap_fileno', c_int, [pcap_t_ptr])
pcap_dump_open = load_func('pcap_dump_open', pcap_dumper_t_ptr, [pcap_t_ptr, c_char_p])
# pcap_dump_fopen = load_func('pcap_dump_fopen', pcap_dumper_t_ptr, [pcap_t_ptr, FILE_ptr])
# pcap_dump_file = load_func('pcap_dump_file', FILE_ptr, [pcap_dumper_t_ptr])
pcap_dump_ftell = load_func('pcap_dump_ftell', c_long, [pcap_dumper_t_ptr])
pcap_dump_flush = load_func('pcap_dump_flush', c_int, [pcap_dumper_t_ptr])
pcap_dump_close = load_func('pcap_dump_close', argtypes=[pcap_dumper_t_ptr])
pcap_dump = load_func('pcap_dump', argtypes=[pcap_dumper_t_ptr, pcap_pkthdr_ptr, c_char_p])
pcap_ng_dump_open = load_func('pcap_ng_dump_open', pcap_dumper_t_ptr, [pcap_t_ptr, c_char_p])
# pcap_ng_dump_fopen = load_func('pcap_ng_dump_fopen', pcap_dumper_t_ptr, [pcap_t_ptr, FILE_ptr])
pcap_ng_dump = load_func('pcap_ng_dump', argtypes=[pcap_dumper_t_ptr, pcap_pkthdr_ptr, c_char_p])
pcap_ng_dump_close = load_func('pcap_ng_dump_close', argtypes=[pcap_dumper_t_ptr])
pcap_findalldevs = load_func('pcap_findalldevs', c_int, [POINTER(pcap_if_t_ptr), c_char_p])
pcap_findalldevs_ex = load_func('pcap_findalldevs_ex', c_int,
          [c_char_p, pcap_rmtauth_ptr, POINTER(pcap_if_t_ptr), c_char_p])
pcap_freealldevs = load_func('pcap_freealldevs', argtypes=[pcap_if_t_ptr])
pcap_lib_version = load_func('pcap_lib_version', c_char_p)
bpf_filter = load_func('bpf_filter', c_uint, [bpf_insn_ptr, c_char_p, c_uint, c_uint])  # Todo
bpf_validate = load_func('bpf_validate', c_int, [bpf_insn_ptr, c_int])  # Todo
bpf_image = load_func('bpf_image', c_char_p, [bpf_insn_ptr, c_int])  # Todo
bpf_dump = load_func('bpf_dump', argtypes=[bpf_program_ptr, c_int])  # Todo
pcap_setbuff = load_func('pcap_setbuff', c_int, [pcap_t_ptr, c_int])  # Todo
pcap_setmode = load_func('pcap_setmode', c_int, [pcap_t_ptr, c_int])  # Todo
pcap_setmintocopy = load_func('pcap_setmintocopy', c_int, [pcap_t_ptr, c_int])  # Todo
pcap_stats_ex = load_func('pcap_stats_ex', c_int, [pcap_t_ptr, pcap_stat_ex_ptr])  # Todo
pcap_set_wait = load_func('pcap_set_wait', [pcap_t_ptr, yield_, c_int])  # Todo
pcap_mac_packets = load_func('pcap_mac_packets', c_ulong)  # Todo
pcap_get_selectable_fd = load_func('pcap_get_selectable_fd', c_int, [pcap_t_ptr])
