from __future__ import unicode_literals, print_function, division

import sys
from ctypes import cdll
from ctypes.util import find_library
from six.moves import queue
import threading

# live cap use libpcap.
import six

from pcappy_port import open_offline, open_live


def has_pcap():
    if sys.platform == 'win32':
        libpcap = cdll.LoadLibrary(find_library('wpcap.dll'))
    else:
        libpcap = cdll.LoadLibrary(find_library('pcap'))
    return libpcap is not None


def open_file(file_name, filter_exp='', call_back=lambda d, hdr, data: None):
    if isinstance(file_name, six.text_type):
        file_name = file_name.encode('utf8')
    if isinstance(filter_exp, six.text_type):
        filter_exp = filter_exp.encode('utf8')
    # Open the file
    p = open_offline(file_name)
    _run_capture(p, filter_exp, call_back)


def open_device(device, filter_exp='', call_back=lambda d, hdr, data: None):
    if isinstance(device, six.text_type):
        device = device.encode('utf8')
    if isinstance(filter_exp, six.text_type):
        filter_exp = filter_exp.encode('utf8')

    p = open_live(device, snaplen=65536, to_ms=0)
    _run_capture(p, filter_exp, call_back)


def _run_capture(p, filter_exp, call_back):
    """
    :type p: pcappy_port.PcapPyAlive
    """
    datalink = p.datalink
    if filter_exp:
        p.filter = filter_exp

    # Parameters are count, callback, user params
    p.loop(-1, call_back, datalink)


def libpcap_produce(device=None, filename=None, filter_exp=''):
    """
    call_back to generator use queue
    """
    q = queue.Queue()  # fmin produces, the generator consumes
    job_done = object()  # signals the processing is done

    # Producer
    def convert(link_type, header, data):
        sec = header['ts']['tv_sec']
        # Todo usec = header['ts']['tv_usec'] produce negetive value
        q.put((link_type, sec * 1000, data))

    def task():
        try:
            if device is not None:
                open_device(device, filter_exp=filter_exp, call_back=convert)
            elif filename is not None:
                open_file(filename, filter_exp=filter_exp, call_back=convert)
            q.put(job_done)
        except:
            import traceback
            traceback.print_exc()
            sys.exit(-1)

    t = threading.Thread(target=task, name="pcap-thread")
    t.setDaemon(True)
    t.start()

    # Consumer
    while True:
        next_item = q.get()
        if next_item is job_done:
            break
        yield next_item
