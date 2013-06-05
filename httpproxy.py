#coding=utf8
# from https://code.google.com/p/python-proxy/source/browse/trunk/PythonProxy.py
__author__ = "dongliu"

import sys
import socket
import select
import threading
from httpparser import (HttpDataReader, read_request, read_response)

_BUFLEN = 8192
_VERSION = 'Python Proxy/0.1.0 Draft 1'
_HTTPVER = 'HTTP/1.1'
_TIMEOUT = 20
_READ_TIMEOUT = 3


REQUEST = 0
RESPONSE = 1


class Seg(object):
    def __init__(self, datatype, data):
        self.datatype = datatype
        self.data = data


class OutputWrapper(object):
    def __init__(self, clientsocket, targetsocket, remains=None):
        self.clientsocket = clientsocket
        self.targetsocket = targetsocket
        self.segs = []
        if remains:
            self.segs.append(Seg(REQUEST, remains))
            self.targetsocket.send(remains)

    def run(self):
        sockets = [self.clientsocket, self.targetsocket]
        count = 0
        while True:
            count += 1
            (recv, _, error) = select.select(sockets, [], sockets, _READ_TIMEOUT)
            if error:
                break
            if not recv:
                continue

            for in_ in recv:
                data = in_.recv(_BUFLEN)
                out = (in_ is self.clientsocket) and self.targetsocket or self.clientsocket
                datatype = (in_ is self.clientsocket) and REQUEST or RESPONSE
                if data:
                    out.send(data)
                    self.segs.append(Seg(datatype, data))
                    count = 0

            if count == _TIMEOUT:
                break

    def output(self, level):
        cur_datatype = self.segs[0].datatype
        cur_data = []
        for seg in self.segs:
            if seg.datatype == cur_datatype:
                cur_data.append(seg.data)
                continue

            reader = HttpDataReader(''.join(cur_data))
            if cur_datatype == REQUEST:
                read_request(reader, level)
            else:
                read_response(reader, level)
            cur_datatype = seg.datatype

        reader = HttpDataReader(''.join(cur_data))
        if cur_datatype == REQUEST:
            read_request(reader, level)
        else:
            read_response(reader, level)

        del cur_data[:]
        self.segs = None


class ConnectionHandler(object):
    def __init__(self, clientsocket):
        self.clientsocket = clientsocket
        self.clientbuffer = ''

    def run(self):
        while True:
            self.clientbuffer += self.clientsocket.recv(_BUFLEN)
            end = self.clientbuffer.find('\n')
            if end != -1:
                break
        self.method, self.path, self.protocol = (self.clientbuffer[:end + 1]).split()
        self.clientbuffer = self.clientbuffer[end + 1:]

        if self.method == 'CONNECT':
            self.method_CONNECT()
        elif self.method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE'):
            self.method_others()
        self.clientsocket.close()
        self.targetsocket.close()

    def method_CONNECT(self):
        """it is usually for https proxy"""
        self._connect_target(self.path)
        self.clientsocket.send('%s 200 Connection established\nProxy-agent: %s\n\n' % (_HTTPVER, _VERSION))
        self.clientbuffer = ''
        self._read_write()

    def method_others(self):
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]
        path = self.path[i:]
        self._connect_target(host)
        self.clientbuffer = '%s %s %s\n%s' % (self.method, path, self.protocol, self.clientbuffer)
        self._read_write()

    def _connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = 80
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
        self.targetsocket = socket.socket(soc_family)
        self.targetsocket.connect(address)

    def _read_write(self):
        wrapper = OutputWrapper(self.clientsocket, self.targetsocket, self.clientbuffer)
        self.clientbuffer = ''
        wrapper.run()
        # parser and output http datas.
        try:
            wrapper.output(2)
        except Exception as e:
            print e


def _worker(workersocket, clientip, clientport):
    handler = ConnectionHandler(workersocket)
    handler.run()


def start_server(host='0.0.0.0', port=8000, IPv6=False):
    ipver = IPv6 and socket.AF_INET6 or socket.AF_INET
    serversocket = socket.socket(ipver)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        serversocket.bind((host, port))
    except Exception as e:
        print e
        sys.exit(-1)
    print "Proxy start on %s:%d." % (host, port)
    serversocket.listen(0)

    while True:
        workersocket, client = serversocket.accept()
        (clientip, clientport) = client
        workerthread = threading.Thread(target=_worker, args=(workersocket, clientip, clientport))
        workerthread.start()

if __name__ == '__main__':
    start_server()