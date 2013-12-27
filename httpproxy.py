#coding=utf8
from Queue import Queue
import config

__author__ = "dongliu"

import sys
import argparse
import socket
import select
import threading
import signal
from StringIO import StringIO
from httpparser import HttpType, parse_http_data
from config import parse_config

_BUF_SIZE = 8192
_MAX_READ_RETRY_COUNT = 20
_READ_TIMEOUT = 3


class ConnectionHandler(object):
    """handle one connection from client"""
    def __init__(self, clientsocket, queue):
        self.clientsocket = clientsocket
        self.first_data = ''
        self.httptype = HttpType.REQUEST
        self.queue = queue
        self.remote_host = None

    def init_connect(self):
        while True:
            self.first_data += self.clientsocket.recv(_BUF_SIZE)
            end = self.first_data.find('\n')
            if end != -1:
                break
        self.method, self.path, self.protocol = self.first_data[:end + 1].split()

        if self.method == 'CONNECT':
            self.first_data = self.first_data[end + 1:]
            self.queue.put((HttpType.REQUEST, self.first_data[end + 1:]))
            self._method_CONNECT()
        elif self.method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE'):
            self.queue.put((HttpType.REQUEST, self.first_data))
            self._method_others()

    def close(self):
        self.queue.put((None, None))
        self.clientsocket.close()
        self.targetsocket.close()

    def _method_CONNECT(self):
        """for http proxy connect method. it is usually for https proxy"""
        self._connect_target(self.path)
        self.clientsocket.send('HTTP/1.1 200 Connection established\nProxy-agent: Python Proxy\n\n')

    def _method_others(self):
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]
        path = self.path[i:]
        self._connect_target(host)

    def _connect_target(self, host):
        i = host.find(':')
        if i != -1:
            portstr = host[i + 1:]
            if portstr:
                port = int(host[i + 1:])
            else:
                port = 80
            host = host[:i]
        else:
            port = 80
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
        self.remote_host = address
        self.targetsocket = socket.socket(soc_family)
        self.targetsocket.connect(address)
        self.targetsocket.send(self.first_data)

    def proxy_data(self):
        """run the proxy"""
        sockets = [self.clientsocket, self.targetsocket]
        empty_read_count = 0
        while True:
            empty_read_count += 1
            (recv, _, error) = select.select(sockets, [], sockets, _READ_TIMEOUT)
            if error:
                # connection closed, or error occured.
                break

            if not recv:
                continue

            for in_ in recv:
                data = in_.recv(_BUF_SIZE)
                out = (in_ is self.clientsocket) and self.targetsocket or self.clientsocket
                httptype = (in_ is self.clientsocket) and HttpType.REQUEST or HttpType.RESPONSE
                if data:
                    out.send(data)
                    empty_read_count = 0
                    self.queue.put((httptype, data))

            if empty_read_count == _MAX_READ_RETRY_COUNT:
                break


def _worker(workersocket, clientip, clientport, outputfile):
    try:
        buf = StringIO()
        queue = Queue()
        handler = ConnectionHandler(workersocket, queue)
        handler.init_connect()
        parser_worker = parse_http_data(queue, buf, (clientip, clientport), handler.remote_host, parse_config)
        handler.proxy_data()
        handler.close()
        parser_worker.join()
        outputfile.write(buf.getvalue())
        outputfile.flush()
    except Exception:
        import traceback
        traceback.print_exc()


def start_server(host='0.0.0.0', port=8000, IPv6=False, output=None):
    """start proxy server."""
    ipver = IPv6 and socket.AF_INET6 or socket.AF_INET
    serversocket = socket.socket(ipver)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        serversocket.bind((host, port))
    except Exception as e:
        print e
        sys.exit(-1)
    print "Proxy start on %s:%d" % (host, port)
    serversocket.listen(0)

    outputfile = output and open(output, "w+") or sys.stdout

    def clean():
        """do clean job after process terminated"""
        try:
            serversocket.close()
        except:
            pass
        try:
            outputfile.close()
        except:
            pass

    # when press Ctrl+C, stop the proxy.
    def signal_handler(signal, frame):
        print '\nStopping proxy...'
        clean()
        # TODO:stop all threads and close all files and sockets.
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            workersocket, client = serversocket.accept()
            (clientip, clientport) = client
            workerthread = threading.Thread(target=_worker, args=(workersocket, clientip, clientport, outputfile))
            workerthread.setDaemon(False)
            workerthread.start()
    finally:
        clean()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen", help="the IP of the interface which the proxy listend on")
    parser.add_argument("-p", "--port", type=int, help="the port of the interface which the proxy listend on")
    parser.add_argument("-6", "--ipv6", help="use ipv6", action="store_true")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)", action="count")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    parser.add_argument("-b", "--beauty", help="output json in a pretty way.", action="store_true")


    args = parser.parse_args()
    setting = {"IPv6": args.ipv6}
    if args.listen:
        setting["host"] = args.listen
    if args.port:
        setting["port"] = args.port
    if args.output:
        setting["output"] = args.output

    if args.verbosity:
        parse_config.level = args.verbosity
    if args.encoding:
        parse_config.encoding = args.encoding
    parse_config.pretty = args.beauty

    start_server(**setting)