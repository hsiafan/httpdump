#coding=utf-8
__author__ = 'dongliu'

import util
from collections import defaultdict


class HttpDataReader(object):
    """
    wrap http data for read.
    """
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.length = len(self.data)

    def readline(self):
        """read line from input data"""
        if self.pos >= self.length:
            return None
        end = self.data.find('\n', self.pos)
        if end < 0:
            end = len(self.data)
        begin = self.pos
        self.pos = end + 1
        return self.data[begin:end]

    def fetchline(self):
        """fetch a line ,but not modify pos"""
        if self.pos >= self.length:
            return None
        end = self.data.find('\n', self.pos)
        if end < 0:
            end = len(self.data)
        return self.data[self.pos:end]

    def read(self, size):
        if self.pos >= self.length:
            return None
        end = self.pos + size
        if end < 0:
            end = len(self.data)
        begin = self.pos
        self.pos = end
        return self.data[begin:end]

    def skip(self, size):
        self.pos = self.pos + size

    def isend(self):
        return self.pos >= self.length

    def remains(self):
        return self.length - self.pos


class HttpRequestHeader(object):
    def __init__(self):
        self.content_len = 0
        self.method = ''
        self.host = ''
        self.uri = ''
        self.transfer_encoding = ''
        self.content_encoding = ''
        self.content_type = ''
        self.gzip = False
        self.chunked = False
        self.host = ''
        self.request = ''


class HttpReponseHeader(object):
    def __init__(self):
        self.content_len = 0
        self.status_code = ''
        self.protocal = ''
        self.transfer_encoding = ''
        self.content_encoding = ''
        self.content_type = ''
        self.gzip = False
        self.chunked = False
        self.host = ''
        self.request = ''
        self.connectionclose = False


def read_http_headers(reader, level):
    """read & parse http headers"""
    line = reader.fetchline()
    if util.ishttprequest(line):
        headers = HttpRequestHeader()
        items = line.split(' ')
        if len(items) == 3:
            headers.method = items[0]
            headers.uri = items[1]
    elif util.ishttpresponse(line):
        headers = HttpReponseHeader()
        items = line.split(' ')
        if len(items) == 3:
            headers.status_code = items[1]
            headers.protocal = items[0]
    else:
        # not httprequest or httpresponse
        return None

    if level >= 1:
        print line
    reader.readline()

    header_dict = defaultdict(str)
    while True:
        line = reader.readline()
        if level >= 1:
            print line

        if line is None or len(line.strip()) == 0:
            break

        key, value = util.parse_http_header(line)
        if key is None:
            # incorrect headers.
            continue

        header_dict[key.lower()] = value

    if "content-length" in header_dict:
        headers.content_len = int(header_dict["content-length"])
    if 'chunked' in header_dict["transfer-encoding"]:
        headers.chunked = True
    headers.content_type = header_dict['content-type']
    headers.gzip = ('gzip' in header_dict["content-length"])
    headers.host = header_dict["host"]
    headers.connectionclose = (header_dict['connection'] == 'close')
    return headers


def read_chunked_body(pacReader, skip=False):
    """
    read chunked body.
    """
    result = []
    while True:
        cline = pacReader.readline()
        if cline is None:
            return None
        chunk_size_end = cline.find(';')
        if chunk_size_end < 0:
            chunk_size_end = len(cline)
        # skip chunk extension
        chunk_size_str = cline[0:chunk_size_end]
        # the last chunk
        if chunk_size_str[0] == '0':
            # chunk footer header
            # todo: handle additional http headers.
            while True:
                cline = pacReader.readline()
                if  cline is None or len(cline.strip()) == 0:
                    break
            return ''.join(result)
        # chunk size
        chunk_size_str = chunk_size_str.strip()
        try:
            chunk_len = int(chunk_size_str, 16)
        except:
            return ''.join(result)

        result.append(pacReader.read(chunk_len))
        if pacReader.isend():
            # skip all
            return ''.join(result)
        # a CRLF to end this chunked response
        pacReader.readline()


def read_request(request_pacs, level, encoding):
    """
    read and output one http request.
    """
    request_pacs.sort(key=lambda x: x.seq)
    #TODO: handle with tcp retransmission
    body = ''.join([p.body for p in request_pacs])
    reader = HttpDataReader(body)
    headers = read_http_headers(reader, level)
    
    # print request info
    if level == 0:
        if not headers.host.startswith('http://'):
            request = headers.method + ' http://' + headers.host + headers.uri
        else:
            request = headers.method + ' ' + headers.uri
        print request

    output_body = False
    if level >= 3:
        output_body = True
    elif level >= 2 and 'www-form-urlencoded' in headers.content_type > 0:
        output_body = True

    content = ''
    # deal with body
    if not headers.chunked:
        if output_body:
            content = reader.read(headers.content_len)
        else:
            reader.skip(headers.content_len)
    else:
        content = read_chunked_body(reader)

    if not headers.gzip:
        # if is gzip by content magic header
        # someone missed the content-encoding header
        headers.gzip = util.isgzip(content)

    if output_body and headers.gzip:
        content = util.ungzip(content)
    # if it is form url encode
    if output_body:
        if content is not None:
            print content
        print ''


def read_response(response_pacs, level, encoding):
    """
    read and output one http response
    """
    response_pacs.sort(key=lambda x: x.seq)
    body = ''.join([p.body for p in response_pacs])
   
    reader = HttpDataReader(body)
    headers = read_http_headers(reader,level)

    # read body
    mime, charset = util.parse_content_type(headers.content_type)
    if len(encoding) > 0 and charset == '':
        charset = encoding

    output_body = False
    if level >= 3:
        output_body = True
    elif level >= 2 and util.istextbody(mime):
        output_body = True

    content = ''
    # deal with body
    if not headers.chunked:
        if headers.content_len == 0:
            if headers.connectionclose:
                # we can't get content length, so asume it till the end of data.
                headers.content_len = reader.remains()
            else:
                #TODO: we can't get content length, and is not a chunked body.
                pass
        if output_body:
            content = reader.read(headers.content_len)
    else:
        content = read_chunked_body(reader)
    if headers.gzip and output_body:
        content = util.ungzip(content)
    if output_body:
        content = util.decode_body(content, charset)
        if not util.print_json(content):
            if content is not None:
                print content


class HttpConn:
    """
    all data having same source/dest ip/port.
    """

    def __init__(self, tcp_pac):
        self.source_ip = tcp_pac.source
        self.source_port = tcp_pac.source_port
        self.dest_ip = tcp_pac.dest
        self.dest_port = tcp_pac.dest_port
        self.pac_list = []
        if len(tcp_pac.body) > 0:
            self.pac_list.append(tcp_pac)
        self.status = 0

    def append(self, tcp_pac):
        if len(tcp_pac.body) == 0:
            return
        if self.status == -1 or self.status == 2:
            # not http conn or conn already closed.
            return
        if tcp_pac.source != self.source_ip:
            tcp_pac.direction = 1

        self.pac_list.append(tcp_pac)

        if self.status == 0:
            if tcp_pac.body != '':
                if util.ishttprequest(tcp_pac.body):
                    self.status = 1
        if tcp_pac.pac_type == -1:
            # end of connection
            if self.status == 1:
                self.status = 2
            else:
                self.status = -2

    def output(self, level, encoding):
        if self.status <= -1:
            return
        elif self.status == 0:
            return
        elif self.status == 1:
            pass
        elif self.status == 2:
            pass
        print self.source_ip, ':', self.source_port, "--- -- - >", self.dest_ip, ':', self.dest_port

        request_pacs = []
        response_pacs = []
        state = 0
        for pac in self.pac_list:
            if len(pac.body) == 0:
                continue
            if state == 0:
                if pac.direction == 1:
                    read_request(request_pacs, level, encoding)
                    state = 1
                    response_pacs.append(pac)
                    del request_pacs[:]
                else:
                    request_pacs.append(pac)
            else:
                if pac.direction == 0:
                    read_response(response_pacs, level, encoding)
                    state = 0
                    request_pacs.append(pac)
                    del response_pacs[:]
                else:
                    response_pacs.append(pac)

        if len(request_pacs) > 0:
            read_request(request_pacs, level, encoding)
        if len(response_pacs) > 0:
            read_response(response_pacs, level, encoding)

        print ''