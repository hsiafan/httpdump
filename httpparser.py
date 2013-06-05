#coding=utf-8
__author__ = 'dongliu'

import textutils
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
    if textutils.ishttprequest(line):
        headers = HttpRequestHeader()
        items = line.split(' ')
        if len(items) == 3:
            headers.method = items[0]
            headers.uri = items[1]
    elif textutils.ishttpresponse(line):
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

        key, value = textutils.parse_http_header(line)
        if key is None:
            # incorrect headers.
            continue

        header_dict[key.lower()] = value

    if "content-length" in header_dict:
        headers.content_len = int(header_dict["content-length"])
    if 'chunked' in header_dict["transfer-encoding"]:
        headers.chunked = True
    headers.content_type = header_dict['content-type']
    headers.gzip = ('gzip' in header_dict["content-encoding"])
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


def read_request(httpDataReader, level, encoding=''):
    """
    read and output one http request.
    """

    headers = read_http_headers(httpDataReader, level)
    
    # print request info
    if level == 0:
        if not headers.host.startswith('http://'):
            request = headers.method + ' http://' + headers.host + headers.uri
        else:
            request = headers.method + ' ' + headers.uri
        print request

    output_body = False
    if level >= 3 or level >= 2 and 'www-form-urlencoded' in headers.content_type:
        output_body = True

    content = ''
    # deal with body
    if not headers.chunked:
        if output_body:
            content = httpDataReader.read(headers.content_len)
        else:
            httpDataReader.skip(headers.content_len)
    else:
        content = read_chunked_body(httpDataReader)

    if not headers.gzip:
        # if is gzip by content magic header
        # someone missed the content-encoding header
        headers.gzip = textutils.isgzip(content)

    # if it is form url encode
    if output_body:
        if headers.gzip:
            content = textutils.ungzip(content)
        if content is not None:
            print content
        print ''


def read_response(httpDataReader, level, encoding=''):
    """
    read and output one http response
    """
    headers = read_http_headers(httpDataReader, level)

    # read body
    mime, charset = textutils.parse_content_type(headers.content_type)
    if len(encoding) > 0 and charset == '':
        charset = encoding

    output_body = False
    if level >= 3 or level >= 2 and textutils.istextbody(mime):
        output_body = True

    content = ''
    # deal with body
    if not headers.chunked:
        if headers.content_len == 0:
            if headers.connectionclose:
                # we can't get content length, so asume it till the end of data.
                headers.content_len = httpDataReader.remains()
            else:
                #TODO: we can't get content length, and is not a chunked body.
                pass
        if output_body:
            content = httpDataReader.read(headers.content_len)
    else:
        content = read_chunked_body(httpDataReader)

    if output_body:
        if headers.gzip:
            content = textutils.ungzip(content)
        content = textutils.decode_body(content, charset)
        if content is not None:
            if not textutils.print_json(content):
                print content