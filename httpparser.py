#coding=utf-8
from Queue import Queue
import threading
import StringIO
from config import OutputLevel

__author__ = 'dongliu'

import textutils
from collections import defaultdict


class HttpType(object):
    REQUEST = 0
    RESPONSE = 1


class DataReader(object):
    """ wrap http data for read. """

    def __init__(self, data_generator):
        self.data_generator = data_generator
        self.data = None
        self.finish = False

    def _fetchdata(self):
        try:
            data = self.data_generator.next()
            return data
        except StopIteration:
            self.finish = True
            return None

    def readline(self):
        """read line from input data"""
        if self.finish:
            return None

        buffers = []
        if not self.data:
            self.data = self._fetchdata()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._fetchdata()
                continue

            idx = self.data.find('\n')
            if idx >= 0:
                buffers.append(self.data[0:idx + 1])
                self.data = self.data[idx + 1:]
                break
            if self.data:
                buffers.append(self.data)
            self.data = self._fetchdata()

        if not buffers and self.finish:
            return None
        return ''.join(buffers)

    def fetchline(self):
        """fetch a line, but not modify pos"""
        line = self.readline()
        if line is None:
            return None

        if self.data:
            self.data = line + self.data
        else:
            self.data = line

        # self.finish may be True, mark it as False
        if self.data:
            self.finish = False
        return line

    def read(self, size):
        if self.finish:
            return None

        buffers = []
        read_size = 0
        if not self.data:
            self.data = self._fetchdata()
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._fetchdata()
                continue

            if len(self.data) >= size - read_size:
                buffers.append(self.data[0:size - read_size])
                self.data = self.data[size - read_size:]
                break

            if self.data:
                buffers.append(self.data)
                read_size += len(self.data)
            self.data = self._fetchdata()

        if not buffers and self.finish:
            return None
        return ''.join(buffers)

    def skip(self, size):
        if self.finish:
            return -1

        read_size = 0
        while self.data is not None:
            if len(self.data) == 0:
                self.data = self._fetchdata()
                continue

            if len(self.data) >= size - read_size:
                self.data = self.data[size - read_size:]
                read_size = size
                break

            read_size += len(self.data)
            self.data = self._fetchdata()

        return read_size

    def readall(self):
        if self.finish:
            return None

        buf = []
        if self.data:
            buf.append(self.data)
        while True:
            data = self._fetchdata()
            if data is None:
                break
            if self.data:
                buf.append(data)

        if not buf and self.finish:
            return None
        return ''.join(buf)

    def skipall(self):
        while self._fetchdata() is not None:
            pass


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
        self.expect = ''


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


def read_http_headers(reader, outputfile, level):
    """read & parse http headers"""
    line = reader.fetchline()
    if line is None:
        return line
    line = line.strip()

    if textutils.ishttprequest(line):
        headers = HttpRequestHeader()
        items = line.split(' ')
        if len(items) == 3:
            headers.method = items[0]
            headers.uri = items[1]
        if level == OutputLevel.ONLY_URL:
            outputfile.write(line)
            outputfile.write('\n')
    elif textutils.ishttpresponse(line):
        headers = HttpReponseHeader()
        items = line.split(' ')
        if len(items) == 3:
            headers.status_code = items[1]
            headers.protocal = items[0]
        if level == OutputLevel.ONLY_URL:
            outputfile.write(line)
            outputfile.write('\n')
    else:
        # not httprequest or httpresponse
        return None

    if level >= OutputLevel.HEADER:
        outputfile.write(line)
        outputfile.write('\n')
    reader.readline()

    header_dict = defaultdict(str)
    while True:
        line = reader.readline()
        if line is None:
            break
        line = line.strip()
        if not line:
            break
        if level >= OutputLevel.HEADER:
            outputfile.write(line)
            outputfile.write('\n')

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
    if 'expect' in header_dict:
        headers.expect = header_dict['expect']

    if level >= OutputLevel.HEADER:
        outputfile.write('\n')
    return headers


def read_chunked_body(pacReader, skip=False):
    """ read chunked body """
    result = []
    # read a chunk per loop
    while True:
        # read chunk size line
        cline = pacReader.readline()
        if cline is None:
            # error ocurred.
            if not skip:
                return ''.join(result)
            else:
                return
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
                if cline is None or len(cline.strip()) == 0:
                    break
            if not skip:
                return ''.join(result)
            else:
                return
                # chunk size
        chunk_size_str = chunk_size_str.strip()
        try:
            chunk_len = int(chunk_size_str, 16)
        except:
            return ''.join(result)

        data = pacReader.read(chunk_len)
        if data is None:
            # skip all
            # error ocurred.
            if not skip:
                return ''.join(result)
            else:
                return
        if not skip:
            result.append(data)

        # a CRLF to end this chunked response
        pacReader.readline()


def print_body(content, gzipped, charset, outputfile, form_encoded, pretty):
    if gzipped:
        content = textutils.ungzip(content)
    content = textutils.decode_body(content, charset)
    if content and form_encoded and pretty:
        import urllib

        content = urllib.unquote(content)
    if content:
        if pretty:
            textutils.try_print_json(content, outputfile)
        else:
            outputfile.write(content)
    else:
        outputfile.write("{empty body}")
    outputfile.write('\n\n')


def read_request(reader, outputfile, request_status, parse_config):
    """
    read and output one http request.
    """
    if 'expect' in request_status and not textutils.ishttprequest(reader.fetchline()):
        headers = request_status['expect']
        del request_status['expect']
    else:
        headers = read_http_headers(reader, outputfile, parse_config.level)
        if headers is None or not isinstance(headers, HttpRequestHeader):
            outputfile.write("{Error, cannot parse http request headers.}")
            outputfile.write('\n')
            reader.skipall()
            return
        if headers.expect:
            # assume it is expect:continue-100
            request_status['expect'] = headers

    mime, charset = textutils.parse_content_type(headers.content_type)
    # usually charset is not set in http post
    output_body = parse_config.level >= OutputLevel.ALL_BODY and not textutils.isbinarybody(mime) \
        or parse_config.level >= OutputLevel.TEXT_BODY and textutils.istextbody(mime)

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
        headers.gzip = textutils.isgzip(content)

    # if it is form url encode

    if 'expect' in request_status and not content:
        content = '{Expect-continue-100, see next content for http post body}'
    if output_body:
        #unescape www-form-encoded data.x-www-form-urlencoded
        if parse_config.encoding and not charset:
            charset = parse_config.encoding
        print_body(content, headers.gzip, charset, outputfile, mime and 'form-urlencoded' in mime, parse_config.pretty)


def read_response(reader, outputfile, request_status, parse_config):
    """
    read and output one http response
    """
    headers = read_http_headers(reader, outputfile, parse_config.level)
    if headers is None or not isinstance(headers, HttpReponseHeader):
        outputfile.write("{Error, cannot parse http response headers.}")
        outputfile.write('\n')
        reader.skipall()
        return

    # read body
    mime, charset = textutils.parse_content_type(headers.content_type)
    if parse_config.encoding and not charset:
        charset = parse_config.encoding

    output_body = parse_config.level >= OutputLevel.ALL_BODY and not textutils.isbinarybody(mime) \
        or parse_config.level >= OutputLevel.TEXT_BODY and textutils.istextbody(mime)

    content = ''
    # deal with body
    if not headers.chunked:
        if headers.content_len == 0:
            if headers.connectionclose:
                # we can't get content length, so asume it till the end of data.
                #TODO: add readall method
                headers.content_len = 10000000L
            else:
                #TODO: we can't get content length, and is not a chunked body.
                pass
        if output_body:
            content = reader.read(headers.content_len)
        else:
            reader.skip(headers.content_len)
    else:
        #TODO: could skip chunked data.
        content = read_chunked_body(reader)

    if output_body:
        print_body(content, headers.gzip, charset, outputfile, False, parse_config.pretty)


class ResetableWrapper(object):
    """a wrapper to distinct request and response datas."""

    def __init__(self, queue):
        self.queue = queue
        self.cur_httptype = None
        self.last_data = None
        self.finish = False

    def remains(self):
        return not self.finish

    def set_type(self, httptype):
        self.cur_httptype = httptype

    def wrap(self):
        if self.last_data:
            temp = self.last_data
            self.last_data = None
            yield temp

        while True:
            httptype, data = self.queue.get(block=True, timeout=None)
            if data is None:
                #None mean finish.
                break
            if httptype == self.cur_httptype:
                yield data
            else:
                # save for next
                self.last_data = data
                return
        self.finish = True


class HttpParser(object):
    def __init__(self, client_host, remote_host, parse_config):
        self.buf = StringIO.StringIO()
        self.client_host = client_host
        self.remote_host = remote_host
        self.parse_config = parse_config
        self.queue = Queue()

        self.worker = self._start()

    def send(self, data):
        self.queue.put(data)

    def _work(self):
        self.buf.write("Connection: [%s:%d] --- -- - > [%s:%d]\n" %
                       (self.client_host[0], self.client_host[1], self.remote_host[0], self.remote_host[1]))

        request_status = {}
        wrapper = ResetableWrapper(self.queue)
        try:
            while wrapper.remains():
                wrapper.set_type(HttpType.REQUEST)
                reader = DataReader(wrapper.wrap())
                if reader.fetchline() is None:
                    break
                read_request(reader, self.buf, request_status, self.parse_config)

                wrapper.set_type(HttpType.RESPONSE)
                reader = DataReader(wrapper.wrap())
                if not wrapper.remains():
                    self.buf.write('{Http response missing}\n\n')
                    break
                if reader.fetchline() is None:
                    self.buf.write('{Http response missing}\n\n')
                    break
                read_response(reader, self.buf, request_status, self.parse_config)
                self.buf.write('\n')
        except Exception as e:
            import traceback

            traceback.print_exc(file=self.buf)
            # consume all datas.
            # for proxy mode, make sure http-proxy works well
            while True:
                httptype, data = self.queue.get(block=True, timeout=None)
                if data is None:
                    break

    def _start(self):
        worker = threading.Thread(target=self._work)
        worker.setDaemon(True)
        worker.start()
        return worker

    def finish(self):
        self.queue.put((None, None))
        self.worker.join()
        return self.buf.getvalue()