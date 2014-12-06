# coding=utf-8
from __future__ import unicode_literals, print_function, division

from io import StringIO

from pcapparser.config import OutputLevel
# print http req/resp
from pcapparser import utils
from pcapparser.processor import HttpDataProcessor
from pcapparser import config


def _get_full_url(uri, host):
    if uri.startswith(b'http://') or uri.startswith(b'https://'):
        return uri
    else:
        return b'http://' + host + uri


class HttpPrinter(HttpDataProcessor):
    def __init__(self, client_host, remote_host):
        self.parse_config = config.get_config()
        self.buf = StringIO()
        self._println(('*' * 10 + " [%s:%d] -- -- --> [%s:%d] " + '*' * 10) %
                      (client_host[0], client_host[1], remote_host[0], remote_host[1]))

    def on_http_req(self, req_header, req_body):
        """
        :type req_header: HttpRequestHeader
        :type req_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(
                req_header.method + b" " + _get_full_url(req_header.uri, req_header.host))
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(req_header.raw_data)
            self._println('')
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(req_header.raw_data)
            self._println('')

            mime, charset = utils.parse_content_type(req_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if not req_header.gzip:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                req_header.gzip = utils.gzipped(req_body)
            if output_body:
                self._print_body(req_body, req_header.gzip, charset)
                self._println('')

    def on_http_resp(self, resp_header, resp_body):
        """
        :type resp_header: HttpResponseHeader
        :type resp_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(resp_header.status_line)
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(resp_header.raw_data)
            self._println('')
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(resp_header.raw_data)
            self._println('')

            mime, charset = utils.parse_content_type(resp_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if not resp_header.gzip:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                resp_header.gzip = utils.gzipped(resp_body)
            if output_body:
                self._print_body(resp_body, resp_header.gzip, charset)
                self._println('')

    def _if_output(self, mime):
        return self.parse_config.level >= OutputLevel.ALL_BODY and not utils.is_binary(mime) \
               or self.parse_config.level >= OutputLevel.TEXT_BODY and utils.is_text(mime)

    def _println(self, line):
        if type(line) == type(b''):
            line = line.decode('utf-8')
        self.buf.write(line)
        self.buf.write('\n')

    def _println_if(self, level, line):
        if self.parse_config.level >= level:
            self._println(line)

    def _print_body(self, body, gzipped, charset):
        if gzipped:
            body = utils.ungzip(body)

        content = utils.decode_body(body, charset)
        if content:
            if self.parse_config.pretty:
                utils.try_print_json(content, self.buf)
            else:
                self.buf.write(content)
            self.buf.write('\n')

    def getvalue(self):
        return self.buf.getvalue()