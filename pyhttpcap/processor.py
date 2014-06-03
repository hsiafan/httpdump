__author__ = 'dongliu'


class HttpDataProcessor(object):
    """
    call back interface for http parser.
    extends this when you need a custom http data processor
    """
    def on_http_req(self, req_header, req_body):
        """
        :type req_header: HttpRequestHeader
        :type req_body: bytes
        :param req_body: raw body data, not decoded or unzipped
        """
        pass

    def on_http_resp(self, resp_header, resp_body):
        """
        :type resp_header: HttpResponseHeader
        :type resp_body: bytes
        :param req_body: raw body data, not decoded or unzipped
        """
        pass