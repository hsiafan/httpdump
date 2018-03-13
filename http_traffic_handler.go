package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"github.com/hsiafan/httpdump/httpport"
	"io"
	"io/ioutil"
	"strings"

	"bufio"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"os"
)

type ConnectionKey struct {
	src EndPoint
	dst EndPoint
}

func (ck *ConnectionKey) reverse() ConnectionKey {
	return ConnectionKey{ck.dst, ck.src}
}

// return the src ip and port
func (ck *ConnectionKey) srcString() string {
	return ck.src.String()
}

// return the dst ip and port
func (ck *ConnectionKey) dstString() string {
	return ck.dst.String()
}

// Impl ConnectionHandler
type HttpConnectionHandler struct {
	config  *Config
	printer *Printer
}

func (handler *HttpConnectionHandler) handle(src EndPoint, dst EndPoint, connection *TcpConnection) {
	ck := ConnectionKey{src, dst}
	trafficHandler := &HttpTrafficHandler{
		key:     ck,
		buffer:  new(bytes.Buffer),
		config:  handler.config,
		printer: handler.printer,
	}
	waitGroup.Add(1)
	go trafficHandler.handle(connection)
}

func (handler *HttpConnectionHandler) finish() {
	//handler.printer.finish()
}

type HttpTrafficHandler struct {
	key     ConnectionKey
	buffer  *bytes.Buffer
	config  *Config
	printer *Printer
}

// read http request/response stream, and do output
func (h *HttpTrafficHandler) handle(connection *TcpConnection) {
	defer waitGroup.Done()
	defer connection.upStream.Close()
	defer connection.downStream.Close()
	// filter by args setting

	requestReader := bufio.NewReader(connection.upStream)
	defer tcpreader.DiscardBytesToEOF(requestReader)
	responseReader := bufio.NewReader(connection.downStream)
	defer tcpreader.DiscardBytesToEOF(responseReader)

	for {
		h.buffer = new(bytes.Buffer)
		filtered := false
		req, err := httpport.ReadRequest(requestReader)

		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing HTTP requests:", err)
			break
		}
		if h.config.host != "" && !wildcardMatch(req.Host, h.config.host) {
			filtered = true
		}
		if h.config.uri != "" && !wildcardMatch(req.RequestURI, h.config.uri) {
			filtered = true
		}

		if !filtered {
			h.printRequest(req)
			h.writeLine("")
		}

		// if is websocket request,  by header: Upgrade: websocket
		websocket := req.Header.Get("Upgrade") == "websocket"
		expectContinue := req.Header.Get("Expect") == "100-continue"

		resp, err := httpport.ReadResponse(responseReader, nil)
		if err == io.EOF {
			fmt.Fprintln(os.Stderr, "Error parsing HTTP requests: unexpected end, ", err)
			break
		}
		if err == io.ErrUnexpectedEOF {
			fmt.Fprintln(os.Stderr, "Error parsing HTTP requests: unexpected end, ", err)
			// here return directly too, to avoid error when long polling connection is used
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing HTTP response:", err, connection.clientId)
			break
		}
		if !filtered {
			h.printResponse(resp)
			h.printer.send(h.buffer.String())
		}

		if websocket {
			if resp.StatusCode == 101 && resp.Header.Get("Upgrade") == "websocket" {
				// change to handle websocket
				h.handleWebsocket(requestReader, responseReader)
				break
			}
		}

		if expectContinue {
			if resp.StatusCode == 100 {
				// read next response, the real response
				resp, err := httpport.ReadResponse(responseReader, nil)
				if err == io.EOF {
					fmt.Fprintln(os.Stderr, "Error parsing HTTP requests: unexpected end, ", err)
					break
				}
				if err == io.ErrUnexpectedEOF {
					fmt.Fprintln(os.Stderr, "Error parsing HTTP requests: unexpected end, ", err)
					// here return directly too, to avoid error when long polling connection is used
					break
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error parsing HTTP response:", err, connection.clientId)
					break
				}
				if !filtered {
					h.printResponse(resp)
					h.printer.send(h.buffer.String())
				}
			} else if resp.StatusCode == 417 {

			}
		}
	}

	h.printer.send(h.buffer.String())
}

func (h *HttpTrafficHandler) handleWebsocket(requestReader *bufio.Reader, responseReader *bufio.Reader) {
	//TODO: websocket

}

func (h *HttpTrafficHandler) writeLine(a ...interface{}) {
	fmt.Fprintln(h.buffer, a...)
}

func (h *HttpTrafficHandler) printRequestMark() {
	h.writeLine()
}

// print http request
func (h *HttpTrafficHandler) printRequest(req *httpport.Request) {
	defer tcpreader.DiscardBytesToEOF(req.Body)
	//TODO: expect-100 continue handle
	if h.config.level == "url" {
		h.writeLine(req.Method, req.Host+req.RequestURI)
		return
	}

	h.writeLine()
	h.writeLine(strings.Repeat("*", 10), h.key.srcString(), " -----> ", h.key.dstString(), strings.Repeat("*", 10))
	h.writeLine(req.RequestLine)
	for _, header := range req.RawHeaders {
		h.writeLine(header)
	}

	var hasBody = true
	if req.ContentLength == 0 || req.Method == "GET" || req.Method == "HEAD" || req.Method == "TRACE" ||
		req.Method == "OPTIONS" {
		hasBody = false
	}

	if h.config.level == "header" {
		if hasBody {
			h.writeLine("\n{body size:", tcpreader.DiscardBytesToEOF(req.Body),
				", set [level = all] to display http body}")
		}
		return
	}

	h.writeLine()
	h.printBody(hasBody, req.Header, req.Body)
}

// print http response
func (h *HttpTrafficHandler) printResponse(resp *httpport.Response) {
	defer tcpreader.DiscardBytesToEOF(resp.Body)
	if h.config.level == "url" {
		return
	}

	h.writeLine(resp.StatusLine)
	for _, header := range resp.RawHeaders {
		h.writeLine(header)
	}

	var hasBody = true
	if resp.ContentLength == 0 || resp.StatusCode == 304 || resp.StatusCode == 204 {
		hasBody = false
	}

	if h.config.level == "header" {
		if hasBody {
			h.writeLine("\n{body size:", tcpreader.DiscardBytesToEOF(resp.Body),
				", set [level = all] to display body content}")
		}
		return
	}

	h.writeLine()
	h.printBody(hasBody, resp.Header, resp.Body)
}

// print http request/response body
func (h *HttpTrafficHandler) printBody(hasBody bool, header httpport.Header, reader io.ReadCloser) {

	if !hasBody {
		return
	}

	// deal with content encoding such as gzip, deflate
	contentEncoding := header.Get("Content-Encoding")
	var nr io.ReadCloser
	var err error
	if contentEncoding == "" {
		// do nothing
		nr = reader
	} else if strings.Contains(contentEncoding, "gzip") {
		nr, err = gzip.NewReader(reader)
		if err != nil {
			h.writeLine("{Decompress gzip err:", err, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
			return
		}
		defer nr.Close()
	} else if strings.Contains(contentEncoding, "deflate") {
		nr, err = zlib.NewReader(reader)
		if err != nil {
			h.writeLine("{Decompress deflate err:", err, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
			return
		}
		defer nr.Close()
	} else {
		h.writeLine("{Unsupport Content-Encoding:", contentEncoding, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
		return
	}

	// check mime type and charset
	contentType := header.Get("Content-Type")
	mimeTypeStr, charset := parseContentType(contentType)
	var mimeType = parseMimeType(mimeTypeStr)
	isText := mimeType.isTextContent()
	isBinary := mimeType.isBinaryContent()

	if !isText {
		err = h.printNonTextTypeBody(nr, contentType, isBinary)
		if err != nil {
			h.writeLine("{Read content error", err, "}")
		}
		return
	}

	var body string
	if charset == "" {
		// response do not set charset, try to detect
		var data []byte
		data, err = ioutil.ReadAll(nr)
		if err == nil {
			// TODO: try to guess charset
			body = string(data)
		}
	} else {
		body, err = readToStringWithCharset(nr, charset)
	}
	if err != nil {
		h.writeLine("{Read body failed", err, "}")
		return
	}

	// prettify json
	if mimeType.subType == "json" || likeJSON(body) {
		var jsonValue interface{}
		json.Unmarshal([]byte(body), &jsonValue)
		prettyJSON, err := json.MarshalIndent(jsonValue, "", "    ")
		if err == nil {
			body = string(prettyJSON)
		}
	}
	h.writeLine(body)
	h.writeLine()
}

func (h *HttpTrafficHandler) printNonTextTypeBody(reader io.Reader, contentType string, isBinary bool) error {
	if h.config.force && !isBinary {
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}
		// TODO: try to guess charset
		str := string(data)
		if err != nil {
			return err
		}
		h.writeLine(str)
		h.writeLine()
	} else {
		h.writeLine("{Non-text body, content-type:", contentType, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
	}
	return nil
}
