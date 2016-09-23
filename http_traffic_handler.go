package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"httpport"
	"io"
	"io/ioutil"
	"strings"

	"github.com/google/gopacket/tcpassembly/tcpreader"
	"bufio"
)

type ConnectionKey struct {
	src EndPoint
	dst EndPoint
}

func (ck *ConnectionKey) reverse() ConnectionKey {
	return ConnectionKey{ck.dst, ck.src}
}

// if ip match this connection
func (ck *ConnectionKey) ipMatched(ip string) bool {
	return ck.src.ip == ip || ck.dst.ip == ip
}

// if port match this connection
func (ck *ConnectionKey) portMatched(port uint16) bool {
	return ck.src.port == port || ck.dst.port == port
}

// return the src ip and port
func (ck *ConnectionKey) srcString() string {
	return ck.src.String()
}

// return the dest ip and port
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
	go trafficHandler.handle(connection.upStream, true)

	trafficHandler = &HttpTrafficHandler{
		key:     ck,
		buffer:  new(bytes.Buffer),
		config:  handler.config,
		printer: handler.printer,
	}
	waitGroup.Add(1)
	go trafficHandler.handle(connection.downStream, false)
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
func (th *HttpTrafficHandler) handle(r io.ReadCloser, isRequest bool) {
	defer r.Close()
	defer waitGroup.Done()
	// filter by args setting
	droped := false
	if th.config.filterIP != "" {
		if !th.key.ipMatched(th.config.filterIP) {
			droped = true
		}
	}
	if th.config.filterPort != 0 {
		if !th.key.portMatched(th.config.filterPort) {
			droped = true
		}
	}

	if droped {
		tcpreader.DiscardBytesToEOF(r)
		return
	}

	th.buffer = new(bytes.Buffer)
	br := bufio.NewReader(r)
	if isRequest {
		for {
			if req, err := httpport.ReadRequest(br); err == io.EOF {
				return
			} else if err != nil {
				th.printRequestMark()
				th.writeLine("Error parsing HTTP requests:", err)
				tcpreader.DiscardBytesToEOF(br)
				break
			} else {
				th.printRequest(req)
			}
			th.printer.send(th.buffer.String())
			th.buffer = new(bytes.Buffer)
		}
	} else {
		for {
			if resp, err := httpport.ReadResponse(br, nil); err == io.EOF {
				return
			} else if err == io.ErrUnexpectedEOF {
				// here return directly too, to avoid error when long polling connection is used
				return
			} else if err != nil {
				th.printResponseMark()
				th.writeLine("Error parsing HTTP response:", err)
				tcpreader.DiscardBytesToEOF(br)
				break
			} else {
				th.printResponse(resp)
			}
			th.printer.send(th.buffer.String())
			th.buffer = new(bytes.Buffer)
		}
	}
	th.printer.send(th.buffer.String())
}

func (th *HttpTrafficHandler) writeLine(a ...interface{}) {
	fmt.Fprintln(th.buffer, a...)
}

func (th *HttpTrafficHandler) printRequestMark() {
	th.writeLine()
	th.writeLine(th.key.srcString(), " -----> ", th.key.dstString())
}

// print http request
func (th *HttpTrafficHandler) printRequest(req *httpport.Request) {
	if th.config.level == "url" {
		tcpreader.DiscardBytesToEOF(req.Body)
		th.writeLine(req.Method, "http://" + req.Host + req.RequestURI)
		return
	}

	th.printRequestMark()
	th.writeLine(req.RequestLine)
	for _, header := range req.RawHeaders {
		th.writeLine(header)
	}

	var hasBody = true
	if req.ContentLength == 0 || req.Method == "GET" || req.Method == "HEAD" || req.Method == "TRACE" ||
			req.Method == "OPTIONS" {
		hasBody = false
	}

	if th.config.level == "header" {
		if hasBody {
			th.writeLine("\n{body size:", tcpreader.DiscardBytesToEOF(req.Body),
				", use [-level all] to display http body}")
		}
		return
	}

	th.writeLine()
	th.printBody(hasBody, req.Header, req.Body)
}

func (th *HttpTrafficHandler) printResponseMark() {
	th.writeLine()
	th.writeLine(th.key.dstString(), " <----- ", th.key.srcString())
}

// print http response
func (th *HttpTrafficHandler) printResponse(resp *httpport.Response) {
	if th.config.level == "url" {
		tcpreader.DiscardBytesToEOF(resp.Body)
		return
	}

	th.printResponseMark()
	th.writeLine(resp.StatusLine)
	for _, header := range resp.RawHeaders {
		th.writeLine(header)
	}

	var hasBody = true
	if resp.ContentLength == 0 || resp.StatusCode == 304 || resp.StatusCode == 204 {
		hasBody = false
	}

	if th.config.level == "header" {
		if hasBody {
			th.writeLine("\n{body size:", tcpreader.DiscardBytesToEOF(resp.Body),
				", set level arg to all to display body content}")
		}
		return
	}

	th.writeLine()
	th.printBody(hasBody, resp.Header, resp.Body)
}

// print http request/response body
func (th *HttpTrafficHandler) printBody(hasBody bool, header httpport.Header, reader io.ReadCloser) {
	defer reader.Close()

	if !hasBody {
		tcpreader.DiscardBytesToEOF(reader)
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
			th.writeLine("{Decompress gzip err:", err, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
			return
		}
		defer nr.Close()
	} else if strings.Contains(contentEncoding, "deflate") {
		nr, err = zlib.NewReader(reader)
		if err != nil {
			th.writeLine("{Decompress deflate err:", err, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
			return
		}
		defer nr.Close()
	} else {
		th.writeLine("{Unsupport Content-Encoding:", contentEncoding, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
		return
	}

	// check mime type and charset
	contentType := header.Get("Content-Type")
	mimeTypeStr, charset := parseContentType(contentType)
	var mimeType = parseMimeType(mimeTypeStr)
	isText := mimeType.isTextContent()
	isBinary := mimeType.isBinaryContent()

	if !isText {
		err = th.printNonTextTypeBody(nr, contentType, isBinary)
		if err != nil {
			th.writeLine("{Read content error", err, "}")
		}
		return
	}

	var body string
	if charset == "" {
		// response do not set charset, try to detect
		var data []byte
		data, err = ioutil.ReadAll(nr)
		if err == nil {
			body, err = byteToStringDetected(data)
		}
	} else {
		body, err = readToStringWithCharset(nr, charset)
	}
	if err != nil {
		th.writeLine("{Read body failed", err, "}")
		tcpreader.DiscardBytesToEOF(reader)
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
	th.writeLine(body)
	th.writeLine()
}

func (th *HttpTrafficHandler) printNonTextTypeBody(reader io.Reader, contentType string, isBinary bool) error {
	if th.config.force && !isBinary {
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}
		str, err := byteToStringDetected(data)
		if err != nil {
			return err
		}
		th.writeLine(str)
		th.writeLine()
	} else {
		th.writeLine("{Non-text body, content-type:", contentType, ", len:", tcpreader.DiscardBytesToEOF(reader), "}")
	}
	return nil
}
