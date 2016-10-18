package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"github.com/caoqianli/httpparse/httpport"
	"io"
	"io/ioutil"
	"strings"

	"github.com/google/gopacket/tcpassembly/tcpreader"
	"bufio"
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
func (th *HttpTrafficHandler) handle(connection *TcpConnection) {
	defer waitGroup.Done()
	defer connection.upStream.Close()
	defer connection.downStream.Close()
	// filter by args setting

	requestReader := bufio.NewReader(connection.upStream)
	defer tcpreader.DiscardBytesToEOF(requestReader)
	responseReader := bufio.NewReader(connection.downStream)
	defer tcpreader.DiscardBytesToEOF(responseReader)

	for {
		th.buffer = new(bytes.Buffer)
		filtered := false
		req, err := httpport.ReadRequest(requestReader)

		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing HTTP requests:", err)
			break
		}
		if th.config.domain != "" && !strings.HasSuffix(req.Host, th.config.domain) {
			filtered = true
		}
		if th.config.urlPath != "" && !strings.Contains(req.RequestURI, th.config.urlPath) {
			filtered = true
		}
		if !filtered {
			th.printRequest(req)
			th.writeLine("")
		}

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
			th.printResponse(resp)
			th.printer.send(th.buffer.String())
		}
	}

	th.printer.send(th.buffer.String())
}

func (th *HttpTrafficHandler) writeLine(a ...interface{}) {
	fmt.Fprintln(th.buffer, a...)
}

func (th *HttpTrafficHandler) printRequestMark() {
	th.writeLine()
}

// print http request
func (th *HttpTrafficHandler) printRequest(req *httpport.Request) {
	defer tcpreader.DiscardBytesToEOF(req.Body)
	if th.config.level == "url" {
		th.writeLine(req.Method, "http://" + req.Host + req.RequestURI)
		return
	}

	th.writeLine()
	th.writeLine(strings.Repeat("*", 10), th.key.srcString(), " -----> ", th.key.dstString(), strings.Repeat("*", 10))
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
				", set [level = all] to display http body}")
		}
		return
	}

	th.writeLine()
	th.printBody(hasBody, req.Header, req.Body)
}

// print http response
func (th *HttpTrafficHandler) printResponse(resp *httpport.Response) {
	defer tcpreader.DiscardBytesToEOF(resp.Body)
	if th.config.level == "url" {
		return
	}

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
				", set [level = all] to display body content}")
		}
		return
	}

	th.writeLine()
	th.printBody(hasBody, resp.Header, resp.Body)
}

// print http request/response body
func (th *HttpTrafficHandler) printBody(hasBody bool, header httpport.Header, reader io.ReadCloser) {

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
			// TODO: try to guess charset
			body = string(data)
		}
	} else {
		body, err = readToStringWithCharset(nr, charset)
	}
	if err != nil {
		th.writeLine("{Read body failed", err, "}")
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
		// TODO: try to guess charset
		str := string(data)
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
