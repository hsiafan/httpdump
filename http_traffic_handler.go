package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"compress/gzip"
	"compress/zlib"
	"bufio"
	"io"
	"fmt"
	"bytes"
	"github.com/caoqianli/httpcap/httpport"
	"io/ioutil"
	"strings"
)

// Create our StreamFactory
type httpStreamFactory struct {
	config  *config
	printer *printer
}

func (hsf *httpStreamFactory) New(f1, f2 gopacket.Flow) tcpassembly.Stream {
	trafficHandler := &trafficHandler{
		flow1:f1,
		flow2:f2,
		buffer:new(bytes.Buffer),
		config:hsf.config,
		printer:hsf.printer,
	}
	r := tcpreader.NewReaderStream()
	go trafficHandler.handleHttpTraffic(&r)
	return &r
}

type trafficHandler struct {
	flow1, flow2 gopacket.Flow
	buffer       *bytes.Buffer
	config       *config
	printer      *printer
}

// read http request/response stream, and do output
func (th *trafficHandler) handleHttpTraffic(r io.Reader) {

	// filter by args setting
	droped := false
	if th.config.filterIp != "" {
		if th.flow1.Src().String() != th.config.filterIp && th.flow1.Dst().String() != th.config.filterIp {
			droped = true
		}
	}
	if th.config.filterPort != "" {
		if th.flow2.Src().String() != th.config.filterPort && th.flow2.Dst().String() != th.config.filterPort {
			droped = true
		}
	}

	if droped {
		tcpreader.DiscardBytesToEOF(r)
		return
	}

	// read first 8 bytes, check if is http request/response
	br := bufio.NewReader(r)
	prefix, err := br.Peek(8)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			tcpreader.DiscardBytesToEOF(r)
			return
		} else {
			//fmt.Println("Read stream prefix error:", err)
			tcpreader.DiscardBytesToEOF(r)
			return
		}
	}

	idx := bytes.IndexByte(prefix, 32)

	th.buffer = new(bytes.Buffer)
	if idx >= 3 {
		method := string(prefix[:idx])
		if method == "GET" || method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" ||
		method == "TRACE" || method == "OPTIONS" {
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
			tcpreader.DiscardBytesToEOF(br)
			//log.Println("Unknown method:", method)
		}
	} else if (string(prefix[:5]) == "HTTP/") {
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
	} else {
		//hsf.printRequestMark()
		//log.Print("Not http traffic")
		tcpreader.DiscardBytesToEOF(br)
		return
	}
	th.printer.send(th.buffer.String())
}

func (th *trafficHandler) writeLine(a ...interface{}) {
	fmt.Fprintln(th.buffer, a...)
}

func (th *trafficHandler) printRequestMark() {
	th.writeLine()
	src1, dst1 := th.flow1.Endpoints()
	src2, dst2 := th.flow2.Endpoints()
	th.writeLine(src1.String() + ":" + src2.String(), " -----> ", dst1.String() + ":" + dst2.String())
}

// print http request
func (th *trafficHandler) printRequest(req *httpport.Request) {
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

	var hasBody bool = true
	if req.ContentLength == 0 || req.Method == "GET" || req.Method == "HEAD" || req.Method == "TRACE" ||
	req.Method == "OPTIONS" {
		hasBody = false
	}

	if th.config.level == "header" {
		if hasBody {
			th.writeLine("\n{body size:", tcpreader.DiscardBytesToEOF(req.Body),
				", set level arg to all to display body content}")
		}
		return
	}

	th.writeLine()
	th.printBody(hasBody, req.Header, req.Body)
}

func (th *trafficHandler) printResponseMark() {
	th.writeLine()
	src1, dst1 := th.flow1.Endpoints()
	src2, dst2 := th.flow2.Endpoints()
	th.writeLine(dst1.String() + ":" + dst2.String(), " <----- ", src1.String() + ":" + src2.String())
}

// print http response
func (th *trafficHandler) printResponse(resp *httpport.Response) {
	if th.config.level == "url" {
		tcpreader.DiscardBytesToEOF(resp.Body)
		return
	}

	th.printResponseMark()
	th.writeLine(resp.StatusLine)
	for _, header := range resp.RawHeaders {
		th.writeLine(header)
	}

	var hasBody bool = true
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
func (th *trafficHandler) printBody(hasBody bool, header httpport.Header, reader io.ReadCloser) {
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

	var str string
	if charset == "" {
		var data []byte
		data, err = ioutil.ReadAll(nr)
		if err == nil {
			str, err = byteToStringDetected(data)
		}
	} else {
		str, err = readToStringWithCharset(nr, charset)
	}
	if err != nil {
		th.writeLine("{Read body failed", err, "}")
		tcpreader.DiscardBytesToEOF(reader)
		return
	}
	th.writeLine(str)
	th.writeLine()
}

func (th *trafficHandler) printNonTextTypeBody(reader io.Reader, contentType string, isBinary bool) error {
	if th.config.forcePrint && !isBinary {
		data, err := ioutil.ReadAll(reader);
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