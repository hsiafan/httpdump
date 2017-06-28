package main

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"strconv"
	"sync"
	"time"
)

// gopacket provide a tcp connection, however it split one tcp connection into two stream.
// So it is hard to match http request and response. we make our own connection here

const MAX_TCP_SEQ uint32 = 0xFFFFFFFF
const TCP_SEQ_WINDOW = 0x0000FFFF

type TcpAssembler struct {
	connectionDict    map[string]*TcpConnection
	lock              sync.Mutex
	connectionHandler ConnectionHandler
	filterIp          string
	filterPort        uint16
}

func newTcpAssembler(connectionHandler ConnectionHandler) *TcpAssembler {
	return &TcpAssembler{connectionDict: map[string]*TcpConnection{}, connectionHandler: connectionHandler}
}

func (assembler *TcpAssembler) assemble(flow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	src := EndPoint{ip: flow.Src().String(), port: uint16(tcp.SrcPort)}
	dst := EndPoint{ip: flow.Dst().String(), port: uint16(tcp.DstPort)}
	dropped := false
	if assembler.filterIp != "" {
		if src.ip != assembler.filterIp && dst.ip != assembler.filterIp {
			dropped = true
		}
	}
	if assembler.filterPort != 0 {
		if src.port != assembler.filterPort && dst.port != assembler.filterPort {
			dropped = true
		}
	}
	if dropped {
		return
	}

	srcString := src.String()
	dstString := dst.String()
	var key string
	if srcString < dstString {
		key = srcString + "-" + dstString
	} else {
		key = dstString + "-" + srcString
	}

	var createNewConn = tcp.SYN && !tcp.ACK || isHttpRequestData(tcp.Payload)
	connection := assembler.retrieveConnection(src, dst, key, createNewConn)
	if connection == nil {
		return
	}

	connection.onReceive(src, dst, tcp, timestamp)

	if connection.closed() {
		assembler.deleteConnection(key)
		connection.finish()
	}
}

// get connection this packet belong to; create new one if is new connection
func (assembler *TcpAssembler) retrieveConnection(src, dst EndPoint, key string, init bool) *TcpConnection {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	connection := assembler.connectionDict[key]
	if connection == nil {
		if init {
			connection = newTcpConnection(key)
			assembler.connectionDict[key] = connection
			assembler.connectionHandler.handle(src, dst, connection)
		}
	}
	return connection
}

// remove connection (when is closed or timeout)
func (assembler *TcpAssembler) deleteConnection(key string) {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	delete(assembler.connectionDict, key)
}

// flush timeout connections
func (assembler *TcpAssembler) flushOlderThan(time time.Time) {
	var connections []*TcpConnection
	assembler.lock.Lock()
	for _, connection := range assembler.connectionDict {
		if connection.lastTimestamp.Before(time) {
			connections = append(connections, connection)
		}
	}
	for _, connection := range connections {
		delete(assembler.connectionDict, connection.key)
	}
	assembler.lock.Unlock()

	for _, connection := range connections {
		connection.flushOlderThan()
	}
}

func (assembler *TcpAssembler) finishAll() {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	for _, connection := range assembler.connectionDict {
		connection.finish()
	}
	assembler.connectionDict = nil
	assembler.connectionHandler.finish()
}

type ConnectionHandler interface {
	handle(src EndPoint, dst EndPoint, connection *TcpConnection)
	finish()
}

// one tcp connection
type TcpConnection struct {
	upStream      *NetworkStream // stream from client to server
	downStream    *NetworkStream // stream from server to client
	clientId      EndPoint       // the client key(by ip and port)
	lastTimestamp time.Time      // timestamp receive last packet
	isHttp        bool
	key           string
}

type EndPoint struct {
	ip   string
	port uint16
}

func (p EndPoint) equals(p2 EndPoint) bool {
	return p.ip == p2.ip && p.port == p2.port
}

func (p EndPoint) String() string {
	return p.ip + ":" + strconv.Itoa(int(p.port))
}

type ConnectionId struct {
	src EndPoint
	dst EndPoint
}

// create tcp connection, by the first tcp packet. this packet should from client to server
func newTcpConnection(key string) *TcpConnection {
	connection := &TcpConnection{
		upStream:   newNetworkStream(),
		downStream: newNetworkStream(),
		key:        key,
	}
	return connection
}

// when receive tcp packet
func (connection *TcpConnection) onReceive(src, dst EndPoint, tcp *layers.TCP, timestamp time.Time) {
	connection.lastTimestamp = timestamp
	payload := tcp.Payload

	if !connection.isHttp {
		// skip no-http data
		if !isHttpRequestData(payload) {
			return
		}
		// receive first valid http data packet
		connection.clientId = src
		connection.isHttp = true
	}

	var sendStream, confirmStream *NetworkStream
	//var up bool
	if connection.clientId.equals(src) {
		sendStream = connection.upStream
		confirmStream = connection.downStream
		//up = true
	} else {
		sendStream = connection.downStream
		confirmStream = connection.upStream
		//up = false
	}

	sendStream.appendPacket(tcp)

	if tcp.SYN {
		// do nothing
	}

	if tcp.ACK {
		// confirm
		confirmStream.confirmPacket(tcp.Ack)
	}

	// terminate connection
	if tcp.FIN || tcp.RST {
		sendStream.closed = true
	}
}

// just close this connection?
func (connection *TcpConnection) flushOlderThan() {
	// flush all data
	//connection.upStream.window
	//connection.downStream.window
	// remove and close connection
	connection.upStream.closed = true
	connection.downStream.closed = true
	connection.finish()

}

func (connection *TcpConnection) closed() bool {
	return connection.upStream.closed && connection.downStream.closed
}

func (connection *TcpConnection) finish() {
	connection.upStream.finish()
	connection.downStream.finish()
}

// tread one-direction tcp data as stream. impl reader closer
type NetworkStream struct {
	window *ReceiveWindow
	c      chan *layers.TCP
	remain []byte
	ignore bool
	closed bool
}

func newNetworkStream() *NetworkStream {
	return &NetworkStream{window: newReceiveWindow(64), c: make(chan *layers.TCP, 1024)}
}

func (stream *NetworkStream) appendPacket(tcp *layers.TCP) {
	if stream.ignore {
		return
	}
	stream.window.insert(tcp)
}

func (stream *NetworkStream) confirmPacket(ack uint32) {
	if stream.ignore {
		return
	}
	stream.window.confirm(ack, stream.c)
}

func (stream *NetworkStream) finish() {
	close(stream.c)
}

func (stream *NetworkStream) Read(p []byte) (n int, err error) {
	for len(stream.remain) == 0 {
		packet, ok := <-stream.c
		if !ok {
			err = io.EOF
			return
		}
		stream.remain = packet.Payload
	}

	if len(stream.remain) > len(p) {
		n = copy(p, stream.remain[:len(p)])
		stream.remain = stream.remain[len(p):]
	} else {
		n = copy(p, stream.remain)
		stream.remain = nil
	}
	return
}

func (stream *NetworkStream) Close() error {
	stream.ignore = true
	return nil
}

type ReceiveWindow struct {
	size        int
	start       int
	buffer      []*layers.TCP
	lastAck     uint32
	expectBegin uint32
}

func newReceiveWindow(initialSize int) *ReceiveWindow {
	buffer := make([]*layers.TCP, initialSize)
	return &ReceiveWindow{buffer: buffer}
}

func (window *ReceiveWindow) destroy() {
	window.size = 0
	window.start = 0
	window.buffer = nil
}

func (window *ReceiveWindow) insert(packet *layers.TCP) {

	if window.expectBegin != 0 && compareTcpSeq(window.expectBegin, packet.Seq+uint32(len(packet.Payload))) >= 0 {
		// dropped
		return
	}

	if len(packet.Payload) == 0 {
		//ignore empty data packet
		return
	}

	idx := window.size
	for ; idx > 0; idx-- {
		index := (idx - 1 + window.start) % len(window.buffer)
		prev := window.buffer[index]
		result := compareTcpSeq(prev.Seq, packet.Seq)
		if result == 0 {
			// duplicated
			return
		}
		if result < 0 {
			// insert at index
			break
		}
	}

	if window.size == len(window.buffer) {
		window.expand()
	}

	if idx == window.size {
		// append at last
		index := (idx + window.start) % len(window.buffer)
		window.buffer[index] = packet
	} else {
		// insert at index
		for i := window.size - 1; i >= idx; i-- {
			next := (i + window.start + 1) % len(window.buffer)
			current := (i + window.start) % len(window.buffer)
			window.buffer[next] = window.buffer[current]
		}
		index := (idx + window.start) % len(window.buffer)
		window.buffer[index] = packet
	}

	window.size++
}

// send confirmed packets to reader, when receive ack
func (window *ReceiveWindow) confirm(ack uint32, c chan *layers.TCP) {
	idx := 0
	for ; idx < window.size; idx++ {
		index := (idx + window.start) % len(window.buffer)
		packet := window.buffer[index]
		result := compareTcpSeq(packet.Seq, ack)
		if result >= 0 {
			break
		}
		window.buffer[index] = nil
		newExpect := packet.Seq + uint32(len(packet.Payload))
		if window.expectBegin != 0 {
			diff := compareTcpSeq(window.expectBegin, packet.Seq)
			if diff > 0 {
				duplicatedSize := window.expectBegin - packet.Seq
				if duplicatedSize < 0 {
					duplicatedSize += MAX_TCP_SEQ
				}
				if duplicatedSize >= uint32(len(packet.Payload)) {
					continue
				}
				packet.Payload = packet.Payload[duplicatedSize:]
			} else if diff < 0 {
				//TODO: we lose packet here
			}
		}
		c <- packet
		window.expectBegin = newExpect
	}
	window.start = (window.start + idx) % len(window.buffer)
	window.size = window.size - idx
	if compareTcpSeq(window.lastAck, ack) < 0 || window.lastAck == 0 {
		window.lastAck = ack
	}
}

func (window *ReceiveWindow) expand() {
	buffer := make([]*layers.TCP, len(window.buffer)*2)
	end := window.start + window.size
	if end < len(window.buffer) {
		copy(buffer, window.buffer[window.start:window.start+window.size])
	} else {
		copy(buffer, window.buffer[window.start:])
		copy(buffer[len(window.buffer)-window.start:], window.buffer[:end-len(window.buffer)])
	}
	window.start = 0
	window.buffer = buffer
}

// compare two tcp sequences, if seq1 is earlier, return num < 0, if seq1 == seq2, return 0, else return num > 0
func compareTcpSeq(seq1, seq2 uint32) int {
	if seq1 < TCP_SEQ_WINDOW && seq2 > MAX_TCP_SEQ-TCP_SEQ_WINDOW {
		return int(seq1 + MAX_TCP_SEQ - seq2)
	} else if seq2 < TCP_SEQ_WINDOW && seq1 > MAX_TCP_SEQ-TCP_SEQ_WINDOW {
		return int(seq1 - (MAX_TCP_SEQ + seq2))
	}
	return int(int32(seq1 - seq2))
}

var HTTP_METHODS = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"TRACE":                              true, "OPTIONS": true, "PATCH": true}

// if is first http request packet
func isHttpRequestData(body []byte) bool {
	if len(body) < 8 {
		return false
	}
	data := body[0:8]
	idx := bytes.IndexByte(data, byte(' '))
	if idx < 0 {
		return false
	}

	method := string(data[:idx])
	return HTTP_METHODS[method]
}
