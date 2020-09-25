package main

import (
	"bytes"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// gopacket provide a tcp connection, however it split one tcp connection into two stream.
// So it is hard to match http request and response. we make our own connection here

const maxTCPSeq uint32 = 0xFFFFFFFF
const tcpSeqWindow = 0x0000FFFF

// TCPAssembler do tcp package assemble
type TCPAssembler struct {
	connectionDict    map[string]*TCPConnection
	lock              sync.Mutex
	connectionHandler ConnectionHandler
	filterIP          string
	filterPort        uint16
}

func newTCPAssembler(connectionHandler ConnectionHandler) *TCPAssembler {
	return &TCPAssembler{connectionDict: map[string]*TCPConnection{}, connectionHandler: connectionHandler}
}

func (assembler *TCPAssembler) assemble(flow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	src := Endpoint{ip: flow.Src().String(), port: uint16(tcp.SrcPort)}
	dst := Endpoint{ip: flow.Dst().String(), port: uint16(tcp.DstPort)}
	dropped := false
	if assembler.filterIP != "" {
		if src.ip != assembler.filterIP && dst.ip != assembler.filterIP {
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

	var createNewConn = tcp.SYN && !tcp.ACK || isHTTPRequestData(tcp.Payload)
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
func (assembler *TCPAssembler) retrieveConnection(src, dst Endpoint, key string, init bool) *TCPConnection {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	connection := assembler.connectionDict[key]
	if connection == nil {
		if init {
			connection = newTCPConnection(key)
			assembler.connectionDict[key] = connection
			assembler.connectionHandler.handle(src, dst, connection)
		}
	}
	return connection
}

// remove connection (when is closed or timeout)
func (assembler *TCPAssembler) deleteConnection(key string) {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	delete(assembler.connectionDict, key)
}

// flush timeout connections
func (assembler *TCPAssembler) flushOlderThan(time time.Time) {
	var connections []*TCPConnection
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

func (assembler *TCPAssembler) finishAll() {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	for _, connection := range assembler.connectionDict {
		connection.finish()
	}
	assembler.connectionDict = nil
	assembler.connectionHandler.finish()
}

// ConnectionHandler is interface for handle tcp connection
type ConnectionHandler interface {
	handle(src Endpoint, dst Endpoint, connection *TCPConnection)
	finish()
}

// TCPConnection hold info for one tcp connection
type TCPConnection struct {
	upStream      *NetworkStream // stream from client to server
	downStream    *NetworkStream // stream from server to client
	clientID      Endpoint       // the client key(by ip and port)
	lastTimestamp time.Time      // timestamp receive last packet
	isHTTP        bool
	key           string
}

// Endpoint is one endpoint of a tcp connection
type Endpoint struct {
	ip   string
	port uint16
}

func (p Endpoint) equals(p2 Endpoint) bool {
	return p.ip == p2.ip && p.port == p2.port
}

func (p Endpoint) String() string {
	return p.ip + ":" + strconv.Itoa(int(p.port))
}

// ConnectionID identify a tcp connection
type ConnectionID struct {
	src Endpoint
	dst Endpoint
}

// create tcp connection, by the first tcp packet. this packet should from client to server
func newTCPConnection(key string) *TCPConnection {
	connection := &TCPConnection{
		upStream:   newNetworkStream(),
		downStream: newNetworkStream(),
		key:        key,
	}
	return connection
}

// when receive tcp packet
func (connection *TCPConnection) onReceive(src, dst Endpoint, tcp *layers.TCP, timestamp time.Time) {
	connection.lastTimestamp = timestamp
	payload := tcp.Payload
	if !connection.isHTTP {
		// skip no-http data
		if !isHTTPRequestData(payload) {
			return
		}
		// receive first valid http data packet
		connection.clientID = src
		connection.isHTTP = true
	}

	var sendStream, confirmStream *NetworkStream
	//var up bool
	if connection.clientID.equals(src) {
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
func (connection *TCPConnection) flushOlderThan() {
	// flush all data
	//connection.upStream.window
	//connection.downStream.window
	// remove and close connection
	connection.upStream.closed = true
	connection.downStream.closed = true
	connection.finish()

}

func (connection *TCPConnection) closed() bool {
	return connection.upStream.closed && connection.downStream.closed
}

func (connection *TCPConnection) finish() {
	connection.upStream.finish()
	connection.downStream.finish()
}

// NetworkStream tread one-direction tcp data as stream. impl reader closer
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

// Close the stream
func (stream *NetworkStream) Close() error {
	stream.ignore = true
	return nil
}

// ReceiveWindow simulate tcp receivec window
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

func (w *ReceiveWindow) destroy() {
	w.size = 0
	w.start = 0
	w.buffer = nil
}

func (w *ReceiveWindow) insert(packet *layers.TCP) {

	if w.expectBegin != 0 && compareTCPSeq(w.expectBegin, packet.Seq+uint32(len(packet.Payload))) >= 0 {
		// dropped
		return
	}

	if len(packet.Payload) == 0 {
		//ignore empty data packet
		return
	}

	idx := w.size
	for ; idx > 0; idx-- {
		index := (idx - 1 + w.start) % len(w.buffer)
		prev := w.buffer[index]
		result := compareTCPSeq(prev.Seq, packet.Seq)
		if result == 0 {
			// duplicated
			return
		}
		if result < 0 {
			// insert at index
			break
		}
	}

	if w.size == len(w.buffer) {
		w.expand()
	}

	if idx == w.size {
		// append at last
		index := (idx + w.start) % len(w.buffer)
		w.buffer[index] = packet
	} else {
		// insert at index
		for i := w.size - 1; i >= idx; i-- {
			next := (i + w.start + 1) % len(w.buffer)
			current := (i + w.start) % len(w.buffer)
			w.buffer[next] = w.buffer[current]
		}
		index := (idx + w.start) % len(w.buffer)
		w.buffer[index] = packet
	}

	w.size++
}

// send confirmed packets to reader, when receive ack
func (w *ReceiveWindow) confirm(ack uint32, c chan *layers.TCP) {
	idx := 0
	for ; idx < w.size; idx++ {
		index := (idx + w.start) % len(w.buffer)
		packet := w.buffer[index]
		result := compareTCPSeq(packet.Seq, ack)
		if result >= 0 {
			break
		}
		w.buffer[index] = nil
		newExpect := packet.Seq + uint32(len(packet.Payload))
		if w.expectBegin != 0 {
			diff := compareTCPSeq(w.expectBegin, packet.Seq)
			if diff > 0 {
				duplicatedSize := w.expectBegin - packet.Seq
				if duplicatedSize < 0 {
					duplicatedSize += maxTCPSeq
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
		w.expectBegin = newExpect
	}
	w.start = (w.start + idx) % len(w.buffer)
	w.size = w.size - idx
	if compareTCPSeq(w.lastAck, ack) < 0 || w.lastAck == 0 {
		w.lastAck = ack
	}
}

func (w *ReceiveWindow) expand() {
	buffer := make([]*layers.TCP, len(w.buffer)*2)
	end := w.start + w.size
	if end < len(w.buffer) {
		copy(buffer, w.buffer[w.start:w.start+w.size])
	} else {
		copy(buffer, w.buffer[w.start:])
		copy(buffer[len(w.buffer)-w.start:], w.buffer[:end-len(w.buffer)])
	}
	w.start = 0
	w.buffer = buffer
}

// compare two tcp sequences, if seq1 is earlier, return num < 0, if seq1 == seq2, return 0, else return num > 0
func compareTCPSeq(seq1, seq2 uint32) int {
	if seq1 < tcpSeqWindow && seq2 > maxTCPSeq-tcpSeqWindow {
		return int(int32(seq1 + maxTCPSeq - seq2))
	} else if seq2 < tcpSeqWindow && seq1 > maxTCPSeq-tcpSeqWindow {
		return int(int32(seq1 - (maxTCPSeq + seq2)))
	}
	return int(int32(seq1 - seq2))
}

var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"TRACE": true, "OPTIONS": true, "PATCH": true}

// if is first http request packet
func isHTTPRequestData(body []byte) bool {
	if len(body) < 8 {
		return false
	}
	data := body[0:8]
	idx := bytes.IndexByte(data, byte(' '))
	if idx < 0 {
		return false
	}

	method := string(data[:idx])
	return httpMethods[method]
}
