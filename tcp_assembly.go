package main

import (
	"github.com/google/gopacket/layers"
	"bytes"
	"time"
	"github.com/google/gopacket"
	"sort"
	"io"
	"sync"
	"strconv"
)

// gopacket provide a tcp connection, however it split one tcp connection into two stream.
// So it is hard to match http request and response. we make our own connection here

const MAX_TCP_SEQ uint32 = 0xFFFFFFFF
const TCP_SEQ_WINDOW = 1 << 10

type TcpAssembler struct {
	connectionDict    map[string]*TcpConnection
	lock              sync.Mutex
	connectionHandler ConnectionHandler
}

func newTcpAssembler(connectionHandler ConnectionHandler) *TcpAssembler {
	return &TcpAssembler{connectionDict:map[string]*TcpConnection{}, connectionHandler:connectionHandler}
}

func (assembler *TcpAssembler) assemble(flow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	src := EndPoint{ip:flow.Src().String(), port:uint16(tcp.SrcPort)}
	dst := EndPoint{ip:flow.Dst().String(), port:uint16(tcp.DstPort)}
	srcString := src.String()
	dstString := dst.String()
	var key string
	if srcString < dstString {
		key = srcString + "-" + dstString
	} else {
		key = dstString + "-" + srcString
	}

	connection := assembler.newConnection(src, dst, key)
	connection.onReceive(src, dst, tcp, timestamp)

	if connection.closed() {
		assembler.deleteConnection(key)
		connection.finish()
	}

	//TODO: cleanup timeout connections
}

func (assembler *TcpAssembler) newConnection(src, dst EndPoint, key string) *TcpConnection {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	connection := assembler.connectionDict[key]
	if (connection == nil) {
		connection = newTcpConnection()
		assembler.connectionDict[key] = connection
		assembler.connectionHandler.handle(src, dst, connection)
	}
	return connection
}

func (assembler *TcpAssembler) deleteConnection(key string) {
	assembler.lock.Lock()
	defer assembler.lock.Unlock()
	delete(assembler.connectionDict, key)
}

func (assembler *TcpAssembler) flushOlderThan(time time.Time) {
	//
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
type  TcpConnection struct {
	upStream      *NetworkStream // stream from client to server
	downStream    *NetworkStream // stream from server to client
	clientId      EndPoint       // the client key(by ip and port)
	lastTimestamp time.Time      // timestamp receive last packet
	isHttp        bool
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
func newTcpConnection() *TcpConnection {
	connection := &TcpConnection{
		upStream:newNetworkStream(),
		downStream:newNetworkStream(),
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

	if len(payload) > 0 {
		sendStream.appendPacket(tcp)
	}

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

func (connection *TcpConnection) closed() bool {
	return connection.upStream.closed && connection.downStream.closed
}

func (connection *TcpConnection) finish() {
	connection.upStream.finish()
	connection.downStream.finish()
}

// tread one-direction tcp data as stream. impl reader closer
type NetworkStream struct {
	buffer []*layers.TCP
	c      chan []byte
	remain []byte
	ignore bool
	closed bool
}

func newNetworkStream() *NetworkStream {
	return &NetworkStream{c:make(chan []byte, 1000)}
}

func (stream *NetworkStream) appendPacket(tcp *layers.TCP) {
	if stream.ignore {
		return
	}
	stream.buffer = append(stream.buffer, tcp)
}

func (stream *NetworkStream) confirmPacket(ack uint32) {
	if stream.ignore {
		return
	}
	var confirmedBuffer, remainedBuffer Buffer
	for _, tcp := range stream.buffer {
		if compareTcpSeq(tcp.Seq, ack) <= 0 {
			confirmedBuffer = append(confirmedBuffer, tcp)
		} else {
			remainedBuffer = append(remainedBuffer, tcp)
		}
	}

	if len(confirmedBuffer) > 0 {
		sort.Sort(confirmedBuffer)
	}
	var lastSeq uint32
	for _, tcp := range confirmedBuffer {
		seq := uint32(tcp.Seq)
		if (seq == lastSeq) {
			continue
		}
		lastSeq = seq
		stream.c <- tcp.Payload
	}

	stream.buffer = remainedBuffer
}

func (stream *NetworkStream) finish() {
	close(stream.c)
}

func (stream *NetworkStream) Read(p []byte) (n int, err error) {
	for len(stream.remain) == 0 {
		data, ok := <-stream.c
		if !ok {
			err = io.EOF
			return
		}
		stream.remain = data
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

type Buffer []*layers.TCP
// impl sort.Interface
// Len is the number of elements in the collection.
func (buffer Buffer) Len() int {
	return len(buffer)
}
// Less reports whether the element with
// index i should sort before the element with index j.
func (buffer Buffer) Less(i, j int) bool {
	return compareTcpSeq(buffer[i].Seq, buffer[j].Seq) < 0
}
// Swap swaps the elements with indexes i and j.
func (buffer Buffer) Swap(i, j int) {
	buffer[i], buffer[j] = buffer[j], buffer[i]
}


// compare two tcp sequences, if seq1 is earlier, return num < 0, if seq1 == seq2, return 0, else return num > 0
func compareTcpSeq(seq1, seq2 uint32) int {
	if seq1 < TCP_SEQ_WINDOW && seq2 > MAX_TCP_SEQ - TCP_SEQ_WINDOW {
		return int(seq1 + MAX_TCP_SEQ - seq2)
	} else if seq2 < TCP_SEQ_WINDOW && seq1 > MAX_TCP_SEQ - TCP_SEQ_WINDOW {
		return int(seq1 - (MAX_TCP_SEQ + seq2))
	}
	return int(int32(seq1 - seq2))
}

var HTTP_METHODS = map[string]bool{"GET":true, "POST":true, "PUT":true, "DELETE":true, "HEAD":true, "TRACE":true,
	"OPTIONS":true, "PATCH":true}


// if is first http request packet
func isHttpRequestData(body []byte) bool {
	if len(body) < 8 {
		return false
	}
	data := body[0:8]
	idx := bytes.IndexByte(data, byte(' '))
	if (idx < 0) {
		return false
	}

	method := string(data[:idx])
	return HTTP_METHODS[method]
}