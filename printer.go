package main

import (
	"fmt"
	"io"
	"os"
)

type printer struct {
	outputQueue chan string
	outputFile  io.WriteCloser
}

var maxOutputQueueLen = 256

func newPrinter() *printer {
	printer := &printer{outputQueue: make(chan string, maxOutputQueueLen), outputFile: os.Stdin}
	printer.start()
	return printer
}

func (printer *printer) send(msg string) {
	if len(printer.outputQueue) == maxOutputQueueLen {
		// skip this msg
		return
	}
	printer.outputQueue <- msg
}

func (printer *printer) start() {
	go printer.print()
}

func (printer *printer) print() {
	for msg := range printer.outputQueue {
		fmt.Println(msg)
	}
	printer.outputFile.Close()
}
