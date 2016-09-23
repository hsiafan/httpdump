package main

import (
	"io"
	"os"
)

type Printer struct {
	outputQueue chan string
	outputFile  io.WriteCloser
}

var maxOutputQueueLen = 4096

func newPrinter() *Printer {
	printer := &Printer{outputQueue: make(chan string, maxOutputQueueLen), outputFile: os.Stdout}
	printer.start()
	return printer
}

func (printer *Printer) send(msg string) {
	if len(printer.outputQueue) == maxOutputQueueLen {
		// skip this msg
		os.Stderr.Write([]byte("message generate too fast, skipped!"))
		return
	}
	printer.outputQueue <- msg
}

func (printer *Printer) start() {
	printerWaitGroup.Add(1)
	go printer.printBackground()
}

func (printer *Printer) printBackground() {
	defer printerWaitGroup.Done()
	defer printer.outputFile.Close()
	for msg := range printer.outputQueue {
		printer.outputFile.Write([]byte(msg))
	}
}

func (printer *Printer) finish() {
	close(printer.outputQueue)
}
