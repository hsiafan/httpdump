package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strconv"
	"sync"
	_ "net/http/pprof"
	"net/http"
)

var waitGroup sync.WaitGroup
var printerWaitGroup sync.WaitGroup

func openFile(pcapFile string) *pcap.Handle {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal("Open file", pcapFile, "error:", err)
	}
	return handle
}

func openDevice(device string) *pcap.Handle {
	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatal("Open device", device, "error:", err)
	}
	return handle
}

// user config for http traffics
type Config struct {
	level      string
	filterIP   string
	filterPort uint16
	domain     string
	urlPath    string
	force      bool
	pretty     bool
}

func parseFilter(filter string) (string, uint16) {
	filter = strings.TrimSpace(filter)
	idx := strings.Index(filter, ":")
	if idx < 0 {
		return filter, 0
	}
	port, err := strconv.Atoi(filter[idx + 1:])
	if err != nil {
		log.Fatalln("Not a port num: " + filter[idx + 1:])
		return filter[:idx], 0
	}
	return filter[:idx], uint16(port)
}

func listenOneSource(handle *pcap.Handle) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	return packets
}

// set packet capture filter, by ip and port
func setDeviceFilter(handle *pcap.Handle, filterIP string, filterPort uint16) {
	var bpfFilter = "tcp"
	if filterPort != 0 {
		bpfFilter += " port " + strconv.Itoa(int(filterPort))
	}
	if filterIP != "" {
		bpfFilter += " ip host " + filterIP
	}
	var err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Set capture filter failed, ", err)
	}
}

// adapter multi channels to one channel. used to aggregate multi devices data
func mergeChannel(channels []chan gopacket.Packet) chan gopacket.Packet {
	var channel = make(chan gopacket.Packet)
	for _, ch := range channels {
		go func(c chan gopacket.Packet) {
			for packet := range c {
				channel <- packet
			}
		}(ch)
	}
	return channel
}

func openSingleDevice(device string, filterIP string, filterPort uint16) (localPackets chan gopacket.Packet, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			switch x := msg.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			localPackets = nil
		}
	}()
	var handle = openDevice(device)
	setDeviceFilter(handle, filterIP, filterPort)
	localPackets = listenOneSource(handle)
	return
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var level = flagSet.String("level", "header", "Print level, url(only url) | header(http headers) | all(headers, and textuary http body)")
	var filePath = flagSet.String("file", "", "Read from pcap file. If not specified, will capture from network devices")
	var device = flagSet.String("device", "any", "Which network interface to capture. If any, capture all interface traffics")
	var filter = flagSet.String("filter", "", "Filter by ip/port, format: [ip][:port], eg: 192.168.122.46:50792, 192.168.122.46, :50792")
	var domain = flagSet.String("domain", "", "Filter by request domain, suffix match")
	var urlPath = flagSet.String("urlPath", "", "Filter by request url path, contains match")
	var force = flagSet.Bool("force", false, "Force print unknown content-type http body even if it seems not to be text content")
	var pretty = flagSet.Bool("pretty", false, "Try to pretify json output")
	flagSet.Parse(os.Args[1:])

	filterIP, filterPort := parseFilter(*filter)

	var config = &Config{
		level:      *level,
		filterIP:   filterIP,
		filterPort: filterPort,
		domain:     *domain,
		urlPath:    *urlPath,
		force:      *force,
		pretty:     *pretty,
	}

	var packets chan gopacket.Packet
	if *filePath != "" {
		// read from pcap file
		var handle = openFile(*filePath)
		packets = listenOneSource(handle)
	} else if *device == "any" && runtime.GOOS != "linux" {
		// capture all device
		// Only linux 2.2+ support any interface. we have to list all network device and listened on them all
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal("Find device error:", err)
		}
		var packetsSlice = make([]chan gopacket.Packet, len(interfaces))
		for _, itf := range interfaces {
			localPackets, err := openSingleDevice(itf.Name, filterIP, filterPort)
			if err != nil {
				fmt.Fprint(os.Stderr, "Open device", device, "error:", err)
				continue
			}
			packetsSlice = append(packetsSlice, localPackets)
		}
		packets = mergeChannel(packetsSlice)
	} else if *device != "" {
		// capture one device
		var err error
		packets, err = openSingleDevice(*device, filterIP, filterPort)
		if err != nil {
			log.Fatal("Listen on device", *device, "failed, error:", err)
		}
	} else {
		log.Fatal("Empty device")
	}

	var handler = &HttpConnectionHandler{
		config:  config,
		printer: newPrinter(),
	}
	var assembler = newTcpAssembler(handler)
	assembler.filterIp = filterIP
	assembler.filterPort = filterPort
	var ticker = time.Tick(time.Second * 30)

	outer:
	for {
		select {
		case packet := <-packets:
		// A nil packet indicates the end of a pcap file.
			if packet == nil {
				break outer
			}

		// only assembly tcp/ip packets
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
					packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			var tcp = packet.TransportLayer().(*layers.TCP)

			assembler.assemble(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
		// flush connections that haven't seen activity in the past 2 minutes.
			assembler.flushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

	assembler.finishAll()
	waitGroup.Wait()
	handler.printer.finish()
	printerWaitGroup.Wait()
}
