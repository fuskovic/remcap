package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
)

type connection struct {
	IP           string
	isConnected  bool
	pktsCaptured int64
	start, end   time.Time
	pcap         struct {
		fileName string
		file     *os.File
	}
	packets []gopacket.Packet
}

type connections []connection

func (c *connection) addPacket(data []byte, layer gopacket.LayerType, opts gopacket.DecodeOptions, ii int) {
	pkt := gopacket.NewPacket(data, layer, opts)
	capLen := len(data)

	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  capLen,
		Length:         capLen,
		InterfaceIndex: ii,
	}
	c.packets = append(c.packets, pkt)
	c.pktsCaptured++
}

func (c *connection) setDefaultOut() {
	y, m, d := c.start.Date()
	date := fmt.Sprintf("%d-%d-%d", m, d, y)
	t := c.start.Format(time.Kitchen)
	c.pcap.fileName = fmt.Sprintf("%s@%s.pcap", date, t)
}

func (c *connection) createPCAP(out string) error {
	_, cf, _, ok := runtime.Caller(0)
	if !ok {
		err := "Failed to evaluate caller file"
		log.Printf(err)
		return errors.New(err)
	}
	pcapsDir := filepath.Join(filepath.Dir(cf), "pcaps")
	if len(out) == 0 {
		c.setDefaultOut()
	} else {
		c.pcap.fileName = fmt.Sprintf("%s.pcap", out)
	}

	path := filepath.Join(pcapsDir, c.pcap.fileName)

	f, err := os.Create(path)
	if err != nil {
		log.Printf("failed to create %s\n", c.pcap.fileName)
		return err
	}
	c.pcap.file = f
	return nil
}

func (c *connection) logStats() {
	start := formatStamp(c.start)
	end := "still capturing"

	if !c.isConnected {
		end = formatStamp(c.end)
	}

	fmt.Printf(strings.Join([]string{
		fmt.Sprintf("client-ip : %s\n", c.IP),
		fmt.Sprintf("currently-conected : %t\n", c.isConnected),
		fmt.Sprintf("start-time : %s\n", start),
		fmt.Sprintf("end-time : %s\n", end),
		fmt.Sprintf("pkts-captured : %d\n", c.pktsCaptured),
	}, ""))
}
