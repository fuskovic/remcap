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

func (c *connection) addPacket(data []byte, layer gopacket.LayerType, ii int) {
	pkt := gopacket.NewPacket(data, layer, gopacket.Default)
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

func (c *connection) createPCAP(out string) error {
	_, cf, _, ok := runtime.Caller(0)
	if !ok {
		msg := "Failed to evaluate caller file"
		log.Printf(msg)
		return errors.New(msg)
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

func (c *connection) setDefaultOut() {
	y, m, d := c.start.Date()
	date := fmt.Sprintf("%d-%d-%d", m, d, y)
	t := c.start.Format(time.Kitchen)
	c.pcap.fileName = fmt.Sprintf("%s@%s.pcap", date, t)
}

func (c *connection) logStats() {
	start := formatStamp(c.start)
	end := "still capturing"

	if !c.isConnected {
		end = formatStamp(c.end)
	}
	stat := func(stat string, value interface{}) string {
		return fmt.Sprintf("%s : %v", stat, value)
	}

	fmt.Println(strings.Join([]string{
		stat("client-ip", c.IP),
		stat("currently-conected", c.isConnected),
		stat("start-time", start),
		stat("end-time", end),
		stat("pkts-captured", c.pktsCaptured),
	}, "\n"))
}

func formatStamp(t time.Time) string {
	y, m, d := t.Date()
	return fmt.Sprintf("%d/%d/%d-%v", m, d, y, t.UTC())
}
