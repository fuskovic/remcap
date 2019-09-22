package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func (c *connection) updateStatus(isUp bool) *connection {
	c.isConnected = isUp
	return c
}

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

func (c *connection) createPCAP() error {
	_, cf, _, ok := runtime.Caller(0)
	if !ok {
		err := "Failed to evaluate caller file"
		log.Printf(err)
		return errors.New(err)
	}
	y, m, d := c.start.Date()
	date := fmt.Sprintf("%d-%d-%d", m, d, y)
	t := c.start.Format(time.Kitchen)

	pcapsDir := filepath.Join(filepath.Dir(cf), "pcaps")
	c.pcap.fileName = fmt.Sprintf("%s@%s.pcap", date, t)
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

	fmt.Printf(`
client-ip : %s
currently-connected : %t
start-time : %v
end-time : %v
pkts-captured : %d`, c.IP, c.isConnected, start, end, c.pktsCaptured)
	fmt.Println()
}

func formatStamp(t time.Time) string {
	y, m, d := t.Date()
	stamp := fmt.Sprintf("%d/%d/%d-%v", m, d, y, t.UTC())
	return stamp
}

func clear() {
	var cmd *exec.Cmd
	run := true
	system := runtime.GOOS

	switch system {
	case "darwin":
		cmd = exec.Command("clear")
	case "linux":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		log.Printf("Clear function not supported on current OS: %s\n", system)
		run = false
	}
	if run {
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}
