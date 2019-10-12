package main

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/fuskovic/rem-cap/server/cmd"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type server struct {
	clients connections
}

func (s *server) Sniff(stream remcappb.RemCap_SniffServer) error {
	status := make(chan connection)
	go s.logStatus(status)
	c := connection{
		start: time.Now(),
	}

	if err := c.createPCAP(cmd.Out); err != nil {
		log.Fatalf("failed to create pcap for %s : %v\n", c.IP, err)
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			if err := s.sendSummary(c, stream, status); err != nil {
				log.Fatalf("failed to send summary : %v\n", err)
			}
			break
		} else if err != nil {
			ip := net.ParseIP(req.GetExtIP()).String()
			log.Printf("Stream error - %s has disconnected: %v\n", ip, err)
			c.isConnected = false
			status <- c
			return err
		}
		c.IP = req.GetExtIP()
		ii := int(req.GetInterfaceIndex())
		c.addPacket(req.GetData(), layers.LayerTypeEthernet, gopacket.Default, ii)
		c.isConnected = true
		status <- c
	}
	return nil
}

func (s *server) sendSummary(c connection, stream remcappb.RemCap_SniffServer, sc chan connection) error {
	f := c.pcap.file
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	c.end = time.Now()
	c.isConnected = false
	sc <- c

	for index, p := range c.packets {
		if err := w.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
			log.Printf("Failed to write packet %d to %s : %v\n", index, c.pcap.fileName, err)
			return err
		}
	}

	log.Printf("\n%s successfully created\n", c.pcap.fileName)

	if err := stream.SendAndClose(&remcappb.Summary{
		StartTime:       c.start.Unix(),
		EndTime:         c.end.Unix(),
		PacketsCaptured: int64(c.pktsCaptured),
	}); err != nil {
		log.Printf("Failed to send and close : %v\n", err)
		return err
	}
	return nil
}

func (s *server) isRegistered(conn connection) bool {
	for _, client := range s.clients {
		if client.IP == conn.IP {
			return true
		}
	}
	return false
}

func (s *server) logStatus(cc chan connection) {
	for {
		select {
		case c := <-cc:
			clear()
			c.logStats()
		}
	}
}

func clear() {
	var e *exec.Cmd
	system := runtime.GOOS
	if system == "linux" || system == "darwin" {
		e = exec.Command("clear")
	} else if system == "windows" {
		e = exec.Command("cmd", "/c", "cls")
	} else {
		log.Printf("Clear function not supported on current OS: %s\n", system)
		return
	}
	e.Stdout = os.Stdout
	if err := e.Run(); err != nil {
		log.Printf("Failed to clear stdout")
	}
}
