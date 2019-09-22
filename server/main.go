package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"google.golang.org/grpc"
)

var maxSize uint32 = 655535

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

type connection struct {
	IP           string
	isConnected  bool
	pktsCaptured int64
	start, end   time.Time
}

func (c *connection) updateStatus(status bool) *connection {
	c.isConnected = status
	return c
}

func (c *connection) logStats() {
	var start, end string

	start = formatStamp(c.start)
	if !c.isConnected {
		end = formatStamp(c.end)
	} else {
		end = "still capturing"
	}

	fmt.Printf(`
client-ip : %s
currently-connected : %t
start-time : %v
end-time : %v
pkts-captured : %d`, c.IP, c.isConnected, start, end, c.pktsCaptured)
	fmt.Println()
}

type connections []connection

type server struct {
	clientConns connections
}

func IPsMatch(firstIP, secondIP string) bool {
	return firstIP == secondIP
}

func (s *server) isRegistered(conn connection) bool {
	for _, client := range s.clientConns {
		if IPsMatch(client.IP, conn.IP) {
			return true
		}
	}
	return false
}

func formatStamp(t time.Time) string {
	y, m, d := t.Date()
	stamp := fmt.Sprintf("%d/%d/%d-%v", m, d, y, t.UTC())
	return stamp
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

func (s *server) Sniff(stream remcappb.RemCap_SniffServer) error {
	streamStarted := time.Now()
	status := make(chan connection)
	go s.logStatus(status)
	c := connection{
		start: streamStarted,
	}

	_, cf, _, ok := runtime.Caller(0)
	if !ok {
		err := "Failed to evaluate caller file"
		log.Printf(err)
		return errors.New(err)
	}
	y, m, d := streamStarted.Date()
	date := fmt.Sprintf("%d-%d-%d", m, d, y)
	t := streamStarted.Format(time.Kitchen)

	pcapsDir := filepath.Join(filepath.Dir(cf), "pcaps")
	fileName := fmt.Sprintf("%s@%s.pcap", date, t)
	path := filepath.Join(pcapsDir, fileName)

	f, err := os.Create(path)
	if err != nil {
		log.Printf("failed to create %s\n", fileName)
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(maxSize, layers.LinkTypeEthernet)
	var packets []gopacket.Packet

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			c.end = time.Now()
			status <- *c.updateStatus(false)
			for index, packet := range packets {
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("Failed to write packet %d to %s : %v\n", index, fileName, err)
				}
			}
			log.Printf("\n%s successfully created\n", fileName)
			if err := stream.SendAndClose(&remcappb.Summary{
				StartTime:       c.start.Unix(),
				EndTime:         c.end.Unix(),
				PacketsCaptured: int64(c.pktsCaptured),
			}); err != nil {
				log.Printf("Failed to send session summary : %v\n", err)
				return err
			}
			break
		}
		if err != nil {
			ip := net.ParseIP(req.GetExtIP()).String()
			log.Printf("Stream error - %s has disconnected: %v\n", ip, err)
			status <- *c.updateStatus(false)
			return err
		}
		c.IP = req.GetExtIP()
		status <- *c.updateStatus(true)

		pkt := gopacket.NewPacket(req.GetData(), layers.LayerTypeEthernet, gopacket.Default)
		capLen := len(req.GetData())
		pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  capLen,
			Length:         capLen,
			InterfaceIndex: int(req.GetInterfaceIndex()),
		}
		packets = append(packets, pkt)
		c.pktsCaptured = int64(len(packets))
	}
	return nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen on 50051 : %v\n", err)
	}
	var s server
	rcServer := grpc.NewServer()
	remcappb.RegisterRemCapServer(rcServer, &s)

	fmt.Println("remcap server running 50051")
	if err := rcServer.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
