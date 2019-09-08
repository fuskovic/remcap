package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
)

var maxSize int32 = 655535
var timeOut = 30 * time.Second

func filterSpecified(args []string) bool {
	return len(args) > 0
}

func sniff(d string, c chan gopacket.Packet) {
	handle, err := pcap.OpenLive(d, maxSize, true, timeOut)
	if err != nil {
		log.Fatalf("failed to listen to %s : %v\n", d, err)
	}
	defer handle.Close()

	args := os.Args[1:]

	if filterSpecified(args) {
		var filter string
		filter = strings.Join(args, filter)
		handle.SetBPFFilter(filter)
	}

	conn := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range conn.Packets() {
		time.Sleep(2 * time.Second)
		c <- packet
	}
}

func listen(c chan gopacket.Packet) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("Failed to identify network devices : %v\n", err)
		return err
	}

	for _, device := range devices {
		go sniff(device.Name, c)
	}
	return nil
}

func main() {
	conn, err := grpc.Dial(":50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to establish connection with gRPC server : %v\n", err)
	}
	defer conn.Close()

	client := remcappb.NewRemCapClient(conn)
	stream, err := client.Sniff(context.Background())
	if err != nil {
		log.Fatalf("failed to create sniff stream : %v\n", err)
	}
	pktChan := make(chan gopacket.Packet)
	if err := listen(pktChan); err != nil {
		log.Fatalf("Failed to listen to network interfaces : %v\n", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	for {
		packet := <-pktChan
		if err := gopacket.SerializePacket(buf, opts, packet); err != nil {
			log.Fatalf("failed to serialize packet : %v\n", err)
		}
		if err := stream.Send(&remcappb.Packet{
			Data: buf.Bytes(),
		}); err != nil {
			log.Fatalf("failed to stream packet : %v\n", err)
		}
	}
	summary, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("Failed to receive summary on close")
	}
	startTime := time.Unix(summary.GetStartTime(), 0)
	endTime := time.Unix(summary.GetEndTime(), 0)
	pktsCaptured := summary.GetPacketsCaptured()
	log.Printf(`Session completed
				Session start time : %s
				Session end time   : %s
				Packets captured   : %d`, startTime, endTime, pktsCaptured)
}