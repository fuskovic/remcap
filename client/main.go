package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/fuskovic/rem-cap/client/cmd"
	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
)

var (
	maxSize  int32 = 65535
	timeOut        = 30 * time.Second
	seshTime time.Duration
	bpf      string
)

func init() {
	cmd.Execute()
	seshTime = cmd.SeshDuration
	bpf = cmd.BPF
}

func sniff(d string, pc chan gopacket.Packet, t time.Timer) {
	handle, err := pcap.OpenLive(d, maxSize, true, timeOut)
	if err != nil {
		log.Fatalf("failed to listen to %s : %v\n", d, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpf); err != nil {
		log.Fatalf("failed to apply Berkeley Packet filter :\n%s\n%v\n", bpf, err)
	}

	conn := gopacket.NewPacketSource(handle, handle.LinkType())
	c := conn.Packets()
	for range c {
		select {
		case <-t.C:
			close(c)
			break
		case packet := <-c:
			pc <- packet
		}
	}
}

func listen(pc chan gopacket.Packet, t time.Timer) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("Failed to identify network devices : %v\n", err)
		return err
	}

	for _, device := range devices {
		go sniff(device.Name, pc, t)
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

	timer := time.NewTimer(seshTime)
	pc := make(chan gopacket.Packet)

	if err := listen(pc, *timer); err != nil {
		log.Fatalf("Failed to listen to network interfaces : %v\n", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	for {
		select {
		case <-timer.C:
			close(pc)
			summary, err := stream.CloseAndRecv()
			if err != nil {
				log.Fatalf("Failed to receive summary on close")
			}
			startTime := time.Unix(summary.GetStartTime(), 0)
			endTime := time.Unix(summary.GetEndTime(), 0)
			pktsCaptured := summary.GetPacketsCaptured()
			fmt.Printf("Session completed\nstart : %s\nend : %s\nPackets captured : %d\n", startTime, endTime, pktsCaptured)
			break
		case packet := <-pc:
			if err := gopacket.SerializePacket(buf, opts, packet); err != nil {
				log.Fatalf("failed to serialize packet : %v\n", err)
			}
			ii := int32(packet.Metadata().InterfaceIndex)
			if err := stream.Send(&remcappb.Packet{
				Data:           buf.Bytes(),
				InterfaceIndex: ii,
			}); err != nil {
				log.Fatalf("failed to stream packet : %v\n", err)
			}
		}
	}
}
