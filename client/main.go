package main

import (
	"context"
	"io"
	"log"
	"time"

	"github.com/fuskovic/rem-cap/client/cmd"
	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
)

var (
	netDevices []string
	maxSize    int32
	timeOut    time.Duration
	seshTime   time.Duration
	bpf        string
)

func init() {
	cmd.Execute()
	seshTime = cmd.SeshDuration
	bpf = cmd.BPF
	netDevices = cmd.NetworkDevices
	timeOut = 30 * time.Second
	maxSize = 65535
}

func sniff(d string, pc chan<- gopacket.Packet, tc <-chan time.Time) {
	handle, err := pcap.OpenLive(d, maxSize, true, timeOut)
	if err != nil {
		log.Fatalf("failed to listen to %s : %v\n", d, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpf); err != nil {
		log.Fatalf("failed to apply Berkeley Packet filter :\n%s\n%v\n", bpf, err)
	}

	conn := gopacket.NewPacketSource(handle, handle.LinkType())

sniffer:
	for {
		select {
		case p := <-conn.Packets():
			pc <- p
		case <-tc:
			break sniffer
		}
	}
}

func listen(pc chan gopacket.Packet, tc <-chan time.Time, done chan bool) error {
	if len(netDevices) == 0 {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Printf("Failed to identify network devices : %v\n", err)
			return err
		}
		for _, d := range devices {
			netDevices = append(netDevices, d.Name)
		}
	}

	go func() {
	validator:
		for {
			select {
			case <-tc:
				done <- true
				break validator
			}
		}
		return
	}()

	for _, nd := range netDevices {
		go sniff(nd, pc, tc)
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
	tc := timer.C
	done := make(chan bool)

	if err := listen(pc, tc, done); err != nil {
		log.Fatalf("Failed to listen to network interfaces : %v\n", err)
	}

main_proc:
	for {
	sub_proc:
		select {
		case p := <-pc:
			ii := int32(p.Metadata().InterfaceIndex)
			if err := stream.Send(&remcappb.Packet{
				Data:           p.Data(),
				InterfaceIndex: ii,
			}); err == io.EOF {
				log.Println("premature stream close")
				break main_proc
			} else if err != nil {
				log.Printf("failed to stream packet : %v\n", err)
				break sub_proc
			}
		case <-done:
			summary, err := stream.CloseAndRecv()
			if err != nil {
				log.Printf("Failed to receive summary on close")
				break main_proc
			}
			startTime := time.Unix(summary.GetStartTime(), 0)
			endTime := time.Unix(summary.GetEndTime(), 0)
			pktsCaptured := summary.GetPacketsCaptured()
			log.Printf("Session completed\nstart : %s\nend : %s\nPackets captured : %d\n", startTime, endTime, pktsCaptured)
			break main_proc
		}
	}
}
