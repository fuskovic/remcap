package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/fuskovic/rem-cap/client/cmd"
	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/polds/MyIP"
	"google.golang.org/grpc"
)

var (
	netDevices        []string
	maxSize           int32
	timeOut, seshTime time.Duration
	bpf, ip           string
)

func init() {
	cmd.Execute()
	seshTime = cmd.SeshDuration
	bpf = cmd.BPF
	netDevices = cmd.NetworkDevices
	timeOut = 30 * time.Second
	maxSize = 65535
	addr, err := myip.GetMyIP()
	if err != nil {
		log.Printf("failed to get this ip : %v\n", err)
	}
	ip = strings.ReplaceAll(addr, " ", "")
}

func filterSpecified() bool {
	return len(bpf) > 0
}

func devicesDesignated(n int) bool {
	return n > 0
}

func getNetInterfaces() (int, error) {
	if len(netDevices) == 0 {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Printf("Failed to identify network devices : %v\n", err)
			return 0, err
		}
		for _, d := range devices {
			netDevices = append(netDevices, d.Name)
		}
		return 0, nil
	}
	return len(netDevices), nil
}

func logProgress(t time.Timer, pc chan gopacket.Packet) {
	startTime := time.Now()

	go func() {
	time_logger:
		for {
			select {
			case <-t.C:
				break time_logger
			}
		}
	}()

	for {
		elapsedTime := time.Since(startTime)
		h, m, s := int(elapsedTime.Hours()), int(elapsedTime.Minutes()), int(elapsedTime.Seconds())
		time.Sleep(1 * time.Second)
		fmt.Printf("\r%s", strings.Repeat(" ", 25))
		fmt.Printf("\rprogress : %dh-%dm-%ds/%v", h, m, s, seshTime)
	}
}

func logSessionStart(t time.Timer, pc chan gopacket.Packet, n int) {
	log.Println("session initialized")

	if filterSpecified() {
		log.Printf("filter specified : %s\n", bpf)
	} else {
		log.Println("no filter specified")
	}

	if devicesDesignated(n) {
		log.Printf("sniffing : %v\n", netDevices)
	} else {
		log.Println("no device(s) specified - sniffing all")
	}

	go logProgress(t, pc)
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

func listen(pc chan gopacket.Packet, t time.Timer, done chan bool) error {
	tc := t.C

	go func() {
	listener:
		for {
			select {
			case <-tc:
				done <- true
				break listener
			}
		}
		return
	}()

	numDesignated, err := getNetInterfaces()
	if err != nil {
		return err
	}

	logSessionStart(t, pc, numDesignated)

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
	done := make(chan bool)

	if err := listen(pc, *timer, done); err != nil {
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
				ExtIP:          ip,
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
			elapsedTime := endTime.Sub(startTime)
			pktsCaptured := summary.GetPacketsCaptured()
			fmt.Printf(`
Capture session terminated
start : %s
end : %s
elapsed : %v
Packets captured : %d
`, startTime, endTime, elapsedTime, pktsCaptured)
			break main_proc
		}
	}
}
