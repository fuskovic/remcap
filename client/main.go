package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/fuskovic/rem-cap/client/cmd"
	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/polds/MyIP"
	"google.golang.org/grpc"
)

func getOpts() grpc.DialOption {
	creds, err := credentials.NewClientTLSFromFile(cmd.CertFile, "")
	if err != nil {
		log.Fatalf("failed to load cert file : %v\n", err)
	}
	opts := grpc.WithTransportCredentials(creds)
	return opts
}

func getNetInterfaces() (int, error) {
	netDevices := cmd.NetworkDevices
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

func listen(pc chan gopacket.Packet, t time.Timer, done chan bool) error {
	tc := t.C

	go func() {
		for {
			select {
			case <-tc:
				done <- true
				break
			}
		}
	}()

	numDesignated, err := getNetInterfaces()
	if err != nil {
		return err
	}

	logSessionStart(t, pc, numDesignated)

	for _, nd := range cmd.NetworkDevices {
		go sniff(nd, pc, tc)
	}

	return nil
}

func sniff(d string, pc chan<- gopacket.Packet, tc <-chan time.Time) {
	handle, err := pcap.OpenLive(d, 65535, true, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to listen to %s : %v\n", d, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(cmd.BPF); err != nil {
		log.Fatalf("failed to apply Berkeley Packet filter :\n%s\n%v\n", cmd.BPF, err)
	}

	conn := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case p := <-conn.Packets():
			pc <- p
		case <-tc:
			break
		}
	}
}

func logSessionStart(t time.Timer, pc chan gopacket.Packet, n int) {
	log.Println("session initialized")

	if len(cmd.BPF) > 0 {
		log.Printf("filter specified : %s\n", cmd.BPF)
	} else {
		log.Println("no filter specified")
	}

	if n > 0 {
		log.Printf("sniffing : %v\n", cmd.NetworkDevices)
	} else {
		log.Println("no device(s) specified - sniffing all")
	}

	go logProgress(t, pc)
}

func logProgress(t time.Timer, pc chan gopacket.Packet) {
	startTime := time.Now()

	go func() {
		for {
			select {
			case <-t.C:
				break
			}
		}
	}()

	for {
		elapsedTime := time.Since(startTime)
		h, m, s := int(elapsedTime.Hours()), int(elapsedTime.Minutes()), int(elapsedTime.Seconds())
		time.Sleep(1 * time.Second)
		fmt.Printf("\r%s", strings.Repeat(" ", 25))
		fmt.Printf("\rprogress : %dh-%dm-%ds/%v", h, m, s, cmd.SeshDuration)
	}
}

func printSummary(start, end time.Time, elapsed time.Duration, captured int64) {
	stat := func(stat string, value interface{}) string {
		return fmt.Sprintf("%s : %v", stat, value)
	}
	fmt.Println(strings.Join([]string{
		"Capture session terminated",
		stat("start", start),
		stat("end", end),
		stat("elapsed", elapsed),
		stat("pkts captured", captured),
	}, "\n"))
}

func main() {
	cmd.Execute()

	addr, _ := myip.GetMyIP()
	ip := net.ParseIP(strings.ReplaceAll(addr, "\n", ""))
	if ip == nil {
		log.Fatalf("invalid ip : %v\n", addr)
	}

	conn, err := grpc.Dial(cmd.Host, getOpts())
	if err != nil {
		log.Fatalf("failed to establish connection with gRPC server : %v\n", err)
	}
	defer conn.Close()

	client := remcappb.NewRemCapClient(conn)
	stream, err := client.Sniff(context.Background())
	if err != nil {
		log.Fatalf("failed to create sniff stream : %v\n", err)
	}

	timer := time.NewTimer(cmd.SeshDuration)
	pc := make(chan gopacket.Packet)
	done := make(chan bool)

	if err := listen(pc, *timer, done); err != nil {
		log.Fatalf("Failed to listen to network interfaces : %v\n", err)
	}

main:
	for {
	sub:
		select {
		case p := <-pc:
			ii := int32(p.Metadata().InterfaceIndex)
			if err := stream.Send(&remcappb.Packet{
				Data:           p.Data(),
				InterfaceIndex: ii,
				ExtIP:          ip.String(),
			}); err == io.EOF {
				log.Println("premature stream close")
				break main
			} else if err != nil {
				log.Printf("failed to stream packet : %v\n", err)
				break sub
			}
		case <-done:
			summary, err := stream.CloseAndRecv()
			if err != nil {
				log.Printf("Failed to receive summary on close")
				break main
			}
			startTime := time.Unix(summary.GetStartTime(), 0)
			endTime := time.Unix(summary.GetEndTime(), 0)
			elapsedTime := endTime.Sub(startTime)
			pktsCaptured := summary.GetPacketsCaptured()
			printSummary(startTime, endTime, elapsedTime, pktsCaptured)
			break main
		}
	}
}
