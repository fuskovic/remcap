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
	myip "github.com/polds/MyIP"
	"google.golang.org/grpc"
)

func getOpts(shouldSecure bool) grpc.DialOption {
	if shouldSecure {
		creds, err := credentials.NewClientTLSFromFile(cmd.CertFile, "")
		if err != nil {
			log.Fatalf("failed to load cert file : %v\n", err)
		}
		opts := grpc.WithTransportCredentials(creds)
		return opts
	}
	return grpc.WithInsecure()
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

func listen(ctx context.Context, pc chan gopacket.Packet) error {
	numDesignated, err := getNetInterfaces()
	if err != nil {
		return err
	}

	logSessionStart(ctx, pc, numDesignated)

	for _, nd := range cmd.NetworkDevices {
		go sniff(ctx, nd, pc)
	}

	return nil
}

func sniff(ctx context.Context, d string, pc chan<- gopacket.Packet) {
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
		case <-ctx.Done():
			break
		}
	}
}

func logSessionStart(ctx context.Context, pc chan gopacket.Packet, n int) {
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

	go logProgress(ctx, pc)
}

func logProgress(ctx context.Context, pc chan gopacket.Packet) {
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			break
		default:
			elapsedTime := time.Since(startTime)
			time.Sleep(500 * time.Millisecond)
			h, m, s := int(elapsedTime.Hours()), int(elapsedTime.Minutes()), int(elapsedTime.Seconds())
			fmt.Printf("\r%s", strings.Repeat(" ", 25))
			fmt.Printf("\rprogress : %dh-%dm-%ds/%v", h, m, s, cmd.SeshDuration)
		}
	}
}

func printSummary(start, end time.Time, elapsed time.Duration, captured int64) {
	stat := func(stat string, value interface{}) string {
		return fmt.Sprintf("%s : %v", stat, value)
	}
	fmt.Println(strings.Join([]string{
		"\nCapture session terminated",
		stat("start", start),
		stat("end", end),
		stat("elapsed", elapsed),
		stat("pkts captured", captured),
	}, "\n"))
}

func main() {
	cmd.Execute()
	parentCtx := context.Background()
	ctx, cancel := context.WithTimeout(parentCtx, cmd.SeshDuration)
	defer cancel()

	addr, _ := myip.GetMyIP()
	ip := net.ParseIP(strings.ReplaceAll(addr, "\n", ""))
	if ip == nil {
		log.Fatalf("invalid ip : %v\n", addr)
	}

	conn, err := grpc.Dial(cmd.Host, getOpts(cmd.IsSecure))
	if err != nil {
		log.Fatalf("failed to establish connection with gRPC server : %v\n", err)
	}
	defer conn.Close()

	client := remcappb.NewRemCapClient(conn)
	stream, err := client.Sniff(parentCtx)
	if err != nil {
		log.Fatalf("failed to create sniff stream : %v\n", err)
	}

	pc := make(chan gopacket.Packet)

	if err := listen(ctx, pc); err != nil {
		log.Fatalf("Failed to listen to network interfaces : %v\n", err)
	}

loop:
	for {
		select {
		case p := <-pc:
			ii := int32(p.Metadata().InterfaceIndex)
			if err := stream.Send(&remcappb.Packet{
				Data:           p.Data(),
				InterfaceIndex: ii,
				ExtIP:          ip.String(),
			}); err == io.EOF {
				log.Println("premature stream close")
			} else if err != nil {
				log.Printf("failed to stream packet : %v\n", err)
			}
		case <-ctx.Done():
			summary, err := stream.CloseAndRecv()
			if err != nil {
				log.Printf("Failed to receive summary on close : %v\n", err)
				break loop
			}
			startTime := time.Unix(summary.GetStartTime(), 0)
			endTime := time.Unix(summary.GetEndTime(), 0)
			elapsedTime := endTime.Sub(startTime)
			pktsCaptured := summary.GetPacketsCaptured()
			printSummary(startTime, endTime, elapsedTime, pktsCaptured)
			break loop
		}
	}
}
