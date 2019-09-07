package main

import (
	"fmt"
	"strings"
	"time"
	"log"
	"os"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
)

var maxSize uint32 = 655535

func filterSpecified(args []string) bool{
	return len(args) > 0
}

func inspectLinkLayer(p gopacket.Packet){
	fmt.Printf("Link layer contents : %s\n", p.LinkLayer().LayerContents())
	fmt.Printf("Link layer payload : %s\n", p.LinkLayer().LayerPayload())
	fmt.Printf("Link layer data : %s\n", p.LinkLayer().LayerType())
	fmt.Printf("Link layer flow : %s\n", p.LinkLayer().LinkFlow())
}

func inspectNetworkLayer(p gopacket.Packet){
	fmt.Printf("Network layer contents : %s\n", p.NetworkLayer().LayerContents())
	fmt.Printf("Network layer payload : %s\n", p.NetworkLayer().LayerPayload())
	fmt.Printf("Network layer data : %s\n", p.NetworkLayer().LayerType())
	fmt.Printf("Network layer flow : %s\n", p.NetworkLayer().NetworkFlow())
}

func inspectTransportLayer(p gopacket.Packet){
	fmt.Printf("Transport layer contents : %s\n", p.TransportLayer().LayerContents())
	fmt.Printf("Transport layer payload : %s\n", p.TransportLayer().LayerPayload())
	fmt.Printf("Transport layer data : %s\n", p.TransportLayer().LayerType())
	fmt.Printf("Transport layer flow : %s\n", p.TransportLayer().TransportFlow())
}

func inspectApplicationLayer(p gopacket.Packet){
	fmt.Printf("Application layer contents : %s\n", p.ApplicationLayer().LayerContents())
	fmt.Printf("Application layer payload : %s\n", p.ApplicationLayer().LayerPayload())
	fmt.Printf("Application layer data : %s\n", p.ApplicationLayer().LayerType())
	fmt.Printf("Application layer flow : %s\n", p.ApplicationLayer().Payload())
}

func inspect(p gopacket.Packet){
	inspectLinkLayer(p)
	inspectNetworkLayer(p)
	inspectTransportLayer(p)
	inspectApplicationLayer(p)
}

func sniff(d string, c chan gopacket.Packet){
	handle, err := pcap.OpenLive(d, 655535, true, 30 * time.Second)
	if err != nil{
		log.Fatalf("failed to listen to %s : %v\n", d, err)
	}
	defer handle.Close()

	args := os.Args[1:]

	if filterSpecified(args){
		var filter string
		filter = strings.Join(args, filter)
		handle.SetBPFFilter(filter)
	}

	conn := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range conn.Packets(){
		time.Sleep(2 * time.Second)
		c <- packet
	}
}

func main(){
	devices, err := pcap.FindAllDevs()
	if err != nil{
		log.Fatalf("Failed to identify network devices : %v\n", err)
	}

	stream := make(chan gopacket.Packet)

	for _, device := range devices{
		go sniff(device.Name, stream)
	}

	f, err := os.Create("test.pcap")
	if err != nil{
		log.Fatalf("failed to create test.pcap")
	}
	defer f.Close()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(maxSize, layers.LinkTypeEthernet)


	for {
		packet := <-stream
		if err := gopacket.SerializePacket(buf, opts, packet); err != nil{
			log.Printf("failed to serialize packet : %v\n", err)
		}
		fmt.Printf("packet : %s\n", buf.Bytes())
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}