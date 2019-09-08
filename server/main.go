package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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

type server struct{}

func (s *server) Sniff(stream remcappb.RemCap_SniffServer) error {
	streamStarted := time.Now()

	_, cf, _, ok := runtime.Caller(0)
	if !ok {
		err := "Failed to evaluate caller file"
		log.Printf(err)
		return errors.New(err)
	}

	pcapsDir := filepath.Join(filepath.Dir(cf), "pcaps")
	fileName := fmt.Sprintf("%s.pcap", streamStarted.String())
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
			for index, packet := range packets {
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("failed to write packet %d to %s : %v\n", index, fileName, err)
					return err
				}
			}
			log.Printf("%s successfully created\n", fileName)

			return stream.SendAndClose(&remcappb.Summary{
				StartTime:       streamStarted.Unix(),
				EndTime:         time.Now().Unix(),
				PacketsCaptured: int64(len(packets)),
			})
		}
		if err != nil {
			log.Printf("Error processing client stream : %v\n", err)
			return err
		}
		pkt := gopacket.NewPacket(req.GetData(), layers.LayerTypeEthernet, gopacket.Default)
		packets = append(packets, pkt)
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen on 50051 : %v\n", err)
	}

	s := grpc.NewServer()
	remcappb.RegisterRemCapServer(s, &server{})

	fmt.Println("starting gRPC server on 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
