package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc/credentials"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/fuskovic/rem-cap/server/cmd"

	"google.golang.org/grpc"
)

func main() {
	cmd.Execute()
	port := fmt.Sprintf(":%s", cmd.Port)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s : %v\n", port, err)
	}

	creds, err := credentials.NewServerTLSFromFile(cmd.CertFile, cmd.PrivateKey)
	if err != nil {
		log.Fatalf("failed to load certificate and or key, err : %v\n", err)
	}
	opts := grpc.Creds(creds)
	s := grpc.NewServer(opts)

	remcappb.RegisterRemCapServer(s, &server{})

	fmt.Printf("remcap server running on %s\n", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
