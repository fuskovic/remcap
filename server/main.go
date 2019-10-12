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

func configServer(isEnabled bool) *grpc.Server {
	if isEnabled {
		certFile := cmd.CertFile  //server.crt
		keyFile := cmd.PrivateKey //server.pem

		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to load certificate and or key, err : %v\n", err)
		}
		opts := grpc.Creds(creds)
		return grpc.NewServer(opts)
	}
	return grpc.NewServer()
}

func main() {
	cmd.Execute()
	port := fmt.Sprintf(":%s", cmd.Port)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s : %v\n", port, err)
	}

	s := configServer(cmd.EnabledTLS)
	remcappb.RegisterRemCapServer(s, &server{})

	fmt.Printf("remcap server running on %s\n", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
