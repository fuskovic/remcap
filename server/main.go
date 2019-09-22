package main

import (
	"fmt"
	"log"
	"net"

	remcappb "github.com/fuskovic/rem-cap/proto"

	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen on 50051 : %v\n", err)
	}

	rcServer := grpc.NewServer()
	remcappb.RegisterRemCapServer(rcServer, &server{})

	fmt.Println("remcap server running 50051")
	if err := rcServer.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
