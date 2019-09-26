package main

import (
	"fmt"
	"log"
	"net"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/fuskovic/rem-cap/server/cmd"

	"google.golang.org/grpc"
)

var port string

func init() {
	cmd.Execute()
	port = fmt.Sprintf(":%s", cmd.Port)
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on 50051 : %v\n", err)
	}

	rcServer := grpc.NewServer()
	remcappb.RegisterRemCapServer(rcServer, &server{})

	fmt.Printf("remcap server running on %s\n", port)
	if err := rcServer.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
