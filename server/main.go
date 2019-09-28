package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	remcappb "github.com/fuskovic/rem-cap/proto"
	"github.com/fuskovic/rem-cap/server/cmd"

	"google.golang.org/grpc"
)

var port string

func init() {
	cmd.Execute()
	port = fmt.Sprintf(":%s", cmd.Port)
}

func clear() {
	e := &exec.Cmd{ Stdout: os.Stdout }
	system := runtime.GOOS
	if system == "linux" || system == "darwin" {
		e = exec.Command("clear")
	}else if system == "windows"{
		e = exec.Command("cmd", "/c", "cls")
	}else{
		log.Printf("Clear function not supported on current OS: %s\n", system)
		return
	}
	if err := e.Run(); err != nil{
		log.Printf("Failed to clear stdout")
	}
}

func formatStamp(t time.Time) string {
	y, m, d := t.Date()
	return fmt.Sprintf("%d/%d/%d-%v", m, d, y, t.UTC())
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s : %v\n", port, err)
	}

	rcServer := grpc.NewServer()
	remcappb.RegisterRemCapServer(rcServer, &server{})

	fmt.Printf("remcap server running on %s\n", port)
	if err := rcServer.Serve(lis); err != nil {
		log.Fatalf("failed to start server : %v\n", err)
	}
}
