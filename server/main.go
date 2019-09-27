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
	var cmd *exec.Cmd
	run := true
	system := runtime.GOOS

	switch system {
	case "darwin":
		cmd = exec.Command("clear")
	case "linux":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		log.Printf("Clear function not supported on current OS: %s\n", system)
		run = false
	}
	if run {
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func formatStamp(t time.Time) string {
	y, m, d := t.Date()
	stamp := fmt.Sprintf("%d/%d/%d-%v", m, d, y, t.UTC())
	return stamp
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
