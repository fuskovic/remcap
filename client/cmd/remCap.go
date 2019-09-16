package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
)

var (
	seconds, minutes, hours int64
	SeshDuration            time.Duration
	minTime                 = 5 * time.Second
	help                    = `

Remcap is a packet capturing tool that records 
and sends network traffic information to a remote host 
for a specified period of time.

Usage:
  remcap [flags]
  remcap [command]

Available Commands:
  bpf         Apply Berkely Packet Filters
  help        Help about any command

Flags:
  -h, --help          help for remcap
  -r, --hours int     Amount of hours to run capture
  -m, --minutes int   Amount of minutes to run capture
  -s, --seconds int   Amount of seconds to run capture

Use "remcap [command] --help" for more information about a command.`

	remCap = &cobra.Command{
		Use:   "remcap",
		Short: "Remote Packet Capture",
		Long: `
Remcap is a packet capturing tool that records 
and sends network traffic information to a remote host 
for a specified period of time.`,
		Run: func(cmd *cobra.Command, input []string) {
			args := fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
			d, err := time.ParseDuration(args)
			if err != nil {
				fmt.Printf("\n%v%s\n", err, help)
				return
			}
			if d < minTime {
				fmt.Printf("\nInvalid session duration : %v\nSession must be at least 30s long%s\n", d, help)
				return
			}
			log.Printf("Session duration set for : %v\n", d)
			SeshDuration = d
		},
	}
)

func Execute() {
	remCap.Execute()
}

func init() {
	remCap.PersistentFlags().Int64VarP(&seconds, "seconds", "s", 0, "Amount of seconds to run capture")
	remCap.PersistentFlags().Int64VarP(&minutes, "minutes", "m", 0, "Amount of minutes to run capture")
	remCap.PersistentFlags().Int64VarP(&hours, "hours", "r", 0, "Amount of hours to run capture")
}
