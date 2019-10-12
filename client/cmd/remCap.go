package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
)

var (
	NetworkDevices          []string
	seconds, minutes, hours int64
	SeshDuration            time.Duration
	Host, CertFile          string
	EnabledTLS              bool

	minSeshTime = 5 * time.Second

	remCap = &cobra.Command{
		Use:   "remcap",
		Short: "Remote Packet Capture",
		Long:  `Remcap is a remote network monitoring tool.`,
		RunE: func(cmd *cobra.Command, input []string) error {
			if err := getSeshTime(); err != nil {
				return err
			}

			if err := setHost(); err != nil {
				return err
			}
			return nil
		},
	}
)

func getSeshTime() error {
	args := fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	d, err := time.ParseDuration(args)
	if err != nil {
		return err
	}
	if d < minSeshTime {
		return fmt.Errorf("Invalid session duration : %v - Session must be at least 5s long\n", d)
	}
	SeshDuration = d
	return nil
}

func setHost() error {
	if len(Host) == 0 {
		return fmt.Errorf("Please specify a host remcap server example : --host <ip>:<port>")
	}
	return nil
}

func Execute() {
	if err := remCap.Execute(); err != nil {
		log.Fatalf("....remcap exiting")
	}

	if err := bpf.Execute(); err != nil {
		log.Fatalf("....remcap exiting")
	}
}

func init() {
	remCap.PersistentFlags().Int64VarP(&seconds, "seconds", "s", 0, "Amount of seconds to run capture")
	remCap.PersistentFlags().Int64VarP(&minutes, "minutes", "m", 0, "Amount of minutes to run capture")
	remCap.PersistentFlags().Int64Var(&hours, "hours", 0, "Amount of hours to run capture")
	remCap.PersistentFlags().StringSliceVarP(&NetworkDevices, "devices", "d", []string{}, "network interface names")
	remCap.PersistentFlags().StringVar(&Host, "host", "", "Address to stream packets to")
	remCap.PersistentFlags().BoolVar(&EnabledTLS, "enable", true, "Enable SSL/TLS encryption")
	remCap.PersistentFlags().StringVar(&CertFile, "cert", "", "path to trust cert from CA")
}
