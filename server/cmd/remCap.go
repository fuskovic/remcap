package cmd

import (
	"fmt"
	"log"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	Port, Out, CertFile, PrivateKey string

	remCap = &cobra.Command{
		Use:   "remcap",
		Short: "Remote Packet Capture",
		Long:  `Remcap is a remote network monitoring tool.`,
		RunE: func(cmd *cobra.Command, input []string) error {
			ok, err := isValid(Port)
			if !ok || err != nil {
				return err
			}
			return nil
		},
	}
)

func isValid(p string) (bool, error) {
	if p == "" {
		return false, fmt.Errorf("No port specified")
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return false, err
	}
	if port >= 0 && port < 65536 {
		return true, nil
	}
	return false, fmt.Errorf("%s is not a valid port\n", Port)
}

func Execute() {
	if err := remCap.Execute(); err != nil {
		log.Fatalf("....remcap exiting")
	}
}

func init() {
	remCap.PersistentFlags().StringVarP(&Port, "port", "p", "", "Port to start remcap server")
	remCap.PersistentFlags().StringVarP(&Out, "out", "o", "", "Specify out file name")
	remCap.PersistentFlags().StringVar(&CertFile, "cert", "", "Path to signed certificate")
	remCap.PersistentFlags().StringVar(&PrivateKey, "key", "", "Path to server private key")
	remCap.MarkFlagRequired("port")
}
