package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	BPF string
	bpf = &cobra.Command{
		Use:   "bpf",
		Short: "Apply Berkely Packet Filters",
		Long: `For more information on Berkeley Packet Filter syntax visit 
		https://yaleman.org/2013/09/11/berkeley-packet-filter-bpf-syntax/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("No filters specified")
			}
			BPF = strings.Join(args, " ")
			return nil
		},
	}
)

func init() {
	remCap.AddCommand(bpf)
}
