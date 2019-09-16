package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	BPF     string
	bpfDesc = `
bpf ( Berkely Packet Filters ) enable you to filter
network traffic by destination and/or source IP, 
port-ranges, protocols, etc.... `
	bpfEx = `
remcap -m 30 bpf src portrange 80-88 tcp dst portrange 1501-1549

remcap -m 30 bpf udp and src port 2005 ip6 and tcp and src port 80

For more information on Berkeley Packet Filter syntax visit 
https://yaleman.org/2013/09/11/berkeley-packet-filter-bpf-syntax/
`

	bpf = &cobra.Command{
		Use:     "bpf",
		Short:   "Apply Berkely Packet Filters",
		Long:    bpfDesc,
		Example: bpfEx,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Printf("\nNo filters given\n%s\n", bpfDesc)
				fmt.Printf("\nExamples:\n%s\n", bpfEx)
			}
			BPF = strings.Join(args, " ")
		},
	}
)

func init() {
	remCap.AddCommand(bpf)
}
