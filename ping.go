package main

import (
	"flag"
	"fmt"
	"log"

	ping "./pingclient"
)

var confile []byte

// type alias
type PingClient = ping.PingClient

var usage = `
PingClient Usage:

    ping config.yaml

Examples:
    # ping with config yaml file
    ping config.yaml
`

func main() {
	flag.Parse()
	yamlfile := flag.Arg(0)

	pingClients, err := ping.InitWithYAMLFile(yamlfile)
	if err != nil {
		log.Fatalf("%s", err)
		return
	}
	for _, pingClient := range pingClients {
		pingClient.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
		}
	}
	for _, pingClient := range pingClients {
		err := pingClient.Run()
		if err != nil {
			log.Fatalf("%s", err)
			return
		}
	}

}
