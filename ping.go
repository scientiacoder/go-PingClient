package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	ping "./PingClient"
)

var confile []byte

// type alias
type PingClient = ping.PingClient

func main() {
	//pingClients, err := ping.InitWithYAMLFile("testyaml/t1.yaml")
	pingClients, err := ping.InitWithYAMLFile("config.yaml")
	if err != nil {
		log.Fatalf("%s", err)
		return
	}

	// Listen for Ctrl-C.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			for _, pingClient := range pingClients {
				pingClient.Stop()
			}
		}
	}()

	for _, p := range pingClients {
		p.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)

		}
		p.OnFinish = func(stats []*ping.Statistics) {
			for _, stat := range stats {
				fmt.Printf("\n--- %s ping statistics ---\n", stat.IP)
				for _, pkt := range stat.PacketsInfo {
					fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
						pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
				}
				fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
					stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss)
				fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
					stat.MinRtt, stat.AvgRtt, stat.MaxRtt, stat.StdDevRtt)
			}
		}
	}

	for _, p := range pingClients {
		p.Run()
	}

}
