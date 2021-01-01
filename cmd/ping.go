package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	ping "../pingclient"
)

var confile []byte

// type alias
type PingClient = ping.PingClient

var usage = `
PingClient Usage:

    ping [-n num] [-i interval] [-t timeout] [-c continuous] [--privileged] host

Examples:

    # ping github continuously
    ping -c www.github.com

    # ping github 5 times
    ping -n 5 www.github.com

    # ping github 5 times at 500ms intervals
    ping -n 5 -i 500ms www.github.com

    # ping github for 10 seconds
    ping -t 10s www.github.com

    # Send a privileged raw ICMP ping
    sudo ping --privileged www.github.com
`

func main() {
	timeout := flag.Duration("t", 5*time.Second, "")
	interval := flag.Duration("i", 1*time.Second, "")
	num := flag.Int("n", 5, "")
	continuous := flag.Bool("c", false, "hahahaha")
	privileged := flag.Bool("privileged", false, "")

	flag.Usage = func() {
		fmt.Print(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	pingClient := ping.New()
	err := pingClient.Add(flag.Arg(0))
	if err != nil {
		log.Fatalf("%s", err)
		return
	}

	// Listen for Ctrl-C.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			pingClient.Stop()
		}
	}()

	pingClient.OnRecv = func(pkt *ping.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)

	}
	pingClient.OnFinish = func(stats []*ping.Statistics) {
		for _, stat := range stats {
			fmt.Printf("\n--- %s %s ping statistics ---\n", stat.URL, stat.IP)
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
	pingClient.Timeout = *timeout
	pingClient.Interval = *interval
	pingClient.Num = *num
	pingClient.Continuous = *continuous
	pingClient.SetPrivileged(*privileged)
	for i := range pingClient.IPs {
		fmt.Printf("PING %s %s:\n", pingClient.URLs[i], pingClient.IPs[i].IP.String())
	}

	err = pingClient.Run()
	if err != nil {
		log.Fatalf("%s", err)
		return
	}

}
