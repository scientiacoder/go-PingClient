package main

import (
	"flag"
	"fmt"
	"time"

	ping "./pingclient"
)

var confile []byte

// type alias
type PingClient = ping.PingClient

var usage = `
PingClient Usage:

    ping [-n num] [-i interval] [-t timeout] [-c continuous] [--privileged] host

Examples:
	# ping with config yaml file
	ping config.yaml

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
	continuous := flag.Bool("c", false, "")
	privileged := flag.Bool("privileged", false, "")

	flag.Usage = func() {
		fmt.Print(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	fmt.Println(flag.NArg())
	fmt.Println(*continuous)
	fmt.Println(flag.Arg(0))

	ping.Use(timeout, interval, num, privileged, continuous)

	/*
		pingClients, err := ping.InitWithYAMLFile("config.yaml")
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

		//	pinger, err := ping.NewPinger("www.google.com")
		//	if err != nil {
		//		panic(err)
		//	}
		//	pinger.Count = 3
		//	err = pinger.Run() // blocks until finished
		//	if err != nil {
		//		panic(err)
		//	}
		//	stats := pinger.Statistics() // get send/receive/rtt stats
		/*
			pingClient := ping.New()
			pingClient.Add("github.com")

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

			err := pingClient.Run()
			if err != nil {
				log.Fatalf("%s", err)
				return
			}
	*/

}
