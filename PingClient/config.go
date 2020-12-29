package lib

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Config helps parsing config.yaml or config.yml
// It will convert yaml file to a list of PingClientConfig
type Config struct {
	pingClientsConf []*PingClientConfig
}

type PingClientConfig struct {
	// time interval of sending packets in milliseconds
	interval time.Duration

	// timeout indicates the maximum waiting response time
	timeout time.Duration

	// ip addresses of pinged endpoints
	ips []*net.IPAddr

	// urls being pinged
	urls []string

	// number of packets be going to send
	num int

	// inverted index after resolve IP address of URL
	ipToURL map[*net.IPAddr]string

	// privileged uses icmp raw socket to ping while non-privileged uses udp
	privileged bool
}

// NewConfig returns an instance of Config which includes list of PingClientConfig
func NewConfig() *Config {
	return &Config{
		pingClientsConf: make([]*PingClientConfig, 0),
	}
}

func NewDefaultPingClientConfig() *PingClientConfig {
	return &PingClientConfig{
		interval:   time.Second,     // default ping interval on Linux is 1 second
		timeout:    5 * time.Second, // MSDN(windows) waits 5 seconds, Linux waits 2 maximum RTT
		ips:        make([]*net.IPAddr, 0),
		urls:       make([]string, 0),
		num:        5, // default num is 5 on most UNIX systems
		ipToURL:    make(map[*net.IPAddr]string),
		privileged: false,
	}
}

// parsePingClientConfig parses values of key app(like PingClient1: PingClient2: ) in yaml file
// and returns the ping client config set by the user
func parsePingClientConfig(conf map[interface{}]interface{}) (*PingClientConfig, error) {
	pingClientConf := NewDefaultPingClientConfig()

	for key := range conf {
		k := key.(string)
		stringKey := key.(string)

		switch k = strings.ToLower(strings.TrimSpace(k)); k {
		case "interval":
			intervalInt := conf[stringKey].(int)
			pingClientConf.interval = time.Duration(intervalInt) * time.Millisecond
		case "timeout":
			timeoutInt := conf[stringKey].(int)
			pingClientConf.timeout = time.Duration(timeoutInt) * time.Millisecond
		case "ips":
			ipStr := conf[stringKey].(string)
			ipStrList := strings.Split(ipStr, " ")
			var ip net.IP
			for _, v := range ipStrList {
				if ip = parseIP(v); ip == nil {
					return nil, fmt.Errorf("Error ParsePingClient(): %s should be in IP format x.x.x.x", v)
				}
				pingClientConf.ips = append(pingClientConf.ips, &net.IPAddr{IP: ip})
			}
		case "urls":
			urlStr := conf[stringKey].(string)
			urlList := strings.Split(urlStr, " ")
			for _, url := range urlList {
				ipaddr, err := parseURL("ip", url)
				if err != nil {
					return nil, fmt.Errorf("Error ParsePingClient(): can not resolve the IP address of url %s", url)
				}
				pingClientConf.ips = append(pingClientConf.ips, ipaddr)
				// construct inverted map
				pingClientConf.ipToURL[ipaddr] = url
			}
		case "num":
			n := conf[stringKey].(int)
			pingClientConf.num = n
		case "privileged":
			p := conf[stringKey].(bool)
			pingClientConf.privileged = p
		}
	}
	return pingClientConf, nil
}

// ParseConfig parses config from yaml file
func ParseConfig(conf map[interface{}]interface{}) (*Config, error) {
	_, ok := conf["app"]
	if !ok {
		return nil, fmt.Errorf("Error ParseConfig(): key app does not exist!")
	}

	m, _ := conf["app"].(map[interface{}]interface{})

	config := NewConfig()

	var p *PingClientConfig
	var err error
	for key := range m {
		v, _ := m[key].(map[interface{}]interface{})
		if p, err = parsePingClientConfig(v); err != nil {
			return nil, fmt.Errorf("%s", err)
		}

		config.pingClientsConf = append(config.pingClientsConf, p)
	}
	return config, nil
}
