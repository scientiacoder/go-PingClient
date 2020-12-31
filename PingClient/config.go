package lib

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Config helps parsing config.yaml or config.yml
// It will convert yaml file to a list of PingClientConfig
type Config struct {
	PingClientsConf []*PingClientConfig
}

// PingClientConfig represents
type PingClientConfig struct {
	// time interval of sending packets in milliseconds
	Interval time.Duration

	// timeout indicates the maximum waiting response time
	Timeout time.Duration

	// ip addresses of pinged endpoints
	IPs []*net.IPAddr

	// urls being pinged
	URLs []string

	// number of packets be going to send
	Num int

	// inverted index after resolve IP address of URL
	IPToURL map[*net.IPAddr]string

	// whether run continuously(forever)
	Continuous bool

	// privileged uses icmp raw socket to ping while non-privileged uses udp
	Privileged bool
}

// NewConfig returns an instance of Config which includes list of PingClientConfig
func NewConfig() *Config {
	return &Config{
		PingClientsConf: make([]*PingClientConfig, 0),
	}
}

func NewDefaultPingClientConfig() *PingClientConfig {
	return &PingClientConfig{
		Interval:   time.Second,     // default ping interval on Linux is 1 second
		Timeout:    5 * time.Second, // MSDN(windows) waits 5 seconds, Linux waits 2 maximum RTT
		IPs:        make([]*net.IPAddr, 0),
		URLs:       make([]string, 0),
		Num:        5, // default num is 5 on most UNIX systems
		IPToURL:    make(map[*net.IPAddr]string),
		Continuous: false,
		Privileged: false,
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
			pingClientConf.Interval = time.Duration(intervalInt) * time.Millisecond
		case "timeout":
			timeoutInt := conf[stringKey].(int)
			pingClientConf.Timeout = time.Duration(timeoutInt) * time.Millisecond
		case "ips":
			ipStr := conf[stringKey].(string)
			ipStrList := strings.Split(ipStr, " ")
			var ip net.IP
			for _, v := range ipStrList {
				if ip = parseIP(v); ip == nil {
					return nil, fmt.Errorf("Error ParsePingClient(): %s should be in IP format x.x.x.x", v)
				}
				pingClientConf.IPs = append(pingClientConf.IPs, &net.IPAddr{IP: ip})
			}
		case "urls":
			urls := make([]string, 0)
			urlStr := conf[stringKey].(string)
			urlList := strings.Split(urlStr, " ")
			for _, url := range urlList {
				ipaddr, err := parseURL("ip", url)
				if err != nil {
					return nil, fmt.Errorf("Error ParsePingClient(): can not resolve the IP address of url %s", url)
				}
				pingClientConf.IPs = append(pingClientConf.IPs, ipaddr)
				// construct inverted map
				pingClientConf.IPToURL[ipaddr] = url
				urls = append(urls, url)
			}
			pingClientConf.URLs = urls
		case "num":
			n := conf[stringKey].(int)
			pingClientConf.Num = n
		case "privileged":
			p := conf[stringKey].(bool)
			pingClientConf.Privileged = p
		case "continuous":
			con := conf[stringKey].(bool)
			pingClientConf.Continuous = con
		}
	}
	return pingClientConf, nil
}

// ParseConfig parses config from yaml file
func ParseConfig(conf map[interface{}]interface{}) (*Config, error) {
	_, ok := conf["app"]
	if !ok {
		return nil, fmt.Errorf("error ParseConfig(): key app does not exist!")
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

		config.PingClientsConf = append(config.PingClientsConf, p)
	}
	return config, nil
}

// InitWithYAMLFile inits a ping client with given yaml file
func InitWithYAMLFile(name string) ([]*PingClient, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("Error main(): %s", err)
	}
	configYaml := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(data), &configYaml)
	if err != nil {
		return nil, fmt.Errorf("Error main(): %s", err)
	}

	config, err := ParseConfig(configYaml)
	if err != nil {
		return nil, fmt.Errorf("Error main(): %s", err)
	}

	return InitWithConfig(config), nil
}
