package main

import (
	"fmt"
	"io/ioutil"
	"log"

	ping "./PingClient"
	"gopkg.in/yaml.v2"
)

var confile []byte

// type alias
type PingClient = ping.PingClient

type Config struct {
}

func initPingClients(configMap map[interface{}]interface{}) ([]PingClient, error) {
	_, ok := configMap["app"]
	if !ok {
		return nil, fmt.Errorf("Error initPingClients(): app does not exist!")
	}

	m, _ := configMap["app"].(map[interface{}]interface{})

	for key, _ := range m {
		v, _ := m[key].(map[interface{}]interface{})
		ping.ParsePingClient(v)
	}

	return nil, nil
}

func main() {
	// "testyaml/t1.yaml"
	data, err := ioutil.ReadFile("config.yaml")
	// data, err := ioutil.ReadFile("testyaml/t1.yaml")
	if err != nil {
		log.Fatalf("Error main(): can not find config.yaml")
		return
	}
	configMap := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(data), &configMap)
	if err != nil {
		log.Fatalf("Error main(): %v", err)
	}

	pingClients := make([]PingClient, 0)
	if pingClients, err = initPingClients(configMap); err != nil {
		log.Printf("%s\n", err)
	}

	fmt.Println(pingClients)

}
