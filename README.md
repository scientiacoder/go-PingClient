# PingClient
PingClient是一款基于Go语言的发送ICMP ping的库，可以自定义配置ping相关的参数并且可同时设置多个IP地址或者是URL，以及包含ping相关的数据分析如RTT(Round-trip time)等。Inspired by [go-fastping](https://github.com/tatsushid/go-fastping) and [go-ping](https://github.com/go-ping/ping)  
主要功能:
 1. 支持Yaml配置ping相关参数以及地址等，一键启动
 2. 可同时配置多个ping的IP或者URL地址以及不同ping的策略
 3. 减少goroutine的数量，降低cpu负载
 4. 支持ping包的数据统计，RTT、packet loss, ttl等  
  
