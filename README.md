# PingClient
PingClient是一款基于Go语言的发送ICMP ping的库，可以自定义配置ping相关的参数并且可同时设置多个IP地址或者是URL，以及包含ping相关的数据分析如RTT(Round-trip time)等。Inspired by [go-fastping](https://github.com/tatsushid/go-fastping) and [go-ping](https://github.com/go-ping/ping) 欢迎```PR```, ```Star```, ```Issue```  

**主要功能**:
 1. 支持Yaml配置ping相关参数以及地址等，一键启动
 2. 可同时配置多个ping的IP或者URL地址以及不同ping的策略, IP地址和URL可以混合
 3. 减少goroutine的数量，降低cpu负载
 4. 支持ping包的数据统计，RTT、packet loss, ttl等  
  
## 目录

<details open>
<summary>展开目录简介</summary>  

- [安装](#安装)
- [使用](#使用)
  - [使用Yaml配置启动PingClient](#标题)
    - [配置ping单一IP地址或者URL](#标题)
    - [配置同时ping多个IP地址或者URL](#标题)
    - [配置同时使用多个PingClient](#标题)
  - [使用命令行启动PingClient](#标题)
    - [命令行ping单一IP地址或者URL](#标题)
    - [命令行同时ping多个IP地址或者URL](#标题)
  - [程序内引用PingClient并启动](#标题)
- [支持的操作系统](#定义)
- [TODO List](#定义)
- [贡献](#定义)
- [许可协议](#定义)
</details>  
  
## 安装
使用git clone来安装:
```
git clone https://github.com/scientiacoder/go-PingClient
cd go-PingClient/
```
或者使用go get安装
```
go get -u -v github.com/scientiacoder/go-PingClient
```
  
## 使用

