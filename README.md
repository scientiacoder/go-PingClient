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
  - [使用Yaml配置启动PingClient](#使用Yaml配置启动PingClient)
    - [配置ping单一IP地址或者URL](#配置ping单一IP地址或者URL)
    - [配置同时ping多个IP地址或者URL](#配置同时ping多个IP地址或者URL)
    - [配置同时使用多个PingClient](#配置同时使用多个PingClient)
  - [更多用例，请参考config.example.yaml文件](./config.example.yaml)
  - 提示: 如果需要同时ping大量地址, 请注释或者删除cmd/ping.go里面OnRecv和OnFinish相关fmt打印信息, 以免在控制台打印大量日志
  - [使用命令行启动PingClient](#使用命令行启动PingClient)
    - [命令行ping单一IP地址或者URL](#命令行ping单一IP地址或者URL)
    - [命令行同时ping多个IP地址或者URL](#命令行同时ping多个IP地址或者URL)
    - [命令行ping使用ICMP原生socket](#命令行ping使用ICMP原生socket)
  - [程序内引用PingClient并启动](#程序内引用PingClient并启动)
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
或者使用go get安装:
```
go get -u -v github.com/scientiacoder/go-PingClient
```
  
## 使用

### 使用Yaml配置启动PingClient
推荐使用Yaml文件配置启动PingClient，参见文件夹下config.yaml以及config.example.yaml  
<details open>
<summary>展开使用Yaml配置启动PingClient</summary>  

#### 配置ping单一IP地址或者URL
假设ping IP地址220.181.38.148 5次时间间隔为200ms发一个包  
config.yaml设置为:
```
app:
  pingClient1:
    interval:
      200   # ping发包的时间间隔,单位毫秒
    timeout:
      5000 # ping如果超时会在经过这个时间后自动退出，单位毫秒
    ips:
      220.181.38.148
    num:
      5 # ping每个地址发包的次数
```
之后运行:
```
go run cmd/ping.go config.yaml
```
样例输出:
```
PING 220.181.38.148:
24 bytes from 220.181.38.148: icmp_seq=4722 time=192.073801ms ttl=40
24 bytes from 220.181.38.148: icmp_seq=4723 time=189.523571ms ttl=40
24 bytes from 220.181.38.148: icmp_seq=4724 time=176.11971ms ttl=40
24 bytes from 220.181.38.148: icmp_seq=4725 time=181.480174ms ttl=40
24 bytes from 220.181.38.148: icmp_seq=4726 time=181.702277ms ttl=40

---  220.181.38.148 ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max/stddev = 176.11971ms/184.179906ms/192.073801ms/5.818286ms
```
  
同样，如果想ping URL地址为www.github.com，只需配置config.yaml
```
app:
  pingClient1:
    interval:
      200   # ping发包的时间间隔,单位毫秒
    timeout:
      5000 # ping如果超时会在经过这个时间后自动退出，单位毫秒
    urls:
      www.github.com
    num:
      5 # ping每个地址发包的次数
```
```
go run cmd/ping.go config.yaml
```
得到输出:
```
PING www.github.com 13.237.44.5:
24 bytes from 13.237.44.5: icmp_seq=4722 time=40.532569ms ttl=40
24 bytes from 13.237.44.5: icmp_seq=4723 time=36.492822ms ttl=40
24 bytes from 13.237.44.5: icmp_seq=4724 time=43.692405ms ttl=40
24 bytes from 13.237.44.5: icmp_seq=4725 time=55.602643ms ttl=40
24 bytes from 13.237.44.5: icmp_seq=4726 time=38.508645ms ttl=40

--- www.github.com 13.237.44.5 ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max/stddev = 36.492822ms/42.965816ms/55.602643ms/6.751356ms
```
  
#### 配置同时ping多个IP地址或者URL
同时ping多个IP地址只需配置config.yaml
```
app:
  pingClient1:
    interval:
      200   # ping发包的时间间隔,单位毫秒
    timeout:
      5000 # ping如果超时会在经过这个时间后自动退出，单位毫秒
    ips:
      220.181.38.148
      13.237.44.5
    num:
      5 # ping每个地址发包的次数
```
```
go run cmd/ping.go config.yaml
```
同时ping多个URL只需配置config.yaml的urls
```
app:
  pingClient1:
    interval:
      200   # ping发包的时间间隔,单位毫秒
    timeout:
      5000 # ping如果超时会在经过这个时间后自动退出，单位毫秒
    urls:
      github.com
      golang.org
      baidu.com
    num:
      5 # ping每个地址发包的次数
```
```
go run cmd/ping.go config.yaml
```
IP和URL混合ping
```
app:
  pingClient1:
    interval:
      200   # ping发包的时间间隔,单位毫秒
    timeout:
      5000 # ping如果超时会在经过这个时间后自动退出，单位毫秒
    ips:
      220.181.38.148
      13.237.44.5
    urls:
      github.com
      golang.org
    num:
      5 # ping每个地址发包的次数
```
```
go run cmd/ping.go config.yaml
```
  
#### 配置同时使用多个PingClient
config.yaml:
```
app:
  pingClient1:
    interval:
      200   # in milliseconds (ping发包的时间间隔,单位毫秒)
    timeout:
      5000   # in milliseconds Timeout specifies a timeout before ping exits (ping会在经过这个时间后自动退出，单位毫秒)
    ips:
      142.250.71.78
      220.181.38.148
    urls:
      www.github.com
      www.stackoverflow.com
      golang.org
    num:
      5 # number of packets send per ip(or url) (ping每个地址的次数)
    privileged:
      false # false uses udp ping, true uses icmp raw socket need privilege (false基于udp, true需要权限使用原生socket)
    continuous:
      false # true means it will ping addresses continuously, ignore the num (default: false) (true表示会一直ping下去, 忽略num, 默认是false)
  pingClient2:
    ips:
      142.250.71.78
      220.181.38.148
  pingClient3:
    urls:
      google.com
  pingClient4:
    urls:
      github.com
    privileged:
      false
```
```
go run cmd/ping.go config.yaml
```  
</details>  

#### 使用命令行启动PingClient
命令行启动例子```go run cmd/ping.go github.com```  
其中命令行支持多种参数启动
```
-t 表示timeout时间自动退出 如: -t 5000ms
-i 表示interval发包时间间隔: -i 500ms
-n 表示要发送的包的数量: -n 6
-c 表示continuous, 如果启动命令带有-c 则会一直ping下去直到Ctrl+c终止 忽略要发送的包数量
-privileged 表示是否使用ICMP原生socket, 需要root权限，默认是使用的udp封装的而不是原生socket -privileged启动使用原生socket
```
<details open>
<summary>展开使用Yaml配置启动PingClient</summary>  

#### 命令行ping单一IP地址或者URL
如果想ping github.com 6次, 时间间隔为1s, 运行:
```
go run cmd/ping.go -n 6 -i 1s github.com
```
该命令中github.com可改为任意**IP地址**
输出为:
```
PING github.com 13.237.44.5:
24 bytes from 13.237.44.5: icmp_seq=4722 time=35.127904ms ttl=41
24 bytes from 13.237.44.5: icmp_seq=4723 time=36.252251ms ttl=41
24 bytes from 13.237.44.5: icmp_seq=4724 time=29.305253ms ttl=41
24 bytes from 13.237.44.5: icmp_seq=4725 time=37.577805ms ttl=41
24 bytes from 13.237.44.5: icmp_seq=4726 time=45.584345ms ttl=41
24 bytes from 13.237.44.5: icmp_seq=4727 time=33.345722ms ttl=41

--- github.com 13.237.44.5 ping statistics ---
6 packets transmitted, 6 packets received, 0% packet loss
round-trip min/avg/max/stddev = 29.305253ms/36.19888ms/45.584345ms/4.946393ms
```
如果想持续ping github.com, 时间间隔为1s(Ctrl+c终止), 运行:
```
go run cmd/ping.go -i 1s -c github.com
```
  
#### 命令行同时ping多个IP地址或者URL
只需将多个IP地址或者URL放在命令最后即可，运行:
```
go run cmd/ping.go -i 1s -c github.com golang.org 13.237.44.5
```

#### 命令行ping使用ICMP原生socket
首先确认go get在root用户的PATH下也安装了PingClient包
```
sudo go get -u -v github.com/scientiacoder/PingClient
```
之后即可sudo运行```-privileged```选项
```
sudo go run cmd/ping.go -i 1s -privileged -c github.com
```
  
</details>
  
### 程序内引用PingClient并启动