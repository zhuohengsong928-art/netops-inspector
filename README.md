# NetOps Inspector 网络运维巡检工具

一个开箱即用的网络巡检命令行工具：批量检查主机是否在线、开放了哪些端口和服务、网站是否可用、SSL 证书还有多久到期，并自动生成巡检报告。适合日常运维巡检、机房设备点检、网站可用性监控等场景。

**零依赖**：只用 Python 标准库，装有 Python 3.8+ 的电脑（Windows / macOS / Linux）直接就能跑，不用 pip 安装任何东西。

## 功能

- **主机存活检测**：批量判断目标主机是否在线
- **端口与服务识别**：扫描常用端口（SSH、HTTP、MySQL、RDP、Redis 等 16 个），识别服务并抓取 Banner
- **网站可用性检查**：HTTP 状态码 + 响应延迟
- **SSL 证书监测**：证书颁发者、到期日、剩余天数，30 天内到期自动预警——避免证书过期导致网站打不开
- **巡检报告**：每次巡检自动生成 txt / json 双份报告，方便存档和二次处理
- **监控模式**：按设定间隔循环巡检，主机掉线/恢复时立即输出状态变化提示

## 快速开始

```bash
# 巡检单个目标
python netops.py example.com

# 按清单批量巡检（把要检查的 IP / 域名写进 targets.txt，每行一个）
python netops.py targets.txt

# 只扫指定端口
python netops.py 192.168.1.1 --ports 22,80,443,3306

# 监控模式：每 60 秒巡检一次，状态变化会提示
python netops.py targets.txt --watch 60
```

## 输出示例

```
[2026-11-20 20:10:05] www.baidu.com —— 存活
    开放端口: 80/HTTP, 443/HTTPS
      443 Banner: HTTP/1.0 400 Bad Request
    网站: HTTP 200，延迟 68 ms，正常
    SSL 证书: GlobalSign RSA OV SSL CA 2018，2027-05-27 到期，剩余 188 天
```

## 目标文件格式

`targets.txt` 每行一个目标，`#` 开头是注释：

```
192.168.1.1
example.com
https://example.com
```

## 项目结构

```
netops.py    主程序（单文件，约 300 行）
targets.txt  巡检目标清单示例
README.md    本说明
```

## 使用场景

- 每天上班先跑一遍，确认负责的服务器和网站都正常
- 证书快到期提前收到预警，不用等用户反馈网站打不开
- 新设备上架后快速点检端口开放情况

> 请只对自己有权管理的网络和设备使用本工具。
