#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络运维巡检工具 NetOps Inspector

功能：
  1. 主机存活检测（TCP 探测）
  2. 常用端口扫描与服务识别（含 Banner 抓取）
  3. 网站可用性检查（HTTP 状态码 + 响应延迟）
  4. SSL 证书有效期检查（到期天数预警）
  5. 批量巡检并生成报告（控制台 + txt + json）
  6. 定时监控模式：循环巡检，记录状态变化（上线/掉线）

仅使用 Python 标准库，无第三方依赖，Python 3.8+ 即可运行。

用法：
  python netops.py targets.txt            # 按目标文件批量巡检
  python netops.py example.com            # 巡检单个目标
  python netops.py targets.txt --watch 60 # 每 60 秒循环监控
  python netops.py example.com --ports 22,80,443,3306

目标文件格式（每行一个，# 开头为注释）：
  192.168.1.1
  example.com
  https://example.com
"""

import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# 常用端口与对应服务名
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

SSL_WARN_DAYS = 30  # 证书剩余天数低于此值时预警


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def scan_port(host, port, timeout=1.5):
    """扫描单个端口，开放时尝试抓取服务 Banner。返回 dict 或 None。

    抓取策略：先被动接收（SSH、FTP、MySQL 等服务会主动发欢迎语），
    没收到再发一个 HTTP 探针（应对 Web 类服务）。
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(0.8)
                try:
                    data = sock.recv(128)
                except OSError:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(128)
                banner = data.decode("utf-8", errors="ignore").strip().splitlines()[0][:80] if data else ""
            except OSError:
                pass
            return {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "banner": banner}
    except OSError:
        return None


def scan_ports(host, ports, workers=32):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(lambda p: scan_port(host, p), ports)
    return sorted([r for r in results if r], key=lambda r: r["port"])


def check_http(url, timeout=8):
    """检查网站可用性：状态码 + 响应延迟（毫秒）。"""
    req = urllib.request.Request(url, headers={"User-Agent": "NetOpsInspector/1.0"})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency = int((time.time() - start) * 1000)
            return {"url": url, "ok": 200 <= resp.status < 400,
                    "status": resp.status, "latency_ms": latency}
    except urllib.error.HTTPError as e:
        latency = int((time.time() - start) * 1000)
        return {"url": url, "ok": False, "status": e.code, "latency_ms": latency}
    except Exception as e:  # 网络不可达、DNS 失败等
        return {"url": url, "ok": False, "status": None,
                "latency_ms": None, "error": str(e)[:100]}


def _read_tlv(buf, pos):
    """读取一个 DER TLV，返回 (tag, value_bytes, next_pos)。"""
    tag = buf[pos]; pos += 1
    if tag & 0x1F == 0x1F:  # 多字节 tag（本工具用到的结构不会出现，保险处理）
        while buf[pos] & 0x80:
            pos += 1
        pos += 1
    first = buf[pos]; pos += 1
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big"); pos += n
    else:
        length = first
    return tag, buf[pos:pos + length], pos + length


def _children(seq_value):
    out, pos = [], 0
    while pos < len(seq_value):
        tag, val, pos = _read_tlv(seq_value, pos)
        out.append((tag, val))
    return out


def _parse_time(tag, val):
    s = val.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSS
        year = int(s[:2]) + (2000 if int(s[:2]) < 50 else 1900)
        s = str(year) + s[2:]
    return datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def _expiry_from_der(der):
    """从 DER 证书中解析到期时间（用于自签名证书：标准库在不校验
    模式下不返回解析后的证书，只能自己读 DER 里的 validity 字段）。"""
    _, cert_body, _ = _read_tlv(der, 0)
    tbs = _children(cert_body)[0][1]          # TBSCertificate
    fields = _children(tbs)
    idx = 1 if fields[0][0] == 0xA0 else 0    # 跳过可选的 [0] 版本号
    validity = fields[idx + 3][1]             # serial、签名算法、颁发者之后是 validity
    times = _children(validity)
    return _parse_time(*times[1])             # 第二个时间是 notAfter


def check_ssl(host, port=443, timeout=5):
    """检查 SSL 证书：颁发者、到期日、剩余天数。

    先按受信任模式校验；遇到自签名证书（内网设备常见）时降级为
    不校验模式读取到期信息，并标注 trusted=False。
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
        trusted = True
    except Exception:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            not_after = _expiry_from_der(der)
            issuer = "自签名证书"
            trusted = False
        except Exception as e:
            return {"host": host, "error": str(e)[:100]}
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {"host": host, "issuer": issuer,
            "expires": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left, "warn": days_left < SSL_WARN_DAYS,
            "trusted": trusted}


def parse_target(line):
    """解析一行目标，返回 (host, url_or_None)。"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("http://") or line.startswith("https://"):
        host = line.split("://", 1)[1].split("/")[0].split(":")[0]
        return host, line
    return line.split(":")[0], None


def inspect_target(host, url, ports):
    """对单个目标做完整巡检，返回结果 dict。

    存活判定：任一被扫端口开放，或网站检查能拿到响应，即视为存活
    （只开 8080 等非标准端口的设备也不会被误报为不可达）。
    """
    result = {"host": host, "time": now_str()}
    result["open_ports"] = scan_ports(host, ports)
    web_url = url or f"https://{host}"
    result["http"] = check_http(web_url)
    result["alive"] = bool(result["open_ports"]) or result["http"].get("status") is not None
    if web_url.startswith("https://"):
        result["ssl"] = check_ssl(host)
    return result


def print_report(r):
    status = "存活" if r["alive"] else "不可达"
    print(f"[{r['time']}] {r['host']} —— {status}")
    if r["open_ports"]:
        ports = ", ".join(f"{p['port']}/{p['service']}" for p in r["open_ports"])
        print(f"    开放端口: {ports}")
        for p in r["open_ports"]:
            if p["banner"]:
                print(f"      {p['port']} Banner: {p['banner']}")
    h = r.get("http", {})
    if h:
        if h.get("status"):
            print(f"    网站: HTTP {h['status']}，延迟 {h['latency_ms']} ms，{'正常' if h['ok'] else '异常'}")
        else:
            print(f"    网站: 检查失败（{h.get('error', '未知错误')}）")
    s = r.get("ssl", {})
    if s and "days_left" in s:
        warn = "  ⚠ 即将到期，请及时续期" if s["warn"] else ""
        trust = "" if s.get("trusted", True) else "（自签名/未受信任）"
        print(f"    SSL 证书: {s['issuer']}，{s['expires']} 到期，剩余 {s['days_left']} 天{trust}{warn}")
    elif s and "error" in s:
        print(f"    SSL 证书: 检查失败（{s['error']}）")


def load_targets(args):
    targets = []
    if args.target.endswith(".txt"):
        with open(args.target, encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = [args.target]
    for line in lines:
        t = parse_target(line)
        if t:
            targets.append(t)
    return targets


def run_once(targets, ports):
    results = []
    for host, url in targets:
        r = inspect_target(host, url, ports)
        print_report(r)
        results.append(r)
    return results


def save_report(results):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    txt_name, json_name = f"report-{stamp}.txt", f"report-{stamp}.json"
    with open(txt_name, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False, indent=2) + "\n")
    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n报告已保存: {txt_name} / {json_name}")


def watch(targets, ports, interval):
    print(f"监控模式：每 {interval} 秒巡检一次，Ctrl+C 退出。状态变化会单独提示。")
    prev = {}
    try:
        while True:
            results = run_once(targets, ports)
            for r in results:
                key = r["host"]
                if key in prev and prev[key] != r["alive"]:
                    change = "恢复上线" if r["alive"] else "⚠ 已掉线"
                    print(f">>> 状态变化: {key} {change}（{now_str()}）")
                prev[key] = r["alive"]
            print(f"--- 下次巡检 {interval} 秒后 ---\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n监控已停止。")


def main():
    ap = argparse.ArgumentParser(description="网络运维巡检工具 NetOps Inspector")
    ap.add_argument("target", help="目标文件（.txt）或单个主机/IP/网址")
    ap.add_argument("--ports", help="要扫描的端口，逗号分隔（默认常用端口集）")
    ap.add_argument("--watch", type=int, metavar="秒", help="监控模式：每 N 秒循环巡检")
    ap.add_argument("--no-save", action="store_true", help="不保存报告文件")
    args = ap.parse_args()

    ports = ([int(p) for p in args.ports.split(",")] if args.ports
             else sorted(COMMON_PORTS))
    targets = load_targets(args)
    if not targets:
        print("没有有效目标。")
        sys.exit(1)

    if args.watch:
        watch(targets, ports, args.watch)
    else:
        results = run_once(targets, ports)
        if not args.no_save:
            save_report(results)


if __name__ == "__main__":
    main()
