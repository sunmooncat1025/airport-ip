#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 定时解析机场私有 DNS，输出 ip.json。

环境变量（可选）：
    XDM_DOMAIN  节点域名，默认 f615b7dd...xingdaomeng.lky
    XDM_DNS     私有 DNS，默认 43.108.56.44
    XDM_PORTS   用于 TCP 探测的端口，逗号分隔，默认 30101,30402,30004
    EDGE_DOMAIN EdgeNova 节点域名，默认 bianasfdloo.bianyuan99.net
    EDGE_DNS    EdgeNova 私有 DNS，默认 47.80.244.10
    EDGE_PORTS  EdgeNova 探测端口，默认 46101,46301,46501

输出示例（另含 edge_domain / edge_ips / edge_ip / edge_port 字段）：
{
  "domain": "...",
  "dns": "43.108.56.44",
  "ips": ["1.2.3.4"],
  "ip": "1.2.3.4",
  "port": 30101,
  "latency_ms": 123,
  "updated": "2026-11-05T00:00:00Z",
  "source": "github-actions"
}
"""

import json
import os
import socket
import struct
import sys
import time

DOMAIN = os.environ.get(
    "XDM_DOMAIN",
    "f615b7dd813b85dc2c8584e558019a6deef99c59d8f06b.xingdaomeng.lky",
).strip()
DNS_SERVER = os.environ.get("XDM_DNS", "43.108.56.44").strip()
PORTS = []
for _p in os.environ.get("XDM_PORTS", "30101,30402,30004").split(","):
    _p = _p.strip()
    if _p.isdigit():
        PORTS.append(int(_p))

# EdgeNova 节点：域名只能由机场私有 DNS 解析，校园网直接封了 53 端口。
EDGE_DOMAIN = os.environ.get(
    "EDGE_DOMAIN", "bianasfdloo.bianyuan99.net"
).strip()
EDGE_DNS = os.environ.get("EDGE_DNS", "47.80.244.10").strip()
EDGE_PORTS = []
for _p in os.environ.get("EDGE_PORTS", "46101,46301,46501").split(","):
    _p = _p.strip()
    if _p.isdigit():
        EDGE_PORTS.append(int(_p))


def build_query(name, qtype=1):
    parts = [p for p in name.rstrip(".").split(".") if p]
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for p in parts:
        q += bytes([len(p)]) + p.encode("ascii")
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return q


def read_name(data, pos):
    parts = []
    jumped = False
    nxt = pos
    for _ in range(128):
        if pos >= len(data):
            break
        ln = data[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                nxt = pos
            break
        if (ln & 0xC0) == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                nxt = pos + 2
            jumped = True
            pos = ptr
            continue
        parts.append(data[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += ln + 1
        if not jumped:
            nxt = pos
    return ".".join(parts), nxt


def parse_response(data):
    if len(data) < 12:
        raise ValueError("short DNS response")
    rcode = struct.unpack("!H", data[2:4])[0] & 0xF
    qd, an = struct.unpack("!HH", data[4:8])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(data, pos)
        pos += 4
    records = []
    for _ in range(an):
        name, pos = read_name(data, pos)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        rd_start = pos
        rd = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            records.append({"name": name, "type": "A",
                            "data": socket.inet_ntoa(rd)})
        elif rtype == 28 and rdlen == 16:
            records.append({"name": name, "type": "AAAA",
                            "data": socket.inet_ntop(socket.AF_INET6, rd)})
        elif rtype == 5:
            cn, _ = read_name(data, rd_start)
            records.append({"name": name, "type": "CNAME", "data": cn})
    return {"rcode": rcode, "records": records}


def udp_query(name, server, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name), (server, 53))
        data, _ = s.recvfrom(4096)
        return parse_response(data)
    finally:
        s.close()


def tcp_query(name, server, timeout=5.0):
    q = build_query(name)
    s = socket.create_connection((server, 53), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack("!H", len(q)) + q)
        hdr = s.recv(2)
        if len(hdr) < 2:
            raise ValueError("no length prefix")
        ln = struct.unpack("!H", hdr)[0]
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        return parse_response(buf)
    finally:
        s.close()


def probe(ip, ports, timeout=3.0):
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((ip, p))
            return p, (time.time() - t0) * 1000
        except Exception:
            pass
        finally:
            s.close()
    return None


def resolve_domain(domain, dns_server, ports):
    try:
        r = udp_query(domain, dns_server)
    except Exception:
        r = tcp_query(domain, dns_server)

    ips = []
    for rec in r.get("records", []):
        if rec.get("type") == "A" and rec.get("data") not in ips:
            ips.append(rec["data"])

    out = {"domain": domain, "dns": dns_server, "ips": ips, "ip": None}
    if ips:
        chosen = None
        for ip in ips:
            got = probe(ip, ports)
            if got:
                chosen = ip
                out["port"] = got[0]
                out["latency_ms"] = round(got[1])
                break
        out["ip"] = chosen or ips[0]
    return out


def main():
    result = {
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "github-actions",
    }
    result.update(resolve_domain(DOMAIN, DNS_SERVER, PORTS))

    # EdgeNova 节点是独立的一批 IP/端口；失败时只记录错误，不影响 xdm 结果。
    try:
        edge = resolve_domain(EDGE_DOMAIN, EDGE_DNS, EDGE_PORTS)
        result["edge_domain"] = edge["domain"]
        result["edge_dns"] = edge["dns"]
        result["edge_ips"] = edge["ips"]
        result["edge_ip"] = edge["ip"]
        if "port" in edge:
            result["edge_port"] = edge["port"]
            result["edge_latency_ms"] = edge["latency_ms"]
    except Exception as e:
        result["edge_error"] = "%s: %s" % (type(e).__name__, e)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ip") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False, indent=2))
        sys.exit(1)
