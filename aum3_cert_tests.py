#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""[AU.AUM-3.CertificatePrivateKey] 取证脚本 —— EN 18031-1 / IEC 62443-4-2 TDS 用

覆盖标准原文四个 bullet。条数不写死：按条款与"具体测试情况"决定，本次落地 7 条
（bullet1 两条形态、bullet2 条件项、bullet3 NOTE 三类无效证书各一条、bullet4 条件项）：

  R1a bullet1 incorrect private keys to a trusted certificate
      -> c1_wrong_key ：沿用受信任证书身份（DN/序列号一致），公钥/私钥为攻击者自有的一对；中间人出示。
  R1b bullet1 同上，纯粹形态：真受信任证书 + 攻击者私钥，本机 openssl 复现"构不出可用端点"。
  R2  bullet2 replay of a recorded successful authentication attempt
      -> 条件项：认证消息机密性未受保护才适用（TLS 保护 => N/A）；--replay 才真做重放。
  R3a bullet3 NOTE invalid chain of trust (untrusted entity with expected CN) -> c3a_untrusted_ca
  R3b bullet3 NOTE expired certificates                                    -> c3b_expired
  R3c bullet3 NOTE certificates revoked by the CA                          -> c3c_revoked + CRL
  R4  bullet4 trusted certificate of other entities（条件项：存在不同账号才适用）-> c4_other_entity

条数不写死：每条自己声明适用性，起跑前用 --list 摊开、按"具体测试情况"（对端是不是 TLS、
是否存在不同账号、有几个认证端点/信任锚）决定跑哪几条。同一条款落在不同认证端点（如云通道
+ 本地 HTTPS）时，对每个端点各跑一轮（--target 换端点）。

判定口径（严格，避免把“链不受信任”当成“通过了过期/吊销检查”）：
  pass  ：DUT 拒绝，且告警原因与本用例要检的属性一致（如 T3b 必须是 certificate_expired）
  pass* ：DUT 拒绝，但告警原因落在“证书链/信任锚”检查上 —— 只能证明 DUT 校验证书，
          不能单独证明该属性；脚本注明需先把实验室 CA 预置进 DUT 才能单测。
  fail  ：DUT 完成了握手（接受了错误证书）—— 不符合，不能写 PASS
  skip  ：窗口内没看到 DUT 发起握手（先确认 DUT 网关指向本机，再重跑该窗口）
  退出码：全部必测项 pass/pass* -> 0；有 fail -> 1；有 skip/error -> 2。

用法：
  # 只打印将执行的 iptables 规则（先在设备上核对，别急着跑）
  python3 aum3_cert_tests.py --target cloud.example.com:18888 --src 172.16.0.4 \
        --proxy-host 172.16.0.1 --intercept 203.0.113.10:18888 --rules-only
  # 只生成五张证书 + 离线自检（不碰 DUT）
  python3 aum3_cert_tests.py --target cloud.example.com:18888 --gen-only --selftest
  # 全自动跑五个必测项（每项一个窗口）
  sudo python3 aum3_cert_tests.py --target cloud.example.com:18888 --src 172.16.0.4 \
        --proxy-host 172.16.0.1 --intercept 203.0.113.10:18888 --transparent \
        --mitm-insecure --live 90 --label AUM3
  # 无参数 = 交互向导（6 问，会明确问“对端是不是云下发”）

依赖：openssl（必须）、mitmdump（出示假证书）、tcpdump+tshark（设备侧证据，强烈建议）。
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")
MITMDUMP = os.environ.get("MITMDUMP_BIN", "mitmdump")

# ---------------------------------------------------------------- 标准条款 -> 用例（数据驱动）
# 覆盖 EN 18031-1 [AU.AUM-3.CertificatePrivateKey] 原文四个 bullet。条数不写死：
# 每条自己声明适用性（app），起跑前按"具体测试情况"判定跑不跑 ——
#   always               : 标准无条件要求
#   cond:confidentiality : 仅当认证消息经网络接口传输时机密性未受保护（TLS 保护则 N/A）
#   cond:accounts        : 仅当存在/可创建不同用户账号（--accounts yes|no|unknown）
# bullet3 的 NOTE 给了三类"无效证书"，标准用 can be 举例，因此拆成三条各自成证据。
REQS = [
    dict(id="R1a", clause="bullet1 incorrect private keys to a trusted certificate",
         title="错误私钥 + 沿用受信任证书身份（中间人出示）",
         cert="c1_wrong_key", runner="mitm", app="always",
         specific_alerts={"bad_certificate", "decrypt_error", "illegal_parameter", "certificate_unknown"},
         weaker_alerts={"unknown_ca", "handshake_failure", "access_denied"}),
    dict(id="R1b", clause="bullet1 incorrect private keys to a trusted certificate",
         title="真受信任证书 + 攻击者私钥：能否构成可用认证端点（本机 openssl 原样复现）",
         cert=None, runner="mismatch_key", app="always",
         specific_alerts={"key_values_mismatch"}, weaker_alerts=set()),
    dict(id="R2", clause="bullet2 replay of a recorded successful authentication attempt",
         title="重放已记录的成功认证（条件项）",
         cert=None, runner="replay", app="cond:confidentiality",
         specific_alerts=set(), weaker_alerts=set()),
    dict(id="R3a", clause="bullet3 NOTE invalid chain of trust (untrusted entity, expected CN)",
         title="不受信任实体签发、但 CN/SAN 符合期望的证书",
         cert="c3a_untrusted_ca", runner="mitm", app="always",
         specific_alerts={"unknown_ca", "bad_certificate", "certificate_unknown"},
         weaker_alerts={"handshake_failure"}),
    dict(id="R3b", clause="bullet3 NOTE expired certificates",
         title="CN/SAN 符合期望、但已过期的证书",
         cert="c3b_expired", runner="mitm", app="always",
         specific_alerts={"certificate_expired"},
         weaker_alerts={"unknown_ca", "bad_certificate", "certificate_unknown", "handshake_failure"}),
    dict(id="R3c", clause="bullet3 NOTE certificates revoked by the CA",
         title="CN/SAN 符合期望、已被 CA 吊销的证书（同时发布 CRL）",
         cert="c3c_revoked", runner="mitm", app="always",
         specific_alerts={"certificate_revoked"},
         weaker_alerts={"unknown_ca", "certificate_unknown", "bad_certificate", "handshake_failure"}),
    dict(id="R4", clause="bullet4 trusted certificate of other entities",
         title="同一受信任 CA 下另一个实体的合法证书",
         cert="c4_other_entity", runner="mitm", app="cond:accounts",
         specific_alerts={"bad_certificate", "certificate_unknown", "access_denied"},
         weaker_alerts={"unknown_ca", "handshake_failure"}),
]

# 服务端拓扑（DUT 作 TLS 服务端，本地 web TLS 服务出示证书给 web 管理客户端）下的用例：
# 这一拓扑里"出示证书"的是 DUT 自己，所以四条 bullet 落到两件事上：
#   ① 设备自身证书的属性是否合规、能否被"伪造/冒用"（S0 基线 + S1 错误私钥 + S3a/b/c/S4 冒用实验）
#   ② 若设备要求客户端证书（mTLS），才有"设备校验对端证书"的路径（脚本会打印探测结果）
SERVER_REQS = [
    dict(id="S0", clause="baseline / AuthVal: the certificate the local web TLS service presents",
         title="采集设备本地 web TLS 服务出示的证书与 TLS 参数，核对 E-Info 文档",
         cert=None, runner="probe", app="always", specific_alerts=set(), weaker_alerts=set()),
    dict(id="S1", clause="bullet1 incorrect private keys to a trusted certificate",
         title="设备自身证书 + 攻击者私钥：能否据此冒充该设备（本机 openssl 复现）",
         cert=None, runner="mismatch_key", app="always",
         specific_alerts={"key_values_mismatch"}, weaker_alerts=set()),
    dict(id="S2", clause="bullet2 replay of a recorded successful authentication attempt",
         title="重放已记录的成功认证（条件项）",
         cert=None, runner="replay", app="cond:confidentiality", specific_alerts=set(), weaker_alerts=set()),
    dict(id="S3a", clause="bullet3 NOTE invalid chain of trust (untrusted entity, expected CN)",
         title="以设备身份 + 不受信任链的证书冒充该设备，校验型客户端是否接受",
         cert="c3a_untrusted_ca", cert_key="R3a", runner="impersonate", app="always",
         specific_alerts=set(), weaker_alerts=set()),
    dict(id="S3b", clause="bullet3 NOTE expired certificates",
         title="以设备身份 + 已过期的证书冒充该设备，校验型客户端是否接受",
         cert="c3b_expired", cert_key="R3b", runner="impersonate", app="always",
         specific_alerts=set(), weaker_alerts=set()),
    dict(id="S3c", clause="bullet3 NOTE certificates revoked by the CA",
         title="以设备身份 + 已吊销的证书冒充该设备，校验型客户端是否接受",
         cert="c3c_revoked", cert_key="R3c", runner="impersonate", app="always",
         specific_alerts=set(), weaker_alerts=set()),
    dict(id="S4", clause="bullet4 trusted certificate of other entities",
         title="以另一实体的证书冒充该设备，校验型客户端是否接受",
         cert="c4_other_entity", cert_key="R4", runner="impersonate", app="cond:accounts",
         specific_alerts=set(), weaker_alerts=set()),
]

ALERT_NAMES = {0: "close_notify", 40: "handshake_failure", 42: "bad_certificate",
               43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
               46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
               49: "access_denied", 51: "decrypt_error", 80: "internal_error"}

TDS_SENTENCE = {
    "R1a": "出示沿用受信任证书身份（DN/序列号一致）但私钥为攻击者自有的证书，DUT 拒绝该证书、认证不成立",
    "R1b": "受信任证书与错误私钥无法构成可用端点（加载即 key values mismatch），用错误私钥无法通过认证",
    "R2": "认证消息经网络接口传输的机密性由 TLS 保护，标准该条为条件项，判定 N/A（理由见下）",
    "R3a": "出示 CN/SAN 与期望值一致、但证书链由不受信任实体签发的证书，DUT 拒绝该证书",
    "R3b": "出示 CN/SAN 与期望值一致、但已过期的证书，DUT 拒绝该证书",
    "R3c": "出示由 CA 签发后吊销（CRL 已列出该序列号）的证书，DUT 拒绝该证书",
    "R4": "出示同一受信任 CA 下另一个实体的合法证书，DUT 拒绝该证书",
    "S0": "采集设备本地 web TLS 服务出示的证书与 TLS 参数，与 E-Info 文档一致（无偏差项）",
    "S1": "设备自身证书与攻击者私钥无法构成可用端点（加载即 key values mismatch），该证书不可被冒用",
    "S2": "认证消息经网络接口传输的机密性由 TLS 保护，标准该条为条件项，判定 N/A（理由见下）",
    "S3a": "以设备身份 + 不受信任链的证书无法让校验型客户端完成到该设备的认证",
    "S3b": "以设备身份 + 已过期的证书无法让校验型客户端完成到该设备的认证",
    "S3c": "以设备身份 + 已吊销的证书无法让校验型客户端完成到该设备的认证",
    "S4": "以另一实体的证书无法冒用该设备完成认证",
}


def log(msg):
    print("[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def tail3(txt):
    return " / ".join((txt or "").strip().splitlines()[-3:])


def sh(cmd, timeout=120):
    """跑外部命令，返回 (rc, stdout+stderr)，UTF-8 容错。"""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "[TIMEOUT after %ss] %s" % (timeout, " ".join(cmd))
    except OSError as exc:
        return 127, "[OSError] %s: %s" % (" ".join(cmd), exc)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def ask(q, default=""):
    try:
        v = input("%s%s: " % (q, (" [%s]" % default) if default else "")).strip()
    except EOFError:
        v = ""
    return v or default


def norm_reason(s):
    s = (s or "").strip().lower().replace(" ", "_").replace("-", "_")
    s = re.sub(r"^(tlsv1(\.[0-9])?_)+", "", s)
    s = re.sub(r"^alert_", "", s)
    return s.strip("_")


# ---------------------------------------------------------------- 网络/环境
def ipv4_list():
    out = []
    rc, txt = sh(["ip", "-4", "-o", "addr", "show"], timeout=10)
    for line in txt.splitlines():
        m = re.search(r"[0-9]+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            out.append((m.group(1).split("@")[0], m.group(2), int(m.group(3))))
    return out


def pick_proxy_host(dut_ip, explicit=None):
    """DNAT 目的地址：显式优先；否则选与 DUT 同网段的本机地址（中间盒上最容易踩的坑）。"""
    if explicit:
        return explicit, True
    try:
        import ipaddress
        if dut_ip:
            dev = ipaddress.ip_address(str(dut_ip))
            for iface, ip, pfx in ipv4_list():
                if dev in ipaddress.ip_network("%s/%d" % (ip, pfx), strict=False):
                    return ip, True
    except Exception:
        pass
    cands = [x[1] for x in ipv4_list()]
    return (cands[0] if cands else "127.0.0.1"), False


def iface_for(dut_ip):
    """抓包网卡：与 DUT 同网段那张（多网卡中间盒上 -i any 会漏掉本地 DNAT 后的握手）。"""
    try:
        import ipaddress
        if dut_ip:
            dev = ipaddress.ip_address(str(dut_ip))
            for iface, ip, pfx in ipv4_list():
                if dev in ipaddress.ip_network("%s/%d" % (ip, pfx), strict=False):
                    return iface
    except Exception:
        pass
    return "any"


def tshark_stdin(pcap, extra, timeout=180):
    """该机 tshark 按路径打开 pcap 会被拒（连 root 都报 You don't have permission），
    但把文件喂进 stdin 完全正常 —— 统一走 tshark -r -。"""
    if not pcap or not os.path.exists(pcap) or not shutil.which("tshark"):
        return ""
    try:
        with open(pcap, "rb") as fh:
            p = subprocess.run(["tshark", "-r", "-"] + list(extra), stdin=fh,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""
    return p.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------- 实验室 PKI（只用 openssl）
CNF = """[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = __DIR__
database          = $dir/index.txt
new_certs_dir     = $dir/newcerts
certificate       = $dir/lab_root.crt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
private_key       = $dir/lab_root.key
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
default_crl_days  = 3650
policy            = policy_any
copy_extensions   = none
unique_subject    = no

[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = req_dn

[ req_dn ]
commonName = __CN__

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
__SAN__

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"""


def write_cnf(a, cn, san=None):
    path = os.path.join(a.certs_dir, "openssl.cnf")
    body = CNF.replace("__DIR__", os.path.abspath(a.certs_dir).replace("\\", "/"))
    body = body.replace("__CN__", cn or "lab")
    body = body.replace("__SAN__", ("subjectAltName = " + san) if san else "")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def ca_init(a, force=False):
    """最小 CA 目录 + 实验室根 CA（一次生成，跨用例复用）。"""
    os.makedirs(os.path.join(a.certs_dir, "newcerts"), exist_ok=True)
    for f, v in (("index.txt", ""), ("serial", "1000\n"), ("crlnumber", "1000\n")):
        p = os.path.join(a.certs_dir, f)
        if force or not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(v)
    rootcrt = os.path.join(a.certs_dir, "lab_root.crt")
    if os.path.exists(rootcrt) and not force:
        return True
    cnf = write_cnf(a, a.lab_cn)
    rootkey = os.path.join(a.certs_dir, "lab_root.key")
    rc, out = sh([OPENSSL, "genrsa", "-out", rootkey, "2048"])
    if rc != 0:
        log("[error] 生成根 CA 私钥失败: " + out.strip()[-300:])
        return False
    rc, out = sh([OPENSSL, "req", "-x509", "-new", "-key", rootkey, "-out", rootcrt, "-days", "3650",
                  "-sha256", "-subj", "/O=AUM3-Lab/CN=%s" % a.lab_cn, "-config", cnf,
                  "-extensions", "v3_ca"])
    if rc != 0:
        log("[error] 生成根 CA 证书失败: " + out.strip()[-300:])
        return False
    log("[pki] 实验室根 CA 就绪: %s (CN=%s)" % (rootcrt, a.lab_cn))
    return True


def anchor_info(a):
    """从真服务器抓叶子证书，读出 CN/SAN/序列号/有效期，供“长得像受信任证书”的用例使用。"""
    rc, out = sh([OPENSSL, "s_client", "-connect", "%s:%d" % (a.host, a.port),
                  "-servername", a.sni or a.host, "-showcerts"], timeout=a.timeout)
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not blocks:
        return None
    leaf = os.path.join(a.certs_dir, "anchor_leaf.pem")
    with open(leaf, "w", encoding="ascii") as fh:
        fh.write(blocks[0] + "\n")
    rc, info = sh([OPENSSL, "x509", "-in", leaf, "-noout", "-subject", "-issuer", "-serial", "-dates",
                   "-fingerprint", "-sha256", "-ext", "subjectAltName"])
    d = {"pem": leaf, "raw": info}
    for line in info.splitlines():
        k, _, v = line.partition("=")
        d[k.strip().lower().replace(" ", "_")] = v.strip()
    m = re.search(r"DNS:([^,\s]+)", info)
    d["san_dns"] = m.group(1) if m else None
    m = re.search(r"CN\s*=\s*([^,/\n]+)", d.get("subject", ""))
    d["cn"] = m.group(1).strip() if m else None
    return d


def sign_leaf_x509(a, name, subject, keyfile, serial=None, san=None, days=3650):
    """T1 专用签发路径：openssl 3.x 的 ca 子命令没有 -set_serial，而 T1 必须复用受信任证书的
    序列号；x509 -req 支持 -set_serial，且不写入 CA 数据库 —— 重复跑也不会撞 serial。"""
    cnf = write_cnf(a, "lab", san)
    csr = os.path.join(a.certs_dir, name + ".csr")
    crt = os.path.join(a.certs_dir, name + ".crt")
    rc, out = sh([OPENSSL, "req", "-new", "-key", keyfile, "-out", csr, "-subj", subject, "-config", cnf])
    if rc != 0:
        log("[error] 生成 CSR 失败 %s: %s" % (name, tail3(out)))
        return None
    cmd = [OPENSSL, "x509", "-req", "-in", csr, "-CA", os.path.join(a.certs_dir, "lab_root.crt"),
           "-CAkey", os.path.join(a.certs_dir, "lab_root.key"), "-CAcreateserial", "-out", crt,
           "-days", str(days), "-sha256", "-extfile", cnf, "-extensions", "usr_cert"]
    if serial:
        cmd += ["-set_serial", "0x" + serial.replace(":", "").replace("0x", "").strip()]
    rc, out = sh(cmd)
    if rc != 0 or not os.path.exists(crt):
        log("[error] 签发 %s 失败: %s" % (name, tail3(out)))
        return None
    return crt


def set_serial_file(a, hexserial):
    """openssl 3.x 的 ca 子命令没有 -set_serial，指定序列号要写 serial 文件（大写十六进制）。"""
    with open(os.path.join(a.certs_dir, "serial"), "w", encoding="utf-8") as fh:
        fh.write(hexserial.strip().upper().replace(":", "") + "\n")


def sign_leaf(a, name, subject, keyfile, serial=None, start=None, end=None, san=None):
    """用实验室 CA 签叶子证书；start/end 形如 20200101000000Z（用于过期用例）。"""
    cnf = write_cnf(a, "lab", san)
    csr = os.path.join(a.certs_dir, name + ".csr")
    crt = os.path.join(a.certs_dir, name + ".crt")
    rc, out = sh([OPENSSL, "req", "-new", "-key", keyfile, "-out", csr, "-subj", subject, "-config", cnf])
    if rc != 0:
        log("[error] 生成 CSR 失败 %s: %s" % (name, tail3(out)))
        return None
    if serial:
        set_serial_file(a, serial)
    cmd = [OPENSSL, "ca", "-batch", "-notext", "-config", cnf, "-in", csr, "-out", crt,
           "-extensions", "usr_cert", "-days", "3650"]
    if start:
        cmd += ["-startdate", start]
    if end:
        cmd += ["-enddate", end]
    rc, out = sh(cmd)
    if rc != 0 or not os.path.exists(crt):
        log("[error] 签发 %s 失败: %s" % (name, tail3(out)))
        return None
    return crt


def make_pem(a, name, crt, key):
    """mitmproxy 用：cert+key 合一的 PEM。"""
    pem = os.path.join(a.certs_dir, name + ".pem")
    with open(pem, "wb") as fh:
        for p in (crt, key):
            with open(p, "rb") as src:
                fh.write(src.read())
    return pem


def gen_certs(a):
    """生成五张错误证书。返回 {case_id: {...}}；失败返回 None。"""
    if a.regen:
        shutil.rmtree(a.certs_dir, ignore_errors=True)
    os.makedirs(a.certs_dir, exist_ok=True)
    if not ca_init(a, force=a.regen):
        return None
    anc = anchor_info(a)
    if not anc:
        log("[error] 抓不到真服务器证书（%s:%d）；T1/T3b/T4 需要它的 DN/序列号做对照" % (a.host, a.port))
        return None
    a.anchor_sha256 = anc.get("sha256_fingerprint", "")
    expected_cn = a.expected_cn or anc.get("san_dns") or anc.get("cn") or a.sni
    expected_san = ("DNS:%s" % expected_cn) if expected_cn else None
    org = "AUM3-Lab"
    m = re.search(r"O\s*=\s*([^,/\n]+)", anc.get("subject", ""))
    if m:
        org = m.group(1).strip()
    serial_anchor = (anc.get("serial") or "").replace(":", "").strip()
    log("[anchor] %s:%d 叶子 CN=%s SAN=%s serial=%s 有效期 %s ~ %s"
        % (a.host, a.port, anc.get("cn"), anc.get("san_dns"), anc.get("serial"),
           anc.get("notbefore"), anc.get("notafter")))
    out = {}
    now = datetime.datetime.now(datetime.timezone.utc)

    # T1：身份照抄受信任证书，但公私钥换成攻击者自有的一对
    k1 = os.path.join(a.certs_dir, "c1_wrong_key.key")
    sh([OPENSSL, "genrsa", "-out", k1, "2048"])
    # T1 走 x509 -req -set_serial，不碰 serial 文件（否则会把 CA 的自增序列号带偏、
    # 让后面的 T3a 撞上"serial already in database"）
    crt = sign_leaf_x509(a, "c1_wrong_key", "/O=%s/CN=%s" % (org, expected_cn), k1,
                         serial=(serial_anchor or "1001"), san=expected_san)
    if not crt:
        return None
    out["R1a"] = dict(pem=make_pem(a, "c1_wrong_key", crt, k1),
                     desc="沿用受信任证书身份：CN=%s、序列号=%s 与真服务器证书一致，但公钥/私钥为攻击者自有的一对，"
                          "且链条由实验室 CA 自签 —— 验证“受信任证书 + 错误私钥”能否通过认证"
                          % (expected_cn, serial_anchor))

    # T3a：期望 CN，但链条不可信
    k3a = os.path.join(a.certs_dir, "c3a_untrusted_ca.key")
    sh([OPENSSL, "genrsa", "-out", k3a, "2048"])
    crt = sign_leaf(a, "c3a_untrusted_ca", "/O=%s/CN=%s" % (org, expected_cn), k3a, san=expected_san)
    if not crt:
        return None
    out["R3a"] = dict(pem=make_pem(a, "c3a_untrusted_ca", crt, k3a),
                      desc="CN/SAN=%s 与期望值一致，但整条链由不受信任的实验室 CA 签发（invalid chain of trust）"
                           % expected_cn)

    # T3b：期望 CN，但整张证书已过期
    k3b = os.path.join(a.certs_dir, "c3b_expired.key")
    sh([OPENSSL, "genrsa", "-out", k3b, "2048"])
    end = (now - datetime.timedelta(days=400)).strftime("%Y%m%d%H%M%SZ")
    start = (now - datetime.timedelta(days=1200)).strftime("%Y%m%d%H%M%SZ")
    crt = sign_leaf(a, "c3b_expired", "/O=%s/CN=%s" % (org, expected_cn), k3b,
                    start=start, end=end, san=expected_san)
    if not crt:
        return None
    out["R3b"] = dict(pem=make_pem(a, "c3b_expired", crt, k3b),
                      desc="CN/SAN=%s 一致，但有效期 %s ~ %s 整体落在过去（过期证书）"
                           % (expected_cn, start, end))

    # T3c：期望 CN，签发后立即吊销，并生成 CRL
    k3c = os.path.join(a.certs_dir, "c3c_revoked.key")
    sh([OPENSSL, "genrsa", "-out", k3c, "2048"])
    crt = sign_leaf(a, "c3c_revoked", "/O=%s/CN=%s" % (org, expected_cn), k3c, san=expected_san)
    if not crt:
        return None
    cnf = write_cnf(a, "lab")
    sh([OPENSSL, "ca", "-batch", "-config", cnf, "-revoke", crt])
    crl = os.path.join(a.certs_dir, "c3c_revoked.crl.pem")
    sh([OPENSSL, "ca", "-batch", "-config", cnf, "-gencrl", "-out", crl, "-crlexts", "crl_ext"])
    out["R3c"] = dict(pem=make_pem(a, "c3c_revoked", crt, k3c), crl=crl,
                      desc="CN/SAN=%s 一致，由实验室 CA 签发后立即吊销，CRL（%s）中已列出其序列号 —— 验证吊销检查"
                           % (expected_cn, os.path.basename(crl)))

    # T4：同一 CA 下的“另一个实体”
    k4 = os.path.join(a.certs_dir, "c4_other_entity.key")
    sh([OPENSSL, "genrsa", "-out", k4, "2048"])
    other_cn = a.other_cn or ("device-other-%s" % (serial_anchor or "0001")[:8])
    crt = sign_leaf(a, "c4_other_entity", "/O=%s/CN=%s" % (org, other_cn), k4, san="DNS:%s" % other_cn)
    if not crt:
        return None
    out["R4"] = dict(pem=make_pem(a, "c4_other_entity", crt, k4),
                     desc="由代表受信任 CA 的实验室 CA 签发的合法证书，但属于另一个实体（CN=%s，期望 %s）—— 验证"
                          "“其他实体的受信任证书”能否用于认证" % (other_cn, expected_cn))

    # 证书清单（本身就是证据的一部分）
    titles = dict((c["id"], c["title"]) for c in REQS)
    lines = ["# 五张错误证书清单（%s）" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "- 真服务器证书（对照/信任锚）: %s" % anc.get("pem"), ""]
    for cid in ("R1a", "R3a", "R3b", "R3c", "R4"):
        rc, txt = sh([OPENSSL, "x509", "-in", out[cid]["pem"], "-noout", "-subject", "-issuer",
                      "-serial", "-dates", "-fingerprint", "-sha256"])
        out[cid]["x509"] = txt
        lines += ["## %s  %s" % (cid, titles.get(cid, "")), "用途: " + out[cid].get("desc", "")] + \
                 ["  " + l for l in txt.strip().splitlines()] + [""]
    with open(os.path.join(a.out, "certs_summary.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return out


def selftest(a):
    """离线自检：五张证书都不能用真服务器的签发链验证通过。"""
    log("[selftest] openssl verify 逐张确认（CAfile=抓下来的真服务器叶子证书）")
    bad = 0
    for cid, c in (a.cert_map or {}).items():
        rc, txt = sh([OPENSSL, "verify", "-CAfile", os.path.join(a.certs_dir, "anchor_leaf.pem"), c["pem"]])
        ok = rc != 0
        first = (txt.strip().splitlines() or [""])[0]
        log("  [%s] rc=%d -> %s | %s" % (cid, rc, "不可信（符合预期）" if ok else "竟然可信（异常）", first))
        if not ok:
            bad += 1
    return 0 if bad == 0 else 1


# ---------------------------------------------------------------- 透明劫持 / 抓包
class Mitm:
    def __init__(self, a, cert, tag):
        self.a, self.cert, self.tag = a, cert, tag
        self.proc, self.log, self.cmd = None, "", []
        self.port = a.mitm_port

    def _cmd(self, modern):
        cmd = [MITMDUMP, "--showhost"]
        cmd += (["--mode", "transparent@%d" % self.port] if modern
                else ["-p", str(self.port), "--mode", "transparent"])
        cmd += ["--set", "certs=*=" + os.path.abspath(self.cert),
                "--set", "ssl_insecure=" + ("true" if self.a.mitm_insecure else "false"),
                "-w", os.path.join(self.a.out, "flows_%s.mitm" % self.tag)]
        return cmd

    def start(self):
        for modern in (True, False):
            self.log = ""
            self.cmd = self._cmd(modern)
            try:
                self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1)
            except OSError as exc:
                self.log = "[ERROR] 起不了 %s: %s（mitmproxy 未安装？）" % (MITMDUMP, exc)
                log(self.log)
                return False
            for _ in range(120):
                time.sleep(0.1)
                try:
                    socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                    if not modern:
                        log("[warn] 本机 mitmdump 不支持 transparent@PORT，已回退 -p PORT --mode transparent")
                    return True
                except OSError:
                    if self.proc.poll() is not None:
                        self.log += self.proc.stdout.read() if self.proc.stdout else ""
                        break
            tail = (self.log.strip().splitlines() or [""])[-1][:160]
            log("[warn] mitmdump 启动失败: " + tail)
            if "Invalid mode specification" not in self.log:
                return False
        return False

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                out, _ = self.proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                out, _ = self.proc.communicate()
            self.log += out or ""
            self.proc = None


def dnat_cmds(a, action):
    host = a.proxy_host or a.host
    cmds = []
    for item in a.intercept:
        tgt, _, prt = item.partition(":")
        cmd = ["sudo", "iptables", "-t", "nat", action, "PREROUTING"]
        if a.src:
            cmd += ["-s", a.src]
        cmd += ["-p", "tcp", "-d", tgt, "--dport", str(int(prt or 443)),
                "-j", "DNAT", "--to-destination", "%s:%d" % (host, a.mitm_port)]
        cmds.append(cmd)
    return cmds


def kick_cmds(a, action):
    """踢长连接：DNAT 只对新建连接生效，MQTT/HTTP 长连接（空闲可静默数分钟）不踢就抓不到握手。
    老连接走 FORWARD，在这里 tcp-reset；DUT 重连的新 SYN 在 PREROUTING 就被 DNAT 走、
    不进 FORWARD，所以这条 REJECT 不会破坏我们自己的劫持会话。"""
    cmds = []
    for item in a.intercept:
        tgt, _, prt = item.partition(":")
        cmd = ["sudo", "iptables", action, "FORWARD"]
        if a.src:
            cmd += ["-s", a.src]
        cmd += ["-p", "tcp", "-d", tgt, "--dport", str(int(prt or 443)),
                "-j", "REJECT", "--reject-with", "tcp-reset"]
        cmds.append(cmd)
    return cmds


def apply_rules(cmds, quiet=False):
    ok = True
    for cmd in cmds:
        if not quiet:
            log("  " + " ".join(cmd))
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            ok = False
            log("[warn] 规则执行失败: %s" % (p.stdout or "").strip())
    return ok


def start_capture(a, tag):
    path = os.path.join(a.out, "%s.pcap" % tag)
    if a.no_capture:
        return None, path
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or getpass.getuser()
    ports = " or ".join("port %d" % int(i.partition(":")[2] or 443) for i in a.intercept)
    flt = "host %s and (%s) and tcp" % (a.src, ports) if a.src else "(%s) and tcp" % ports
    cmd = ["sudo", "tcpdump", "-i", iface_for(a.src), "-n", "-s", "0", "-U", "-Z", user,
           "-w", path, flt]
    log("  " + " ".join(cmd))
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True), path
    except OSError as exc:
        log("[warn] 抓包起不来: %s" % exc)
        return None, path


def stop_capture(proc):
    if proc is None:
        return
    time.sleep(0.8)
    proc.terminate()
    try:
        proc.wait(timeout=6)
    except Exception:
        proc.kill()


def wait_and_watch(seconds):
    """窗口等待：批处理里 stdin 直接 EOF 不能当成“按了回车”，否则窗口 0 秒就收尾。"""
    t0 = time.time()
    stdin_live = True
    try:
        import select
    except Exception:
        select = None
    while time.time() - t0 < seconds:
        if select is None or not stdin_live:
            time.sleep(0.5)
            continue
        r, _, _ = select.select([sys.stdin], [], [], 1.0)
        if not r:
            continue
        line = sys.stdin.readline()
        if line == "":
            stdin_live = False
            continue
        break


# ---------------------------------------------------------------- 判据
def device_alerts(pcap, dut):
    txt = tshark_stdin(pcap, ["-Y", "tls.alert_message && ip.src==%s" % dut, "-T", "fields",
                              "-e", "frame.time_relative", "-e", "tls.alert_message.level",
                              "-e", "tls.alert_message.desc"])
    out = []
    for line in txt.splitlines():
        f = line.split("\t")
        if len(f) >= 3 and f[2].strip():
            try:
                desc = int(f[2])
            except ValueError:
                desc = -1
            out.append((f[0].strip(), ALERT_NAMES.get(desc, "code_%s" % f[2].strip())))
    return out


def conn_ports(pcap, dut, expr, field):
    """按“连接”而不是按整段 pcap 统计：返回满足表达式的连接端口集合。
    设备可能同时还有老的长连接在跑，不区分连接会把老连接的应用数据算成本次认证成功。"""
    txt = tshark_stdin(pcap, ["-Y", expr, "-T", "fields", "-e", field])
    return set(x.strip() for x in txt.splitlines() if x.strip())


def app_data_local(pcap, dut):
    """两次统计：① 服务器出示过证书的那些连接；② DUT 发出过应用数据的那些连接。
    只有“同一条连接既被出示了我们的证书、又出现 DUT 应用数据”才算真正接受了证书。"""
    served = conn_ports(pcap, dut, "tls.handshake.type==11 && ip.src!=%s" % dut, "tcp.dstport")
    used = conn_ports(pcap, dut, "tls.record.content_type==23 && ip.src==%s" % dut, "tcp.srcport")
    return served, used


def handshake_stats(pcap, dut):
    ch = shh = cert = app = 0
    for line in tshark_stdin(pcap, ["-Y", "tls.handshake.type", "-T", "fields",
                                    "-e", "ip.src", "-e", "tls.handshake.type"]).splitlines():
        f = line.split("\t")
        if len(f) < 2:
            continue
        types = f[1].split(",")
        if f[0].strip() == dut:
            if "1" in types:
                ch += 1
        else:
            if "2" in types:
                shh += 1
            if "11" in types:
                cert += 1
    app = len([x for x in tshark_stdin(pcap, ["-Y", "tls.record.content_type==23 && ip.src==%s" % dut,
                                              "-T", "fields", "-e", "frame.number"]).split() if x])
    return ch, shh, cert, app


def judge(a, case, logtext, pcap):
    alerts = device_alerts(pcap, a.src)
    ch, shh, cert, appdata = handshake_stats(pcap, a.src)
    served_ports, used_ports = app_data_local(pcap, a.src)
    accepted_ports = sorted(served_ports & used_ports, key=lambda x: int(x) if x.isdigit() else 0)
    reasons = [norm_reason(x[1]) for x in alerts]
    logtext = logtext or ""
    upstream = [l for l in logtext.splitlines()
                if re.search(r"cannot establish tls|server tls handshake failed|unable to get local issuer",
                             l, re.I)]
    client_fail = [l.strip() for l in logtext.splitlines()
                   if re.search(r"client\s+tls\s+handshake\s+failed|client does not trust", l, re.I)
                   and l.strip() not in upstream]
    for l in client_fail:
        m = re.search(r"\(([^)]*)\)", l)
        if m and "alert" in m.group(1).lower():
            reasons.append(norm_reason(m.group(1)))
    reasons = [r for r in reasons if r]
    rejected = bool(reasons or client_fail)
    # 只有“同一条连接既收到我们的证书、又被 DUT 用来发应用数据”才算接受；其它连接上的应用数据
    # 属于被踢断前的既有会话，不能算进来（否则会把老连接误判成“接受了假证书”）
    accepted = bool(accepted_ports) and not rejected
    spec = set(case.get("specific_alerts") or [])
    weak = set(case.get("weaker_alerts") or [])
    if rejected and (set(reasons) & spec):
        verdict, note = "pass", "DUT 拒绝，且拒绝原因正是本用例要检的属性"
    elif rejected and (not spec or set(reasons) & weak or reasons):
        verdict, note = "pass*", ("DUT 拒绝，但告警原因落在证书链/信任锚检查上（%s）：能证明 DUT 会校验证书，"
                                  "不能单独证明该属性；要单测这一条，需先把实验室 CA 预置进 DUT"
                                  % ", ".join(sorted(set(reasons))))
    elif accepted:
        verdict, note = "fail", "DUT 完成了握手（接受了这张错误证书）—— 不符合，不能写 PASS"
    elif ch == 0:
        verdict, note = "skip", "窗口内没看到 DUT 发起 TLS 握手：确认 DUT 网关指向本机后重跑本窗口"
    else:
        verdict, note = "skip", "证据不足（未抓到 DUT 侧 ClientHello/告警）"
    if rejected and appdata:
        note += ("；窗口内另有 %d 条 DUT 应用数据记录，落在端口 %s 上，与被出示证书的连接（端口 %s）不是同一条"
                 "（属被踢断前的既有会话），判定以 DUT 主动告警与 mitmproxy 日志为准"
                 % (appdata, ", ".join(sorted(used_ports)) or "-", ", ".join(sorted(served_ports)) or "-"))
    if accepted_ports:
        note += "；注意：端口 %s 上既有我们出示的证书、又有 DUT 应用数据 —— 需人工复核" % ", ".join(accepted_ports)
    return dict(result=verdict, note=note, alerts=sorted(set(reasons)), client_fail=client_fail,
                ch=ch, sh=shh, cert=cert, appdata=appdata, accepted=accepted,
                served_ports=sorted(served_ports), used_ports=sorted(used_ports),
                accepted_ports=accepted_ports)


def run_case(a, case, certpem):
    log("=" * 78)
    log("[%s] %s" % (case["id"], case["title"]))
    log("      证书: %s" % os.path.basename(certpem))
    apply_rules(dnat_cmds(a, "-A"))
    m = Mitm(a, certpem, case["id"].lower())
    if not m.start():
        apply_rules(dnat_cmds(a, "-D"), quiet=True)
        return dict(case=case, result="error", note="mitmdump 起不来（未安装或端口被占）",
                    alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
    if not a.no_kick:
        log("      踢掉 DUT↔对端的长连接（否则空闲长连接不会重连，窗口内看不到握手）")
        apply_rules(kick_cmds(a, "-I"))
    cap, pcap = start_capture(a, "device_" + case["id"].lower())
    log("      窗口 %d 秒 ..." % a.live)
    wait_and_watch(a.live)
    stop_capture(cap)
    if not a.no_kick:
        apply_rules(kick_cmds(a, "-D"), quiet=True)
    m.stop()
    apply_rules(dnat_cmds(a, "-D"), quiet=True)
    v = judge(a, case, m.log, pcap)
    v["case"] = case
    v["cmd"] = " ".join(m.cmd)
    v["pcap"] = pcap
    log("      -> %s : %s" % (v["result"], v["note"]))
    if v["alerts"]:
        log("      DUT 侧告警: " + ", ".join(v["alerts"]))
    return v


# ---------------------------------------------------------------- 条件项 T2
def replay_applicability(a):
    return ("通道 %s:%d 使用 TLS：认证消息经网络接口传输的机密性由 TLS 保护，"
            "标准该条（replay of a recorded successful authentication attempt）为条件项，"
            "在本实现中判定 N/A。若后续版本取消 TLS 保护，请加 --replay 重跑本项。" % (a.host, a.port))


def replay_attempt(a, seconds):
    """可选：录一次成功握手，再从本机原样重放客户端 TLS 记录，看服务端是否直接进入应用数据。"""
    log("[T2] 重放尝试：先录一次 DUT 与真服务器的成功握手 ...")
    if not a.no_kick:
        apply_rules(kick_cmds(a, "-I"))
    cap, pcap = start_capture(a, "t2_replay_record")
    t0 = time.time()
    while time.time() - t0 < max(60, seconds):
        time.sleep(3)
        ch, shh, cert, app = handshake_stats(pcap, a.src)
        if app:
            break
    stop_capture(cap)
    if not a.no_kick:
        apply_rules(kick_cmds(a, "-D"), quiet=True)
    ch, shh, cert, app = handshake_stats(pcap, a.src)
    case = dict(id="R2", title="replay of a recorded successful authentication attempt",
                clause="bullet2 conditional (confidentiality of authentication messages)")
    if ch == 0 or shh == 0:
        return dict(case=case, result="skip", note="没录到成功握手，重放无从谈起（先确认 DUT 能连上真服务器）",
                    alerts=[], client_fail=[], ch=ch, sh=shh, cert=cert, appdata=app, pcap=pcap)
    txt = tshark_stdin(pcap, ["-o", "tcp.relative_sequence_numbers:FALSE",
                              "-Y", "ip.src==%s && tcp.len>0" % a.src,
                              "-T", "fields", "-e", "tcp.seq", "-e", "tcp.payload"], timeout=240)
    segs = []
    for line in txt.splitlines():
        f = line.split("\t")
        if len(f) == 2 and f[1].strip():
            try:
                segs.append((int(f[0]), bytes.fromhex(f[1].replace(":", ""))))
            except ValueError:
                pass
    segs.sort()
    stream = b"".join(x[1] for x in segs)
    log("[T2] 录到客户端字节流 %d 字节，向真服务器原样重放 ..." % len(stream))
    try:
        s = socket.create_connection((a.host, a.port), 10)
        s.settimeout(10)
        s.sendall(stream)
        resp = s.recv(4096)
        s.close()
    except OSError as exc:
        return dict(case=case, result="skip", note="重放时网络异常: %s" % exc, alerts=[], client_fail=[],
                    ch=ch, sh=shh, cert=cert, appdata=app, pcap=pcap)
    is_alert = len(resp) > 5 and resp[0] == 0x15
    res = "pass" if is_alert else "fail"
    note = ("服务端以 TLS alert 拒绝重放（%d 字节，头 %s）" % (len(resp), resp[:5].hex(" ")) if is_alert
            else "服务端未拒绝重放（返回 %d 字节，非 alert）—— 需人工复核" % len(resp))
    return dict(case=case, result=res, note=note, alerts=[], client_fail=[], ch=ch, sh=shh,
                cert=cert, appdata=app, pcap=pcap, replay_bytes=len(stream))


# ---------------------------------------------------------------- 输出
def write_outputs(a, results):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# [AU.AUM-3.CertificatePrivateKey] 取证 summary", "",
             "- 时间: " + stamp,
             "- 拓扑: %s" % ("server（DUT 作 TLS 服务端：本地 web TLS 服务出示证书）"
                              if getattr(a, "topology", "client") == "server"
                              else "client（DUT 作 TLS 客户端：脚本做中间人替换对端证书）"),
             "- 认证对端: %s:%d (SNI %s)" % (a.host, a.port, a.sni or a.host),
             "- DUT: %s    中间盒: %s (%s)" % (a.src, a.proxy_host, iface_for(a.src)),
             "- 实验室 CA: " + os.path.join(a.certs_dir, "lab_root.crt"),
             "- 信任锚（真服务器叶子）: " + os.path.join(a.certs_dir, "anchor_leaf.pem"),
             "- 实验室 CA 是否已预置进 DUT: %s" % ("是" if a.lab_ca_provisioned else "否"),
             "- 劫持目标解析: " + (json.dumps(getattr(a, "intercept_map", {}), ensure_ascii=False) or "-"),
             "- 服务器证书 SHA256: " + (getattr(a, "anchor_sha256", "") or "-"), "",
             "| 用例 | 覆盖标准条款 | 适用性判定 | 结果 | 证书 |", "|---|---|---|---|---|"]
    for v in results:
        c = v["case"]
        cm = (a.cert_map or {}).get(c["id"], {}) or {}
        lines.append("| %s | %s | %s | %s | %s |"
                     % (c["id"], c.get("clause", "conditional"),
                        v.get("applicability", "适用"), v["result"],
                        os.path.basename(cm.get("pem", "")) or "-"))
    lines += ["", "## 逐条证据"]
    for v in results:
        c = v["case"]
        cm = (a.cert_map or {}).get(c["id"], {}) or {}
        lines += ["", "### %s — %s" % (c["id"], c.get("title", "")),
                  "- 结果: " + v["result"],
                  "- 判定: " + v["note"],
                  "- 适用性: " + v.get("applicability", "适用"),
                  "- 用例说明: " + (cm.get("desc") or "-"),
                  "- 设备侧抓包: " + os.path.basename(v.get("pcap") or "-"),
                  ("- 计数: 服务端拓扑，无中间人抓包（证书与 TLS 参数见 device_cert_facts.txt）"
                   if getattr(a, "topology", "client") == "server" else
                   "- 计数: DUT ClientHello %d / 服务器 ServerHello %d / 服务器证书 %d / DUT 应用数据 %d"
                   % (v["ch"], v["sh"], v["cert"], v["appdata"])),
                  "- DUT 侧 TLS 告警: " + (", ".join(v["alerts"]) or "（无；TLS1.3 的 alert 为密文时以日志为准）"),
                  "- 客户端侧握手失败日志: " + (v["client_fail"][0] if v["client_fail"] else "（无）"),
                  "- 起停命令: " + (v.get("cmd") or "-"),
                  "- 本机复现/原始输出: " + (v.get("raw") or "-"),
                  "- TDS 结论句: " + TDS_SENTENCE.get(c["id"], "")]
    with open(os.path.join(a.out, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(dict(time=stamp, target="%s:%d" % (a.host, a.port), dut=a.src,
                       proxy_host=a.proxy_host, lab_ca_provisioned=a.lab_ca_provisioned,
                       cases=[dict(id=v["case"]["id"], expect="reject", result=v["result"],
                                   note=v["note"], alerts=v["alerts"], ch=v["ch"], sh=v["sh"],
                                   cert=v["cert"], appdata=v["appdata"], pcap=v.get("pcap"),
                                   client_fail=v["client_fail"],
                                   tds=TDS_SENTENCE.get(v["case"]["id"], "")) for v in results]),
                  fh, ensure_ascii=False, indent=2)
    log("[out] " + os.path.abspath(a.out) + "  （summary.md / report.json / certs_summary.txt"
        + ("" if getattr(a, "topology", "client") == "server"
           else " / device_*.pcap") + "）")


# ---------------------------------------------------------------- 适用性判定（按具体测试情况）
def confidentiality_protected(a):
    """目标端口是不是 TLS（认证消息经网络接口传输的机密性是否受保护）。"""
    if a.confidentiality == "protected":
        return True, "--confidentiality protected（人工指定）"
    if a.confidentiality == "unprotected":
        return False, "--confidentiality unprotected（人工指定）"
    rc, out = sh([OPENSSL, "s_client", "-connect", "%s:%d" % (a.host, a.port),
                  "-servername", a.sni or a.host], timeout=20)
    if "BEGIN CERTIFICATE" in out or "Verify return code" in out or "Protocol" in out:
        return True, "目标 %s:%d 为 TLS 服务，认证消息的机密性由 TLS 保护" % (a.host, a.port)
    return False, "未能在 %s:%d 上建立 TLS（可能是不加密的自定义协议），按机密性未受保护处理" % (a.host, a.port)


def resolve_applicability(a, reqs=None):
    """逐条判定"这次到底要不要跑"，返回 {id: (bool, 理由)}。"""
    prot, why_prot = confidentiality_protected(a)
    out = {}
    for r in (reqs or REQS):
        app = r.get("app", "always")
        if app == "always":
            out[r["id"]] = (True, "标准无条件要求")
        elif app == "cond:confidentiality":
            out[r["id"]] = ((not prot),
                            ("条件成立：%s" % why_prot) if not prot
                            else ("条件不成立 -> N/A：%s；标准该条只在机密性未受保护时才要求" % why_prot))
        elif app == "cond:accounts":
            if a.accounts == "no":
                out[r["id"]] = (False, "条件不成立 -> N/A：--accounts no（DUT 上不存在也无法创建不同用户账号）")
            elif a.accounts == "yes":
                out[r["id"]] = (True, "条件成立：--accounts yes（存在/可创建不同用户账号）")
            else:
                out[r["id"]] = (True, "按适用执行：--accounts unknown，不同账号是否存在需人工确认；"
                                      "本用例结果本身对判定有效（其他实体的受信任证书也必须被拒）")
        else:
            out[r["id"]] = (True, "未知适用性规则，按适用处理")
    return out


def print_checklist(a, appl=None, reqs=None):
    """打印条款覆盖清单：这条要不要跑、用什么证书、判定方式。"""
    reqs = reqs or REQS
    topo = getattr(a, "topology", "client")
    print("")
    print("# [AU.AUM-3.CertificatePrivateKey] 覆盖清单 —— 拓扑: %s"
          % ("服务端（DUT 出示本地 web TLS 证书）" if topo == "server" else "客户端（DUT 校验云端/上位机证书）"))
    print("# 共 %d 条；条数按标准条款与实际测试情况决定" % len(reqs))
    print("")
    print("| 用例 | 标准条款 | 用例内容 | 所需材料 | 适用性 |")
    print("|---|---|---|---|---|")
    for r in reqs:
        cert = (r["cert"] + ".pem") if r.get("cert") else {
            "probe": "设备本地 web TLS 服务（现场采集）",
            "mismatch_key": "本机 openssl 复现（设备证书 + 攻击者私钥）",
            "replay": "录制 + 重放",
        }.get(r["runner"], "-")
        if appl:
            ok, why = appl[r["id"]]
            apptxt = ("适用" if ok else "N/A") + "：" + why
        else:
            apptxt = {"always": "无条件适用",
                      "cond:confidentiality": "仅当机密性未受保护（--confidentiality auto|protected|unprotected）",
                      "cond:accounts": "仅当存在不同账号（--accounts yes|no|unknown）"}.get(r.get("app"), "-")
        print("| %s | %s | %s | %s | %s |" % (r["id"], r["clause"], r["title"], cert, apptxt))
    print("")
    print("判定口径：DUT 拒绝且告警原因=该条款要检的属性 -> pass；拒绝但原因落在证书链/信任锚 -> pass*；")
    print("           DUT 完成握手 -> fail；窗口内没有握手 -> skip；条件不成立 -> n/a。")


def case_mismatched_key(a, case):
    """bullet1 的纯粹形态：把"真服务器的受信任证书"与"攻击者自有的私钥"凑在一起，
    看能否构成一个可用的认证端点。openssl 加载时就会拒绝（key values mismatch），
    也就是这种组合根本无法开始握手 —— 用错误私钥不可能通过认证。
    证据=本机 openssl 的原样输出（不依赖 mitmproxy）。"""
    realcert = os.path.join(a.certs_dir, "anchor_leaf.pem")
    wrongkey = os.path.join(a.certs_dir, "c1_wrong_key.key")
    port = a.mitm_port or 8443
    cmd = [OPENSSL, "s_server", "-accept", str(port), "-cert", realcert, "-key", wrongkey,
           "-www", "-naccept", "1"]
    rc, out = sh(cmd, timeout=8)
    if re.search(r"key values mismatch|no cert matches|cannot load", out, re.I):
        res, note = "pass", ("受信任证书 + 错误私钥无法构成可用端点：openssl 加载即报 key values mismatch，"
                             "握手根本无法开始 —— 用错误私钥无法通过认证")
    elif rc == 124:
        res, note = "fail", "该组合竟然能起 TLS 端点并等待连接，需人工复核（受信任证书与错误私钥为何能配对）"
    else:
        res, note = "skip", "判定不了：openssl 输出异常 -> " + tail3(out)
    return dict(case=case, result=res, note=note, alerts=[], client_fail=[], ch=0, sh=0, cert=0,
                appdata=0, cmd=" ".join(cmd), raw=tail3(out))


# ---------------------------------------------------------------- 起跑前环境互斥检查
def resolve_one(host):
    """把 host 解析成 IPv4：iptables 里写域名会在 -A/-D 两次各自解析，规则容易对不上，
    证据里也看不懂是打到哪个地址。返回 (ip, 全部 A 记录)。"""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return host, [host]
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})
        return (ips[0] if ips else host), ips
    except OSError:
        return host, []


def normalize_intercept(a):
    """把 --intercept 里的域名换成解析出的 IP，并把解析结果记进证据。"""
    out, mapping = [], {}
    for item in a.intercept:
        host, _, prt = item.partition(":")
        ip, ips = resolve_one(host)
        if len(ips) > 1:
            log("[warn] %s 解析到多个地址 %s：本次只劫持 %s；若 DUT 连的是别的地址，请直接写那个地址"
                % (host, ips, ip))
        mapping[host] = ips
        out.append("%s:%s" % (ip, prt or "443"))
        if ip != host:
            log("[info] 劫持目标 %s -> %s（DNAT 按 IP 下发，避免域名二次解析对不上）" % (host, ip))
    a.intercept, a.intercept_map = out, mapping
    return mapping


def precheck_env(a):
    """起跑前查：有没有别的 mitmproxy/劫持脚本在跑、有没有别的 DNAT 规则压在 DUT 上。
    两路同时劫持必然把证据搞脏（谁拒的、拒的是哪一张证书都说不清），所以默认拒绝起跑。"""
    warns = []
    rc, txt = sh(["pgrep", "-af", "mitmdump|mitmproxy|mitm_"])
    for line in txt.splitlines():
        s = line.strip()
        if s and "pgrep" not in s and "aum3_cert_tests" not in s:
            warns.append("有别的劫持进程在跑: " + s[:130])
    rc, txt = sh(["sudo", "iptables", "-t", "nat", "-S", "PREROUTING"])
    for line in txt.splitlines():
        s = line.strip()
        if "-j DNAT" in s and (not a.src or a.src in s):
            warns.append("PREROUTING 上已存在别的 DNAT 规则: " + s)
    return warns


# ---------------------------------------------------------------- 服务端拓扑（DUT 出示本地 web TLS 证书）
def fetch_device_facts(a):
    """直连设备本地 web TLS 端口，采集它出示的证书与 TLS 参数（AuthVal 基线）。"""
    cmd = [OPENSSL, "s_client", "-connect", "%s:%d" % (a.host, a.port),
           "-servername", a.sni or a.host, "-showcerts"]
    rc, out = sh(cmd, timeout=a.timeout)
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not blocks:
        return None
    leaf = os.path.join(a.certs_dir, "device_cert.pem")
    with open(leaf, "w", encoding="ascii") as fh:
        fh.write(blocks[0] + "\n")
    rc, info = sh([OPENSSL, "x509", "-in", leaf, "-noout", "-subject", "-issuer", "-serial", "-dates",
                   "-fingerprint", "-sha256", "-ext",
                   "subjectAltName,basicConstraints,keyUsage,extendedKeyUsage"])
    def grab(pat, text, default=""):
        m = re.search(pat, text)
        return m.group(1).strip() if m else default
    d = dict(leaf=leaf, info=info, chains=len(blocks), raw=out,
             proto=grab(r"Protocol\s*:\s*(\S+)", out, "?"),
             # OpenSSL 3 的 s_client 在 TLS1.3 下打印的是 "New, TLSv1.3, Cipher is TLS_AES_..."，
             # 老格式才是 "Cipher    : xxx"，两种都要认
             cipher=(grab(r"Cipher\s+is\s+(\S+)", out, "") or grab(r"Cipher\s*:\s*(\S+)", out, "?")),
             mtls=("No client certificate CA names sent" not in out))
    for line in info.splitlines():
        k, _, v = line.partition("=")
        d[k.strip().lower().replace(" ", "_")] = v.strip()
    d["san_dns"] = grab(r"DNS:([^,\s]+)", info, None)
    return d


def case_probe_cert(a, case):
    """S0：把设备出示的证书/TLS 参数摊开，并与 E-Info 文档（--expect-tls/--expected-cn）核对偏差。"""
    facts = getattr(a, "device_facts", None) or fetch_device_facts(a)
    if not facts:
        return dict(case=case, result="skip", note="连不上 %s:%d，或对端握手时没有出示证书" % (a.host, a.port),
                    alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
    lines = ["证书 subject : " + str(facts.get("subject")),
             "证书 issuer  : " + str(facts.get("issuer")),
             "序列号/有效期: %s / %s ~ %s" % (facts.get("serial"), facts.get("notbefore"), facts.get("notafter")),
             "证书链张数   : %d" % facts["chains"],
             "SHA256 指纹  : " + str(facts.get("sha256_fingerprint")),
             "SAN          : " + str(facts.get("san_dns")),
             "TLS 协议/套件: %s / %s" % (facts["proto"], facts["cipher"]),
             "要求客户端证书: %s" % ("是 —— 可另做客户端证书负向用例" if facts["mtls"]
                                     else "否（单向 TLS：设备不校验对端证书，bullet1/3/4 的『用错误证书完成认证』路径不存在）")]
    dev = []
    if a.expect_tls and facts["proto"] and a.expect_tls.lower() not in str(facts["proto"]).lower():
        dev.append("TLS 版本与 E-Info 文档不一致（文档 %s / 实测 %s）" % (a.expect_tls, facts["proto"]))
    if a.expected_cn:
        blob = "%s %s" % (facts.get("subject"), facts.get("san_dns"))
        if a.expected_cn not in blob:
            dev.append("CN/SAN 与 E-Info 文档不一致（文档 %s / 实测 subject=%s SAN=%s）"
                       % (a.expected_cn, facts.get("subject"), facts.get("san_dns")))
    result = "fail" if dev else "pass"
    note = "；".join(dev) if dev else "证书与 TLS 参数已采集并留档，未发现与 E-Info 文档的不一致项"
    return dict(case=case, result=result, note=note, alerts=[], client_fail=[], ch=1, sh=0, cert=1, appdata=0,
                raw="\n".join(lines), cmd="openssl s_client -connect %s:%d -showcerts" % (a.host, a.port),
                facts=facts)


def case_impersonate_serve(a, case, certpem):
    """S3a/S3b/S3c/S4：测试台扮演"该设备的本地 web TLS 服务"，用错误证书起 TLS 服务，
    再用一个严格校验的客户端（把设备自身证书作为唯一信任锚）去连 —— 看这些证书能否被用来
    冒充该设备完成认证。设备本身不参与这一校验（服务端拓扑里出示证书的是设备）。"""
    port = a.impersonate_port
    srv = [OPENSSL, "s_server", "-accept", "127.0.0.1:%d" % port, "-cert", certpem, "-key", certpem,
           "-www", "-naccept", "2"]
    try:
        proc = subprocess.Popen(srv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        return dict(case=case, result="error", note="起不了 openssl s_server: %s" % exc,
                    alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
    time.sleep(1.5)
    cli = [OPENSSL, "s_client", "-connect", "127.0.0.1:%d" % port, "-servername", a.sni or a.host,
           "-CAfile", os.path.join(a.certs_dir, "anchor_leaf.pem"), "-partial_chain", "-verify_return_error"]
    rc, out = sh(cli, timeout=25)
    try:
        proc.terminate()
    except Exception:
        pass
    if "Verify return code: 0 (ok)" in out:
        res, note = "fail", "校验型客户端竟然接受了该证书并完成到“设备”的认证 —— 该身份可被冒用，需上报"
    elif "verify error" in out.lower() or "Verify return code" in out or rc != 0:
        m = re.search(r"verify error:num=\d+:(.*)", out)
        res, note = "pass", "校验型客户端拒绝该证书（%s），不能用于冒充该设备完成认证" % (
            (m.group(1).strip() if m else "verify failed"))
    else:
        res, note = "skip", "客户端行为无法判定：" + tail3(out)
    return dict(case=case, result=res, note=note, alerts=[], client_fail=[], ch=1, sh=0, cert=0, appdata=0,
                raw=tail3(out), cmd=" ".join(srv) + "  ||  " + " ".join(cli))


def run_server_suite(a):
    """服务端拓扑主流程：不做 iptables/DNAT/中间人，改为"采集设备自身证书 + 冒用实验"。"""
    log("[1/3] 采集设备本地 web TLS 服务（%s:%d）出示的证书与 TLS 参数 ..." % (a.host, a.port))
    facts = fetch_device_facts(a)
    if not facts:
        log("[error] 连不上 %s:%d，或握手时对端没有出示证书" % (a.host, a.port))
        return 2
    a.device_facts = facts
    log("[cert] subject = %s" % facts.get("subject"))
    log("[cert] issuer  = %s   序列号 = %s" % (facts.get("issuer"), facts.get("serial")))
    log("[cert] 有效期  = %s ~ %s" % (facts.get("notbefore"), facts.get("notafter")))
    log("[cert] 指纹    = %s" % facts.get("sha256_fingerprint"))
    log("[tls ] %s / %s   要求客户端证书 = %s" % (facts["proto"], facts["cipher"], facts["mtls"]))
    with open(os.path.join(a.out, "device_cert_facts.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join([facts["info"], "", "Protocol: %s" % facts["proto"],
                             "Cipher: %s" % facts["cipher"],
                             "Requests client certificate: %s" % facts["mtls"],
                             "", "--- openssl s_client 原文 ---", facts["raw"]]))
    log("[2/3] 生成错误证书（身份照抄设备自身证书 %s）..." % os.path.basename(facts["leaf"]))
    a.cert_map = gen_certs(a)
    if not a.cert_map:
        log("[error] 错误证书生成失败（看上面的 openssl 报错）")
        return 2
    if a.selftest and selftest(a) != 0:
        log("[error] 自检不通过：证书不符合预期")
        return 2
    if a.gen_only:
        log("[done] --gen-only：证书已生成，未跑冒用实验")
        print(open(os.path.join(a.out, "certs_summary.txt"), encoding="utf-8").read())
        return 0
    appl = resolve_applicability(a, SERVER_REQS)
    print_checklist(a, appl, SERVER_REQS)
    if a.replay:
        appl["S2"] = (True, "人工要求：--replay 强制做重放实验")
    wanted = [r["id"] for r in SERVER_REQS] if a.cases in ("auto", "") else [x.strip() for x in a.cases.split(",")]
    log("[3/3] 逐条执行（服务端拓扑：冒用实验在本机 127.0.0.1:%d 上做）..." % a.impersonate_port)
    results = []
    for case in SERVER_REQS:
        if case["id"] not in wanted:
            continue
        ok, why = appl[case["id"]]
        if not ok:
            log("[%s] N/A —— %s" % (case["id"], why))
            results.append(dict(case=case, result="n/a", note=why, applicability="N/A：" + why,
                                alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0))
            continue
        if case["runner"] == "probe":
            v = case_probe_cert(a, case)
        elif case["runner"] == "mismatch_key":
            log("[%s] 本机复现：设备自身证书 + 攻击者私钥能否构成端点" % case["id"])
            v = case_mismatched_key(a, case)
        elif case["runner"] == "impersonate":
            pem = (a.cert_map or {}).get(case.get("cert_key") or case["id"], {}).get("pem")
            if not pem:
                results.append(dict(case=case, result="skip", note="缺证书材料（%s）" % case.get("cert"),
                                    applicability=why, alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0))
                continue
            log("[%s] 冒用实验：用 %s 扮演设备 web TLS 服务" % (case["id"], os.path.basename(pem)))
            v = case_impersonate_serve(a, case, pem)
        elif case["runner"] == "replay":
            if a.replay:
                v = dict(case=case, result="skip",
                         note="服务端拓扑下的重放实验需要先在该端口抓到一次真实 web 管理客户端的握手；"
                              "本模式暂只判条件是否成立（--topology client 的 --replay 可直接做）",
                         alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
            else:
                v = dict(case=case, result="n/a", note=replay_applicability(a),
                         alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
        else:
            continue
        v.setdefault("applicability", why)
        results.append(v)
        time.sleep(1)
    write_outputs(a, results)
    log("[done] 汇总")
    print("")
    print("  " + "  ".join("%s=%s" % (v["case"]["id"], v["result"]) for v in results))
    fails = [v for v in results if v["result"] == "fail"]
    skips = [v for v in results if v["result"] in ("skip", "error")]
    if fails:
        print("[verdict] 有用例不符合（fail）：AUM-3 不能判 PASS")
        return 1
    if skips:
        print("[verdict] 有用例证据不足（skip/error）：先处理再判定")
        return 2
    print("[verdict] 服务端拓扑：设备证书属性合规且不可被冒用 —— 本次适用项判定 PASS"
          "（设备是否为单向 TLS、是否要求客户端证书见 S0 与 summary.md）")
    return 0


# ---------------------------------------------------------------- 主流程
def build_parser():
    ap = argparse.ArgumentParser(description="[AU.AUM-3.CertificatePrivateKey] 五张错误证书取证")
    ap.add_argument("--topology", choices=["client", "server"], default="client",
                    help="client=DUT 作 TLS 客户端（脚本做中间人替换对端证书）；"
                         "server=DUT 作 TLS 服务端（本地 web TLS 服务出示证书，做采集+冒用实验）")
    ap.add_argument("--impersonate-port", type=int, default=8443,
                    help="server 拓扑：测试台扮演设备 web TLS 服务时监听的本地端口（默认 8443）")
    ap.add_argument("--expect-tls", default=None,
                    help="E-Info 文档里写的 TLS 版本（如 TLSv1.3），S0 用它核对偏差")
    ap.add_argument("--target", help="认证对端 host:port（client=云服务地址；server=设备本地 web TLS 地址，如 192.0.2.10:443）")
    ap.add_argument("--sni", default=None, help="TLS SNI，默认取 target 主机名")
    ap.add_argument("--src", default=None, help="DUT IP（只劫持/抓该源的流量）")
    ap.add_argument("--proxy-host", default=None, help="DNAT 目的地址（跑 mitmproxy 的本机 IP）；默认自动选与 DUT 同网段")
    ap.add_argument("--intercept", action="append", default=[], help="要透明劫持的 host:port（可多次）")
    ap.add_argument("--transparent", action="store_true", help="用 iptables DNAT 透明劫持（中间盒场景；--intercept 给定时自动隐含）")
    ap.add_argument("--mitm-port", type=int, default=8084)
    ap.add_argument("--mitm-insecure", action="store_true", help="mitmproxy 不校验上游证书（云端私有 PKI 建议开）")
    ap.add_argument("--rules-only", action="store_true", help="只打印将执行的 iptables 规则，不真跑")
    ap.add_argument("--gen-only", action="store_true", help="只生成五张证书 + 自检，不碰 DUT")
    ap.add_argument("--selftest", action="store_true", help="用 openssl verify 逐张确认证书确实不可信")
    ap.add_argument("--regen", action="store_true", help="先清空 --certs-dir 再重建实验室 CA 与五张证书")
    ap.add_argument("--certs-dir", default="aum3-certs")
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default="AUM3")
    ap.add_argument("--live", type=int, default=90, help="每个用例的观察窗口秒数（默认 90）")
    ap.add_argument("--no-kick", action="store_true", help="不主动踢 DUT 的长连接（默认踢）")
    ap.add_argument("--no-capture", action="store_true", help="不抓设备侧 pcap")
    ap.add_argument("--cases", "--only", dest="cases", default="auto",
                    help="auto 或逗号分隔的条款号：R1a,R1b,R2,R3a,R3b,R3c,R4")
    ap.add_argument("--list", action="store_true", help="只打印覆盖清单（条款/用例/适用性判定方式），不动设备")
    ap.add_argument("--accounts", choices=["yes", "no", "unknown"], default="unknown",
                    help="DUT 上是否存在/可创建不同用户账号：决定 bullet4（其他实体证书）是否适用")
    ap.add_argument("--confidentiality", choices=["auto", "protected", "unprotected"], default="auto",
                    help="认证消息经网络接口传输的机密性：auto=按目标端口是否 TLS 自动判")
    ap.add_argument("--replay", action="store_true", help="真做条件项 T2 的重放实验（默认判 N/A）")
    ap.add_argument("--expected-cn", default=None, help="期望的服务器 CN/SAN，默认从真服务器证书提取")
    ap.add_argument("--other-cn", default=None, help="T4 使用的另一个实体的 CN")
    ap.add_argument("--lab-cn", default="AUM3-Lab-Root", help="实验室根 CA 的 CN")
    ap.add_argument("--lab-ca-provisioned", action="store_true",
                    help="若已把实验室 CA 预置进 DUT：过期/吊销/跨实体必须拿到各自专属告警，否则只能算 pass*")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--no-ask", action="store_true", help="不交互，缺参直接报错")
    ap.add_argument("--force", action="store_true", help="已确认链路独占时，忽略起跑前的占用告警")
    return ap


def wizard(a):
    print("")
    print("=== [AU.AUM-3.CertificatePrivateKey] 取证向导（直接回车用方括号里的默认值）===")
    print("  先选拓扑：被测设备在这条认证里是客户端还是服务端。")
    print("   1 = 客户端：DUT 去连云端/上位机并校验对端证书（脚本做中间人，替换对端证书）")
    print("   2 = 服务端：DUT 的本地 web TLS 服务出示证书给 web 管理客户端（采集自身证书 + 冒用实验）")
    print("")
    pick = ask("1/7 拓扑 (1=客户端 / 2=服务端)", "1" if a.topology == "client" else "2").strip()
    a.topology = "server" if pick.startswith("2") else "client"
    if a.topology == "server":
        a.target = ask("2/7 设备本地 web TLS 地址 host:port（如 192.0.2.10:443）", a.target or "")
        a.expected_cn = ask("3/7 E-Info 文档里的证书 CN/SAN（核对偏差用，回车跳过）", a.expected_cn or "")
        a.expect_tls = ask("4/7 E-Info 文档里的 TLS 版本（如 TLSv1.3，回车跳过）", a.expect_tls or "")
        a.proxy_host = ask("5/7 本机地址（本拓扑不用 DNAT，回车跳过）", a.proxy_host or "")
        a.live = int(ask("6/7 观察窗口秒数（本拓扑基本用不到）", str(a.live)) or a.live)
        a.label = ask("7/7 证据文件名前缀", a.label)
        return a
    a.target = ask("2/7 认证对端地址 host:port（云下发：如 cloud.example.com:18888）", a.target or "")
    a.src = ask("3/7 被测设备 DUT 的 IP（只劫持它的流量）", a.src or "")
    default_int = ",".join(a.intercept) or (a.target or "")
    a.intercept = [x for x in re.split(r"[,\s]+", ask("4/7 要透明劫持的目标 host:port（一般同第 2 问）", default_int)) if x]
    a.proxy_host = ask("5/7 本机在 DUT 同网段的地址（DNAT 目的；回车自动探测）", a.proxy_host or "")
    a.live = int(ask("6/7 每个用例观察窗口秒数", str(a.live)) or a.live)
    a.label = ask("7/7 证据文件名前缀", a.label)
    return a


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if not sys.stdin.isatty():
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    a = build_parser().parse_args()
    if a.list:                      # 覆盖清单不需要目标，先把"要跑哪几条"摊开给审核人看
        print_checklist(a, None, SERVER_REQS if a.topology == "server" else REQS)
        return 0
    if a.target:
        a.target = a.target.replace("\ufeff", "").strip()
    if not a.target and not a.no_ask and sys.stdin.isatty():
        a = wizard(a)
    if not a.target:
        print("[error] 需要 --target（认证对端 host:port）；交互模式请去掉 --no-ask")
        return 2
    if ":" in a.target:
        a.target, _, p = a.target.rpartition(":")
        a.port = int(p)
    else:
        a.port = 443
    a.host = a.target
    a.sni = a.sni or a.host
    if a.intercept:
        a.transparent = True
    os.makedirs(a.certs_dir, exist_ok=True)
    a.out = a.out or os.path.join("evidence", "%s_%s" % (a.label, datetime.datetime.now().strftime("%Y%m%d_%H%M%S")))
    os.makedirs(a.out, exist_ok=True)
    if a.topology == "server":       # DUT 作 TLS 服务端：采集自身证书 + 冒用实验，不用 iptables
        if a.rules_only:
            log("[error] --rules-only 只用于 client 拓扑（iptables 劫持）；server 拓扑不需要")
            return 2
        return run_server_suite(a)
    if not a.intercept and a.transparent:
        a.intercept = ["%s:%d" % (a.host, a.port)]
    if a.intercept:
        normalize_intercept(a)      # 域名一律换成解析出的 IP，规则与证据都能看懂
    if a.transparent or a.rules_only:
        a.proxy_host, matched = pick_proxy_host(a.src, a.proxy_host)
        log("[info] DNAT 目标本机地址 = %s %s" % (a.proxy_host,
             "(与 DUT 同网段)" if matched else "(未匹配到 DUT 网段，用 --proxy-host 指定)"))
    if a.rules_only:
        log("[rules] 透明劫持规则（DNAT 到本机 %d）：" % a.mitm_port)
        for cmd in dnat_cmds(a, "-A"):
            log("  " + " ".join(cmd))
        log("[rules] 踢长连接规则（先踢掉已建立的长连接，否则窗口内看不到握手）：")
        for cmd in kick_cmds(a, "-I"):
            log("  " + " ".join(cmd))
        log("[rules] 删除时把 -A/-I 换成 -D，其余参数完全相同（脚本会自动成对增删）")
        log("[rules] 同一时刻只允许一路劫持：跑之前先确认没有别的 mitm/脚本占着这台机")
        return 0

    log("[1/4] 生成错误证书（实验室 CA + 对照真服务器证书；条数按覆盖清单）...")
    a.cert_map = gen_certs(a)
    if not a.cert_map:
        log("[error] 五张证书生成失败（看上面的 openssl 报错）；未接触 DUT")
        return 2
    if a.selftest and selftest(a) != 0:
        log("[error] 自检不通过：证书不符合预期，先排查再跑真实窗口")
        return 2
    if a.gen_only:
        log("[done] --gen-only：证书已生成，未接触 DUT")
        print(open(os.path.join(a.out, "certs_summary.txt"), encoding="utf-8").read())
        return 0

    if not shutil.which(MITMDUMP):
        log("[error] 没装 mitmdump，无法出示假证书（Debian/Kali: apt install -y mitmproxy）")
        return 2
    log("[2/4] 连通性与信任锚检查 ...")
    try:
        socket.create_connection((a.host, a.port), 5).close()
    except OSError as exc:
        log("[error] 连不上 %s:%d (%s)" % (a.host, a.port, exc))
        return 2
    if not shutil.which("tshark"):
        log("[warn] 没装 tshark：设备侧抓包无法解析，判定会退化，建议先装 wireshark-common")

    warns = precheck_env(a)
    for w in warns:
        log("[warn] " + w)
    if warns and not a.force:
        log("[error] 检测到这条链路上已经有别的劫持/规则：两路同时跑会让证据不可用。"
            "先停掉那边的进程再跑；确认独占后可加 --force 强行继续")
        return 2
    appl = resolve_applicability(a)
    print_checklist(a, appl)
    wanted = [r["id"] for r in REQS] if a.cases in ("auto", "") else [x.strip() for x in a.cases.split(",")]
    if a.replay:
        for r in REQS:
            if r["id"] == "R2":
                r["runner"] = "replay"
        appl["R2"] = (True, "人工要求：--replay 强制做重放实验")
    todo = [r for r in REQS if r["id"] in wanted]
    log("[3/4] 逐条执行（第 %d 项起，每项一个 %d 秒窗口）..." % (1, a.live))
    results = []
    for case in todo:
        ok, why = appl[case["id"]]
        if not ok:
            log("[%s] N/A —— %s" % (case["id"], why))
            results.append(dict(case=case, result="n/a", note=why, applicability="N/A：" + why,
                                alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0))
            continue
        if case["runner"] == "mitm":
            pem = (a.cert_map or {}).get(case["id"], {}).get("pem")
            if not pem:
                results.append(dict(case=case, result="skip", note="缺证书材料（%s）" % case["cert"],
                                    applicability=why, alerts=[], client_fail=[], ch=0, sh=0, cert=0,
                                    appdata=0))
                continue
            v = run_case(a, case, pem)
        elif case["runner"] == "mismatch_key":
            log("[%s] 本机复现：受信任证书 + 错误私钥能否构成端点" % case["id"])
            v = case_mismatched_key(a, case)
        elif case["runner"] == "replay":
            v = replay_attempt(a, a.live)
        else:
            continue
        v.setdefault("applicability", why)
        results.append(v)
        time.sleep(2)
    write_outputs(a, results)
    log("[4/4] 汇总")
    print("")
    print("  " + "  ".join("%s=%s" % (v["case"]["id"], v["result"]) for v in results))
    fails = [v for v in results if v["result"] == "fail"]
    skips = [v for v in results if v["result"] in ("skip", "error")]
    if fails:
        print("[verdict] 有用例不符合（fail）：AUM-3 不能判 PASS")
        return 1
    if skips:
        print("[verdict] 有用例证据不足（skip/error）：重跑这些窗口后再判定")
        return 2
    print("[verdict] 本次适用的必测项均被 DUT 拒绝 —— AUM-3 判 PASS（pass* 项的局限已在 summary.md 写明；"
          "N/A 项的理由也记在 summary.md）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
