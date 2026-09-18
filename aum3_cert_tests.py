#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""[AU.AUM-3.CertificatePrivateKey] 鍙栬瘉鑴氭湰 鈥斺€?EN 18031-1 / IEC 62443-4-2 TDS 鐢?
瑕嗙洊鏍囧噯鍘熸枃鍥涗釜 bullet銆傛潯鏁颁笉鍐欐锛氭寜鏉℃涓?鍏蜂綋娴嬭瘯鎯呭喌"鍐冲畾锛屾湰娆¤惤鍦?7 鏉?锛坆ullet1 涓ゆ潯褰㈡€併€乥ullet2 鏉′欢椤广€乥ullet3 NOTE 涓夌被鏃犳晥璇佷功鍚勪竴鏉°€乥ullet4 鏉′欢椤癸級锛?
  R1a bullet1 incorrect private keys to a trusted certificate
      -> c1_wrong_key 锛氭部鐢ㄥ彈淇′换璇佷功韬唤锛圖N/搴忓垪鍙蜂竴鑷达級锛屽叕閽?绉侀挜涓烘敾鍑昏€呰嚜鏈夌殑涓€瀵癸紱涓棿浜哄嚭绀恒€?  R1b bullet1 鍚屼笂锛岀函绮瑰舰鎬侊細鐪熷彈淇′换璇佷功 + 鏀诲嚮鑰呯閽ワ紝鏈満 openssl 澶嶇幇"鏋勪笉鍑哄彲鐢ㄧ鐐?銆?  R2  bullet2 replay of a recorded successful authentication attempt
      -> 鏉′欢椤癸細璁よ瘉娑堟伅鏈哄瘑鎬ф湭鍙椾繚鎶ゆ墠閫傜敤锛圱LS 淇濇姢 => N/A锛夛紱--replay 鎵嶇湡鍋氶噸鏀俱€?  R3a bullet3 NOTE invalid chain of trust (untrusted entity with expected CN) -> c3a_untrusted_ca
  R3b bullet3 NOTE expired certificates                                    -> c3b_expired
  R3c bullet3 NOTE certificates revoked by the CA                          -> c3c_revoked + CRL
  R4  bullet4 trusted certificate of other entities锛堟潯浠堕」锛氬瓨鍦ㄤ笉鍚岃处鍙锋墠閫傜敤锛?> c4_other_entity

鏉℃暟涓嶅啓姝伙細姣忔潯鑷繁澹版槑閫傜敤鎬э紝璧疯窇鍓嶇敤 --list 鎽婂紑銆佹寜"鍏蜂綋娴嬭瘯鎯呭喌"锛堝绔槸涓嶆槸 TLS銆?鏄惁瀛樺湪涓嶅悓璐﹀彿銆佹湁鍑犱釜璁よ瘉绔偣/淇′换閿氾級鍐冲畾璺戝摢鍑犳潯銆傚悓涓€鏉℃钀藉湪涓嶅悓璁よ瘉绔偣锛堝浜戦€氶亾
+ 鏈湴 HTTPS锛夋椂锛屽姣忎釜绔偣鍚勮窇涓€杞紙--target 鎹㈢鐐癸級銆?
鍒ゅ畾鍙ｅ緞锛堜弗鏍硷紝閬垮厤鎶娾€滈摼涓嶅彈淇′换鈥濆綋鎴愨€滈€氳繃浜嗚繃鏈?鍚婇攢妫€鏌モ€濓級锛?  pass  锛欴UT 鎷掔粷锛屼笖鍛婅鍘熷洜涓庢湰鐢ㄤ緥瑕佹鐨勫睘鎬т竴鑷达紙濡?T3b 蹇呴』鏄?certificate_expired锛?  pass* 锛欴UT 鎷掔粷锛屼絾鍛婅鍘熷洜钀藉湪鈥滆瘉涔﹂摼/淇′换閿氣€濇鏌ヤ笂 鈥斺€?鍙兘璇佹槑 DUT 鏍￠獙璇佷功锛?          涓嶈兘鍗曠嫭璇佹槑璇ュ睘鎬э紱鑴氭湰娉ㄦ槑闇€鍏堟妸瀹為獙瀹?CA 棰勭疆杩?DUT 鎵嶈兘鍗曟祴銆?  fail  锛欴UT 瀹屾垚浜嗘彙鎵嬶紙鎺ュ彈浜嗛敊璇瘉涔︼級鈥斺€?涓嶇鍚堬紝涓嶈兘鍐?PASS
  skip  锛氱獥鍙ｅ唴娌＄湅鍒?DUT 鍙戣捣鎻℃墜锛堝厛纭 DUT 缃戝叧鎸囧悜鏈満锛屽啀閲嶈窇璇ョ獥鍙ｏ級
  閫€鍑虹爜锛氬叏閮ㄥ繀娴嬮」 pass/pass* -> 0锛涙湁 fail -> 1锛涙湁 skip/error -> 2銆?
鐢ㄦ硶锛?  # 鍙墦鍗板皢鎵ц鐨?iptables 瑙勫垯锛堝厛鍦ㄨ澶囦笂鏍稿锛屽埆鎬ョ潃璺戯級
  python3 aum3_cert_tests.py --target cloud.example.com:18888 --src 172.16.0.4 \
        --proxy-host 172.16.0.1 --intercept 203.0.113.10:18888 --rules-only
  # 鍙敓鎴愪簲寮犺瘉涔?+ 绂荤嚎鑷锛堜笉纰?DUT锛?  python3 aum3_cert_tests.py --target cloud.example.com:18888 --gen-only --selftest
  # 鍏ㄨ嚜鍔ㄨ窇浜斾釜蹇呮祴椤癸紙姣忛」涓€涓獥鍙ｏ級
  sudo python3 aum3_cert_tests.py --target cloud.example.com:18888 --src 172.16.0.4 \
        --proxy-host 172.16.0.1 --intercept 203.0.113.10:18888 --transparent \
        --mitm-insecure --live 90 --label AUM3
  # 鏃犲弬鏁?= 浜や簰鍚戝锛? 闂紝浼氭槑纭棶鈥滃绔槸涓嶆槸浜戜笅鍙戔€濓級

渚濊禆锛歰penssl锛堝繀椤伙級銆乵itmdump锛堝嚭绀哄亣璇佷功锛夈€乼cpdump+tshark锛堣澶囦晶璇佹嵁锛屽己鐑堝缓璁級銆?"""

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

# ---------------------------------------------------------------- 鏍囧噯鏉℃ -> 鐢ㄤ緥锛堟暟鎹┍鍔級
# 瑕嗙洊 EN 18031-1 [AU.AUM-3.CertificatePrivateKey] 鍘熸枃鍥涗釜 bullet銆傛潯鏁颁笉鍐欐锛?# 姣忔潯鑷繁澹版槑閫傜敤鎬э紙app锛夛紝璧疯窇鍓嶆寜"鍏蜂綋娴嬭瘯鎯呭喌"鍒ゅ畾璺戜笉璺?鈥斺€?#   always               : 鏍囧噯鏃犳潯浠惰姹?#   cond:confidentiality : 浠呭綋璁よ瘉娑堟伅缁忕綉缁滄帴鍙ｄ紶杈撴椂鏈哄瘑鎬ф湭鍙椾繚鎶わ紙TLS 淇濇姢鍒?N/A锛?#   cond:accounts        : 浠呭綋瀛樺湪/鍙垱寤轰笉鍚岀敤鎴疯处鍙凤紙--accounts yes|no|unknown锛?# bullet3 鐨?NOTE 缁欎簡涓夌被"鏃犳晥璇佷功"锛屾爣鍑嗙敤 can be 涓句緥锛屽洜姝ゆ媶鎴愪笁鏉″悇鑷垚璇佹嵁銆?REQS = [
    dict(id="R1a", clause="bullet1 incorrect private keys to a trusted certificate",
         title="閿欒绉侀挜 + 娌跨敤鍙椾俊浠昏瘉涔﹁韩浠斤紙涓棿浜哄嚭绀猴級",
         cert="c1_wrong_key", runner="mitm", app="always",
         specific_alerts={"bad_certificate", "decrypt_error", "illegal_parameter", "certificate_unknown"},
         weaker_alerts={"unknown_ca", "handshake_failure", "access_denied"}),
    dict(id="R1b", clause="bullet1 incorrect private keys to a trusted certificate",
         title="鐪熷彈淇′换璇佷功 + 鏀诲嚮鑰呯閽ワ細鑳藉惁鏋勬垚鍙敤璁よ瘉绔偣锛堟湰鏈?openssl 鍘熸牱澶嶇幇锛?,
         cert=None, runner="mismatch_key", app="always",
         specific_alerts={"key_values_mismatch"}, weaker_alerts=set()),
    dict(id="R2", clause="bullet2 replay of a recorded successful authentication attempt",
         title="閲嶆斁宸茶褰曠殑鎴愬姛璁よ瘉锛堟潯浠堕」锛?,
         cert=None, runner="replay", app="cond:confidentiality",
         specific_alerts=set(), weaker_alerts=set()),
    dict(id="R3a", clause="bullet3 NOTE invalid chain of trust (untrusted entity, expected CN)",
         title="涓嶅彈淇′换瀹炰綋绛惧彂銆佷絾 CN/SAN 绗﹀悎鏈熸湜鐨勮瘉涔?,
         cert="c3a_untrusted_ca", runner="mitm", app="always",
         specific_alerts={"unknown_ca", "bad_certificate", "certificate_unknown"},
         weaker_alerts={"handshake_failure"}),
    dict(id="R3b", clause="bullet3 NOTE expired certificates",
         title="CN/SAN 绗﹀悎鏈熸湜銆佷絾宸茶繃鏈熺殑璇佷功",
         cert="c3b_expired", runner="mitm", app="always",
         specific_alerts={"certificate_expired"},
         weaker_alerts={"unknown_ca", "bad_certificate", "certificate_unknown", "handshake_failure"}),
    dict(id="R3c", clause="bullet3 NOTE certificates revoked by the CA",
         title="CN/SAN 绗﹀悎鏈熸湜銆佸凡琚?CA 鍚婇攢鐨勮瘉涔︼紙鍚屾椂鍙戝竷 CRL锛?,
         cert="c3c_revoked", runner="mitm", app="always",
         specific_alerts={"certificate_revoked"},
         weaker_alerts={"unknown_ca", "certificate_unknown", "bad_certificate", "handshake_failure"}),
    dict(id="R4", clause="bullet4 trusted certificate of other entities",
         title="鍚屼竴鍙椾俊浠?CA 涓嬪彟涓€涓疄浣撶殑鍚堟硶璇佷功",
         cert="c4_other_entity", runner="mitm", app="cond:accounts",
         specific_alerts={"bad_certificate", "certificate_unknown", "access_denied"},
         weaker_alerts={"unknown_ca", "handshake_failure"}),
]

ALERT_NAMES = {0: "close_notify", 40: "handshake_failure", 42: "bad_certificate",
               43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
               46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
               49: "access_denied", 51: "decrypt_error", 80: "internal_error"}

TDS_SENTENCE = {
    "R1a": "鍑虹ず娌跨敤鍙椾俊浠昏瘉涔﹁韩浠斤紙DN/搴忓垪鍙蜂竴鑷达級浣嗙閽ヤ负鏀诲嚮鑰呰嚜鏈夌殑璇佷功锛孌UT 鎷掔粷璇ヨ瘉涔︺€佽璇佷笉鎴愮珛",
    "R1b": "鍙椾俊浠昏瘉涔︿笌閿欒绉侀挜鏃犳硶鏋勬垚鍙敤绔偣锛堝姞杞藉嵆 key values mismatch锛夛紝鐢ㄩ敊璇閽ユ棤娉曢€氳繃璁よ瘉",
    "R2": "璁よ瘉娑堟伅缁忕綉缁滄帴鍙ｄ紶杈撶殑鏈哄瘑鎬х敱 TLS 淇濇姢锛屾爣鍑嗚鏉′负鏉′欢椤癸紝鍒ゅ畾 N/A锛堢悊鐢辫涓嬶級",
    "R3a": "鍑虹ず CN/SAN 涓庢湡鏈涘€间竴鑷淬€佷絾璇佷功閾剧敱涓嶅彈淇′换瀹炰綋绛惧彂鐨勮瘉涔︼紝DUT 鎷掔粷璇ヨ瘉涔?,
    "R3b": "鍑虹ず CN/SAN 涓庢湡鏈涘€间竴鑷淬€佷絾宸茶繃鏈熺殑璇佷功锛孌UT 鎷掔粷璇ヨ瘉涔?,
    "R3c": "鍑虹ず鐢?CA 绛惧彂鍚庡悐閿€锛圕RL 宸插垪鍑鸿搴忓垪鍙凤級鐨勮瘉涔︼紝DUT 鎷掔粷璇ヨ瘉涔?,
    "R4": "鍑虹ず鍚屼竴鍙椾俊浠?CA 涓嬪彟涓€涓疄浣撶殑鍚堟硶璇佷功锛孌UT 鎷掔粷璇ヨ瘉涔?,
}


def log(msg):
    print("[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def tail3(txt):
    return " / ".join((txt or "").strip().splitlines()[-3:])


def sh(cmd, timeout=120):
    """璺戝閮ㄥ懡浠わ紝杩斿洖 (rc, stdout+stderr)锛孶TF-8 瀹归敊銆?""
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


# ---------------------------------------------------------------- 缃戠粶/鐜
def ipv4_list():
    out = []
    rc, txt = sh(["ip", "-4", "-o", "addr", "show"], timeout=10)
    for line in txt.splitlines():
        m = re.search(r"[0-9]+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            out.append((m.group(1).split("@")[0], m.group(2), int(m.group(3))))
    return out


def pick_proxy_host(dut_ip, explicit=None):
    """DNAT 鐩殑鍦板潃锛氭樉寮忎紭鍏堬紱鍚﹀垯閫変笌 DUT 鍚岀綉娈电殑鏈満鍦板潃锛堜腑闂寸洅涓婃渶瀹规槗韪╃殑鍧戯級銆?""
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
    """鎶撳寘缃戝崱锛氫笌 DUT 鍚岀綉娈甸偅寮狅紙澶氱綉鍗′腑闂寸洅涓?-i any 浼氭紡鎺夋湰鍦?DNAT 鍚庣殑鎻℃墜锛夈€?""
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
    """璇ユ満 tshark 鎸夎矾寰勬墦寮€ pcap 浼氳鎷掞紙杩?root 閮芥姤 You don't have permission锛夛紝
    浣嗘妸鏂囦欢鍠傝繘 stdin 瀹屽叏姝ｅ父 鈥斺€?缁熶竴璧?tshark -r -銆?""
    if not pcap or not os.path.exists(pcap) or not shutil.which("tshark"):
        return ""
    try:
        with open(pcap, "rb") as fh:
            p = subprocess.run(["tshark", "-r", "-"] + list(extra), stdin=fh,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""
    return p.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------- 瀹為獙瀹?PKI锛堝彧鐢?openssl锛?CNF = """[ ca ]
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
    """鏈€灏?CA 鐩綍 + 瀹為獙瀹ゆ牴 CA锛堜竴娆＄敓鎴愶紝璺ㄧ敤渚嬪鐢級銆?""
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
        log("[error] 鐢熸垚鏍?CA 绉侀挜澶辫触: " + out.strip()[-300:])
        return False
    rc, out = sh([OPENSSL, "req", "-x509", "-new", "-key", rootkey, "-out", rootcrt, "-days", "3650",
                  "-sha256", "-subj", "/O=AUM3-Lab/CN=%s" % a.lab_cn, "-config", cnf,
                  "-extensions", "v3_ca"])
    if rc != 0:
        log("[error] 鐢熸垚鏍?CA 璇佷功澶辫触: " + out.strip()[-300:])
        return False
    log("[pki] 瀹為獙瀹ゆ牴 CA 灏辩华: %s (CN=%s)" % (rootcrt, a.lab_cn))
    return True


def anchor_info(a):
    """浠庣湡鏈嶅姟鍣ㄦ姄鍙跺瓙璇佷功锛岃鍑?CN/SAN/搴忓垪鍙?鏈夋晥鏈燂紝渚涒€滈暱寰楀儚鍙椾俊浠昏瘉涔︹€濈殑鐢ㄤ緥浣跨敤銆?""
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
    """T1 涓撶敤绛惧彂璺緞锛歰penssl 3.x 鐨?ca 瀛愬懡浠ゆ病鏈?-set_serial锛岃€?T1 蹇呴』澶嶇敤鍙椾俊浠昏瘉涔︾殑
    搴忓垪鍙凤紱x509 -req 鏀寔 -set_serial锛屼笖涓嶅啓鍏?CA 鏁版嵁搴?鈥斺€?閲嶅璺戜篃涓嶄細鎾?serial銆?""
    cnf = write_cnf(a, "lab", san)
    csr = os.path.join(a.certs_dir, name + ".csr")
    crt = os.path.join(a.certs_dir, name + ".crt")
    rc, out = sh([OPENSSL, "req", "-new", "-key", keyfile, "-out", csr, "-subj", subject, "-config", cnf])
    if rc != 0:
        log("[error] 鐢熸垚 CSR 澶辫触 %s: %s" % (name, tail3(out)))
        return None
    cmd = [OPENSSL, "x509", "-req", "-in", csr, "-CA", os.path.join(a.certs_dir, "lab_root.crt"),
           "-CAkey", os.path.join(a.certs_dir, "lab_root.key"), "-CAcreateserial", "-out", crt,
           "-days", str(days), "-sha256", "-extfile", cnf, "-extensions", "usr_cert"]
    if serial:
        cmd += ["-set_serial", "0x" + serial.replace(":", "").replace("0x", "").strip()]
    rc, out = sh(cmd)
    if rc != 0 or not os.path.exists(crt):
        log("[error] 绛惧彂 %s 澶辫触: %s" % (name, tail3(out)))
        return None
    return crt


def set_serial_file(a, hexserial):
    """openssl 3.x 鐨?ca 瀛愬懡浠ゆ病鏈?-set_serial锛屾寚瀹氬簭鍒楀彿瑕佸啓 serial 鏂囦欢锛堝ぇ鍐欏崄鍏繘鍒讹級銆?""
    with open(os.path.join(a.certs_dir, "serial"), "w", encoding="utf-8") as fh:
        fh.write(hexserial.strip().upper().replace(":", "") + "\n")


def sign_leaf(a, name, subject, keyfile, serial=None, start=None, end=None, san=None):
    """鐢ㄥ疄楠屽 CA 绛惧彾瀛愯瘉涔︼紱start/end 褰㈠ 20200101000000Z锛堢敤浜庤繃鏈熺敤渚嬶級銆?""
    cnf = write_cnf(a, "lab", san)
    csr = os.path.join(a.certs_dir, name + ".csr")
    crt = os.path.join(a.certs_dir, name + ".crt")
    rc, out = sh([OPENSSL, "req", "-new", "-key", keyfile, "-out", csr, "-subj", subject, "-config", cnf])
    if rc != 0:
        log("[error] 鐢熸垚 CSR 澶辫触 %s: %s" % (name, tail3(out)))
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
        log("[error] 绛惧彂 %s 澶辫触: %s" % (name, tail3(out)))
        return None
    return crt


def make_pem(a, name, crt, key):
    """mitmproxy 鐢細cert+key 鍚堜竴鐨?PEM銆?""
    pem = os.path.join(a.certs_dir, name + ".pem")
    with open(pem, "wb") as fh:
        for p in (crt, key):
            with open(p, "rb") as src:
                fh.write(src.read())
    return pem


def gen_certs(a):
    """鐢熸垚浜斿紶閿欒璇佷功銆傝繑鍥?{case_id: {...}}锛涘け璐ヨ繑鍥?None銆?""
    if a.regen:
        shutil.rmtree(a.certs_dir, ignore_errors=True)
    os.makedirs(a.certs_dir, exist_ok=True)
    if not ca_init(a, force=a.regen):
        return None
    anc = anchor_info(a)
    if not anc:
        log("[error] 鎶撲笉鍒扮湡鏈嶅姟鍣ㄨ瘉涔︼紙%s:%d锛夛紱T1/T3b/T4 闇€瑕佸畠鐨?DN/搴忓垪鍙峰仛瀵圭収" % (a.host, a.port))
        return None
    a.anchor_sha256 = anc.get("sha256_fingerprint", "")
    expected_cn = a.expected_cn or anc.get("san_dns") or anc.get("cn") or a.sni
    expected_san = ("DNS:%s" % expected_cn) if expected_cn else None
    org = "AUM3-Lab"
    m = re.search(r"O\s*=\s*([^,/\n]+)", anc.get("subject", ""))
    if m:
        org = m.group(1).strip()
    serial_anchor = (anc.get("serial") or "").replace(":", "").strip()
    log("[anchor] %s:%d 鍙跺瓙 CN=%s SAN=%s serial=%s 鏈夋晥鏈?%s ~ %s"
        % (a.host, a.port, anc.get("cn"), anc.get("san_dns"), anc.get("serial"),
           anc.get("notbefore"), anc.get("notafter")))
    out = {}
    now = datetime.datetime.now(datetime.timezone.utc)

    # T1锛氳韩浠界収鎶勫彈淇′换璇佷功锛屼絾鍏閽ユ崲鎴愭敾鍑昏€呰嚜鏈夌殑涓€瀵?    k1 = os.path.join(a.certs_dir, "c1_wrong_key.key")
    sh([OPENSSL, "genrsa", "-out", k1, "2048"])
    # T1 璧?x509 -req -set_serial锛屼笉纰?serial 鏂囦欢锛堝惁鍒欎細鎶?CA 鐨勮嚜澧炲簭鍒楀彿甯﹀亸銆?    # 璁╁悗闈㈢殑 T3a 鎾炰笂"serial already in database"锛?    crt = sign_leaf_x509(a, "c1_wrong_key", "/O=%s/CN=%s" % (org, expected_cn), k1,
                         serial=(serial_anchor or "1001"), san=expected_san)
    if not crt:
        return None
    out["R1a"] = dict(pem=make_pem(a, "c1_wrong_key", crt, k1),
                     desc="娌跨敤鍙椾俊浠昏瘉涔﹁韩浠斤細CN=%s銆佸簭鍒楀彿=%s 涓庣湡鏈嶅姟鍣ㄨ瘉涔︿竴鑷达紝浣嗗叕閽?绉侀挜涓烘敾鍑昏€呰嚜鏈夌殑涓€瀵癸紝"
                          "涓旈摼鏉＄敱瀹為獙瀹?CA 鑷 鈥斺€?楠岃瘉鈥滃彈淇′换璇佷功 + 閿欒绉侀挜鈥濊兘鍚﹂€氳繃璁よ瘉"
                          % (expected_cn, serial_anchor))

    # T3a锛氭湡鏈?CN锛屼絾閾炬潯涓嶅彲淇?    k3a = os.path.join(a.certs_dir, "c3a_untrusted_ca.key")
    sh([OPENSSL, "genrsa", "-out", k3a, "2048"])
    crt = sign_leaf(a, "c3a_untrusted_ca", "/O=%s/CN=%s" % (org, expected_cn), k3a, san=expected_san)
    if not crt:
        return None
    out["R3a"] = dict(pem=make_pem(a, "c3a_untrusted_ca", crt, k3a),
                      desc="CN/SAN=%s 涓庢湡鏈涘€间竴鑷达紝浣嗘暣鏉￠摼鐢变笉鍙椾俊浠荤殑瀹為獙瀹?CA 绛惧彂锛坕nvalid chain of trust锛?
                           % expected_cn)

    # T3b锛氭湡鏈?CN锛屼絾鏁村紶璇佷功宸茶繃鏈?    k3b = os.path.join(a.certs_dir, "c3b_expired.key")
    sh([OPENSSL, "genrsa", "-out", k3b, "2048"])
    end = (now - datetime.timedelta(days=400)).strftime("%Y%m%d%H%M%SZ")
    start = (now - datetime.timedelta(days=1200)).strftime("%Y%m%d%H%M%SZ")
    crt = sign_leaf(a, "c3b_expired", "/O=%s/CN=%s" % (org, expected_cn), k3b,
                    start=start, end=end, san=expected_san)
    if not crt:
        return None
    out["R3b"] = dict(pem=make_pem(a, "c3b_expired", crt, k3b),
                      desc="CN/SAN=%s 涓€鑷达紝浣嗘湁鏁堟湡 %s ~ %s 鏁翠綋钀藉湪杩囧幓锛堣繃鏈熻瘉涔︼級"
                           % (expected_cn, start, end))

    # T3c锛氭湡鏈?CN锛岀鍙戝悗绔嬪嵆鍚婇攢锛屽苟鐢熸垚 CRL
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
                      desc="CN/SAN=%s 涓€鑷达紝鐢卞疄楠屽 CA 绛惧彂鍚庣珛鍗冲悐閿€锛孋RL锛?s锛変腑宸插垪鍑哄叾搴忓垪鍙?鈥斺€?楠岃瘉鍚婇攢妫€鏌?
                           % (expected_cn, os.path.basename(crl)))

    # T4锛氬悓涓€ CA 涓嬬殑鈥滃彟涓€涓疄浣撯€?    k4 = os.path.join(a.certs_dir, "c4_other_entity.key")
    sh([OPENSSL, "genrsa", "-out", k4, "2048"])
    other_cn = a.other_cn or ("device-other-%s" % (serial_anchor or "0001")[:8])
    crt = sign_leaf(a, "c4_other_entity", "/O=%s/CN=%s" % (org, other_cn), k4, san="DNS:%s" % other_cn)
    if not crt:
        return None
    out["R4"] = dict(pem=make_pem(a, "c4_other_entity", crt, k4),
                     desc="鐢变唬琛ㄥ彈淇′换 CA 鐨勫疄楠屽 CA 绛惧彂鐨勫悎娉曡瘉涔︼紝浣嗗睘浜庡彟涓€涓疄浣擄紙CN=%s锛屾湡鏈?%s锛夆€斺€?楠岃瘉"
                          "鈥滃叾浠栧疄浣撶殑鍙椾俊浠昏瘉涔︹€濊兘鍚︾敤浜庤璇? % (other_cn, expected_cn))

    # 璇佷功娓呭崟锛堟湰韬氨鏄瘉鎹殑涓€閮ㄥ垎锛?    titles = dict((c["id"], c["title"]) for c in REQS)
    lines = ["# 浜斿紶閿欒璇佷功娓呭崟锛?s锛? % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "- 鐪熸湇鍔″櫒璇佷功锛堝鐓?淇′换閿氾級: %s" % anc.get("pem"), ""]
    for cid in ("R1a", "R3a", "R3b", "R3c", "R4"):
        rc, txt = sh([OPENSSL, "x509", "-in", out[cid]["pem"], "-noout", "-subject", "-issuer",
                      "-serial", "-dates", "-fingerprint", "-sha256"])
        out[cid]["x509"] = txt
        lines += ["## %s  %s" % (cid, titles.get(cid, "")), "鐢ㄩ€? " + out[cid].get("desc", "")] + \
                 ["  " + l for l in txt.strip().splitlines()] + [""]
    with open(os.path.join(a.out, "certs_summary.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return out


def selftest(a):
    """绂荤嚎鑷锛氫簲寮犺瘉涔﹂兘涓嶈兘鐢ㄧ湡鏈嶅姟鍣ㄧ殑绛惧彂閾鹃獙璇侀€氳繃銆?""
    log("[selftest] openssl verify 閫愬紶纭锛圕Afile=鎶撲笅鏉ョ殑鐪熸湇鍔″櫒鍙跺瓙璇佷功锛?)
    bad = 0
    for cid, c in (a.cert_map or {}).items():
        rc, txt = sh([OPENSSL, "verify", "-CAfile", os.path.join(a.certs_dir, "anchor_leaf.pem"), c["pem"]])
        ok = rc != 0
        first = (txt.strip().splitlines() or [""])[0]
        log("  [%s] rc=%d -> %s | %s" % (cid, rc, "涓嶅彲淇★紙绗﹀悎棰勬湡锛? if ok else "绔熺劧鍙俊锛堝紓甯革級", first))
        if not ok:
            bad += 1
    return 0 if bad == 0 else 1


# ---------------------------------------------------------------- 閫忔槑鍔寔 / 鎶撳寘
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
                self.log = "[ERROR] 璧蜂笉浜?%s: %s锛坢itmproxy 鏈畨瑁咃紵锛? % (MITMDUMP, exc)
                log(self.log)
                return False
            for _ in range(120):
                time.sleep(0.1)
                try:
                    socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                    if not modern:
                        log("[warn] 鏈満 mitmdump 涓嶆敮鎸?transparent@PORT锛屽凡鍥為€€ -p PORT --mode transparent")
                    return True
                except OSError:
                    if self.proc.poll() is not None:
                        self.log += self.proc.stdout.read() if self.proc.stdout else ""
                        break
            tail = (self.log.strip().splitlines() or [""])[-1][:160]
            log("[warn] mitmdump 鍚姩澶辫触: " + tail)
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
    """韪㈤暱杩炴帴锛欴NAT 鍙鏂板缓杩炴帴鐢熸晥锛孧QTT/HTTP 闀胯繛鎺ワ紙绌洪棽鍙潤榛樻暟鍒嗛挓锛変笉韪㈠氨鎶撲笉鍒版彙鎵嬨€?    鑰佽繛鎺ヨ蛋 FORWARD锛屽湪杩欓噷 tcp-reset锛汥UT 閲嶈繛鐨勬柊 SYN 鍦?PREROUTING 灏辫 DNAT 璧般€?    涓嶈繘 FORWARD锛屾墍浠ヨ繖鏉?REJECT 涓嶄細鐮村潖鎴戜滑鑷繁鐨勫姭鎸佷細璇濄€?""
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
            log("[warn] 瑙勫垯鎵ц澶辫触: %s" % (p.stdout or "").strip())
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
        log("[warn] 鎶撳寘璧蜂笉鏉? %s" % exc)
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
    """绐楀彛绛夊緟锛氭壒澶勭悊閲?stdin 鐩存帴 EOF 涓嶈兘褰撴垚鈥滄寜浜嗗洖杞︹€濓紝鍚﹀垯绐楀彛 0 绉掑氨鏀跺熬銆?""
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


# ---------------------------------------------------------------- 鍒ゆ嵁
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
    """鎸夆€滆繛鎺モ€濊€屼笉鏄寜鏁存 pcap 缁熻锛氳繑鍥炴弧瓒宠〃杈惧紡鐨勮繛鎺ョ鍙ｉ泦鍚堛€?    璁惧鍙兘鍚屾椂杩樻湁鑰佺殑闀胯繛鎺ュ湪璺戯紝涓嶅尯鍒嗚繛鎺ヤ細鎶婅€佽繛鎺ョ殑搴旂敤鏁版嵁绠楁垚鏈璁よ瘉鎴愬姛銆?""
    txt = tshark_stdin(pcap, ["-Y", expr, "-T", "fields", "-e", field])
    return set(x.strip() for x in txt.splitlines() if x.strip())


def app_data_local(pcap, dut):
    """涓ゆ缁熻锛氣憼 鏈嶅姟鍣ㄥ嚭绀鸿繃璇佷功鐨勯偅浜涜繛鎺ワ紱鈶?DUT 鍙戝嚭杩囧簲鐢ㄦ暟鎹殑閭ｄ簺杩炴帴銆?    鍙湁鈥滃悓涓€鏉¤繛鎺ユ棦琚嚭绀轰簡鎴戜滑鐨勮瘉涔︺€佸張鍑虹幇 DUT 搴旂敤鏁版嵁鈥濇墠绠楃湡姝ｆ帴鍙椾簡璇佷功銆?""
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
    # 鍙湁鈥滃悓涓€鏉¤繛鎺ユ棦鏀跺埌鎴戜滑鐨勮瘉涔︺€佸張琚?DUT 鐢ㄦ潵鍙戝簲鐢ㄦ暟鎹€濇墠绠楁帴鍙楋紱鍏跺畠杩炴帴涓婄殑搴旂敤鏁版嵁
    # 灞炰簬琚涪鏂墠鐨勬棦鏈変細璇濓紝涓嶈兘绠楄繘鏉ワ紙鍚﹀垯浼氭妸鑰佽繛鎺ヨ鍒ゆ垚鈥滄帴鍙椾簡鍋囪瘉涔︹€濓級
    accepted = bool(accepted_ports) and not rejected
    spec = set(case.get("specific_alerts") or [])
    weak = set(case.get("weaker_alerts") or [])
    if rejected and (set(reasons) & spec):
        verdict, note = "pass", "DUT 鎷掔粷锛屼笖鎷掔粷鍘熷洜姝ｆ槸鏈敤渚嬭妫€鐨勫睘鎬?
    elif rejected and (not spec or set(reasons) & weak or reasons):
        verdict, note = "pass*", ("DUT 鎷掔粷锛屼絾鍛婅鍘熷洜钀藉湪璇佷功閾?淇′换閿氭鏌ヤ笂锛?s锛夛細鑳借瘉鏄?DUT 浼氭牎楠岃瘉涔︼紝"
                                  "涓嶈兘鍗曠嫭璇佹槑璇ュ睘鎬э紱瑕佸崟娴嬭繖涓€鏉★紝闇€鍏堟妸瀹為獙瀹?CA 棰勭疆杩?DUT"
                                  % ", ".join(sorted(set(reasons))))
    elif accepted:
        verdict, note = "fail", "DUT 瀹屾垚浜嗘彙鎵嬶紙鎺ュ彈浜嗚繖寮犻敊璇瘉涔︼級鈥斺€?涓嶇鍚堬紝涓嶈兘鍐?PASS"
    elif ch == 0:
        verdict, note = "skip", "绐楀彛鍐呮病鐪嬪埌 DUT 鍙戣捣 TLS 鎻℃墜锛氱‘璁?DUT 缃戝叧鎸囧悜鏈満鍚庨噸璺戞湰绐楀彛"
    else:
        verdict, note = "skip", "璇佹嵁涓嶈冻锛堟湭鎶撳埌 DUT 渚?ClientHello/鍛婅锛?
    if rejected and appdata:
        note += ("锛涚獥鍙ｅ唴鍙︽湁 %d 鏉?DUT 搴旂敤鏁版嵁璁板綍锛岃惤鍦ㄧ鍙?%s 涓婏紝涓庤鍑虹ず璇佷功鐨勮繛鎺ワ紙绔彛 %s锛変笉鏄悓涓€鏉?
                 "锛堝睘琚涪鏂墠鐨勬棦鏈変細璇濓級锛屽垽瀹氫互 DUT 涓诲姩鍛婅涓?mitmproxy 鏃ュ織涓哄噯"
                 % (appdata, ", ".join(sorted(used_ports)) or "-", ", ".join(sorted(served_ports)) or "-"))
    if accepted_ports:
        note += "锛涙敞鎰忥細绔彛 %s 涓婃棦鏈夋垜浠嚭绀虹殑璇佷功銆佸張鏈?DUT 搴旂敤鏁版嵁 鈥斺€?闇€浜哄伐澶嶆牳" % ", ".join(accepted_ports)
    return dict(result=verdict, note=note, alerts=sorted(set(reasons)), client_fail=client_fail,
                ch=ch, sh=shh, cert=cert, appdata=appdata, accepted=accepted,
                served_ports=sorted(served_ports), used_ports=sorted(used_ports),
                accepted_ports=accepted_ports)


def run_case(a, case, certpem):
    log("=" * 78)
    log("[%s] %s" % (case["id"], case["title"]))
    log("      璇佷功: %s" % os.path.basename(certpem))
    apply_rules(dnat_cmds(a, "-A"))
    m = Mitm(a, certpem, case["id"].lower())
    if not m.start():
        apply_rules(dnat_cmds(a, "-D"), quiet=True)
        return dict(case=case, result="error", note="mitmdump 璧蜂笉鏉ワ紙鏈畨瑁呮垨绔彛琚崰锛?,
                    alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0)
    if not a.no_kick:
        log("      韪㈡帀 DUT鈫斿绔殑闀胯繛鎺ワ紙鍚﹀垯绌洪棽闀胯繛鎺ヤ笉浼氶噸杩烇紝绐楀彛鍐呯湅涓嶅埌鎻℃墜锛?)
        apply_rules(kick_cmds(a, "-I"))
    cap, pcap = start_capture(a, "device_" + case["id"].lower())
    log("      绐楀彛 %d 绉?..." % a.live)
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
        log("      DUT 渚у憡璀? " + ", ".join(v["alerts"]))
    return v


# ---------------------------------------------------------------- 鏉′欢椤?T2
def replay_applicability(a):
    return ("閫氶亾 %s:%d 浣跨敤 TLS锛氳璇佹秷鎭粡缃戠粶鎺ュ彛浼犺緭鐨勬満瀵嗘€х敱 TLS 淇濇姢锛?
            "鏍囧噯璇ユ潯锛坮eplay of a recorded successful authentication attempt锛変负鏉′欢椤癸紝"
            "鍦ㄦ湰瀹炵幇涓垽瀹?N/A銆傝嫢鍚庣画鐗堟湰鍙栨秷 TLS 淇濇姢锛岃鍔?--replay 閲嶈窇鏈」銆? % (a.host, a.port))


def replay_attempt(a, seconds):
    """鍙€夛細褰曚竴娆℃垚鍔熸彙鎵嬶紝鍐嶄粠鏈満鍘熸牱閲嶆斁瀹㈡埛绔?TLS 璁板綍锛岀湅鏈嶅姟绔槸鍚︾洿鎺ヨ繘鍏ュ簲鐢ㄦ暟鎹€?""
    log("[T2] 閲嶆斁灏濊瘯锛氬厛褰曚竴娆?DUT 涓庣湡鏈嶅姟鍣ㄧ殑鎴愬姛鎻℃墜 ...")
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
        return dict(case=case, result="skip", note="娌″綍鍒版垚鍔熸彙鎵嬶紝閲嶆斁鏃犱粠璋堣捣锛堝厛纭 DUT 鑳借繛涓婄湡鏈嶅姟鍣級",
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
    log("[T2] 褰曞埌瀹㈡埛绔瓧鑺傛祦 %d 瀛楄妭锛屽悜鐪熸湇鍔″櫒鍘熸牱閲嶆斁 ..." % len(stream))
    try:
        s = socket.create_connection((a.host, a.port), 10)
        s.settimeout(10)
        s.sendall(stream)
        resp = s.recv(4096)
        s.close()
    except OSError as exc:
        return dict(case=case, result="skip", note="閲嶆斁鏃剁綉缁滃紓甯? %s" % exc, alerts=[], client_fail=[],
                    ch=ch, sh=shh, cert=cert, appdata=app, pcap=pcap)
    is_alert = len(resp) > 5 and resp[0] == 0x15
    res = "pass" if is_alert else "fail"
    note = ("鏈嶅姟绔互 TLS alert 鎷掔粷閲嶆斁锛?d 瀛楄妭锛屽ご %s锛? % (len(resp), resp[:5].hex(" ")) if is_alert
            else "鏈嶅姟绔湭鎷掔粷閲嶆斁锛堣繑鍥?%d 瀛楄妭锛岄潪 alert锛夆€斺€?闇€浜哄伐澶嶆牳" % len(resp))
    return dict(case=case, result=res, note=note, alerts=[], client_fail=[], ch=ch, sh=shh,
                cert=cert, appdata=app, pcap=pcap, replay_bytes=len(stream))


# ---------------------------------------------------------------- 杈撳嚭
def write_outputs(a, results):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# [AU.AUM-3.CertificatePrivateKey] 鍙栬瘉 summary", "",
             "- 鏃堕棿: " + stamp,
             "- 璁よ瘉瀵圭: %s:%d (SNI %s)" % (a.host, a.port, a.sni or a.host),
             "- DUT: %s    涓棿鐩? %s (%s)" % (a.src, a.proxy_host, iface_for(a.src)),
             "- 瀹為獙瀹?CA: " + os.path.join(a.certs_dir, "lab_root.crt"),
             "- 淇′换閿氾紙鐪熸湇鍔″櫒鍙跺瓙锛? " + os.path.join(a.certs_dir, "anchor_leaf.pem"),
             "- 瀹為獙瀹?CA 鏄惁宸查缃繘 DUT: %s" % ("鏄? if a.lab_ca_provisioned else "鍚?),
             "- 鍔寔鐩爣瑙ｆ瀽: " + (json.dumps(getattr(a, "intercept_map", {}), ensure_ascii=False) or "-"),
             "- 鏈嶅姟鍣ㄨ瘉涔?SHA256: " + (getattr(a, "anchor_sha256", "") or "-"), "",
             "| 鐢ㄤ緥 | 瑕嗙洊鏍囧噯鏉℃ | 閫傜敤鎬у垽瀹?| 缁撴灉 | 璇佷功 |", "|---|---|---|---|---|"]
    for v in results:
        c = v["case"]
        cm = (a.cert_map or {}).get(c["id"], {}) or {}
        lines.append("| %s | %s | %s | %s | %s |"
                     % (c["id"], c.get("clause", "conditional"),
                        v.get("applicability", "閫傜敤"), v["result"],
                        os.path.basename(cm.get("pem", "")) or "-"))
    lines += ["", "## 閫愭潯璇佹嵁"]
    for v in results:
        c = v["case"]
        cm = (a.cert_map or {}).get(c["id"], {}) or {}
        lines += ["", "### %s 鈥?%s" % (c["id"], c.get("title", "")),
                  "- 缁撴灉: " + v["result"],
                  "- 鍒ゅ畾: " + v["note"],
                  "- 閫傜敤鎬? " + v.get("applicability", "閫傜敤"),
                  "- 鐢ㄤ緥璇存槑: " + (cm.get("desc") or "-"),
                  "- 璁惧渚ф姄鍖? " + os.path.basename(v.get("pcap") or "-"),
                  "- 璁℃暟: DUT ClientHello %d / 鏈嶅姟鍣?ServerHello %d / 鏈嶅姟鍣ㄨ瘉涔?%d / DUT 搴旂敤鏁版嵁 %d"
                  % (v["ch"], v["sh"], v["cert"], v["appdata"]),
                  "- DUT 渚?TLS 鍛婅: " + (", ".join(v["alerts"]) or "锛堟棤锛汿LS1.3 鐨?alert 涓哄瘑鏂囨椂浠ユ棩蹇椾负鍑嗭級"),
                  "- 瀹㈡埛绔晶鎻℃墜澶辫触鏃ュ織: " + (v["client_fail"][0] if v["client_fail"] else "锛堟棤锛?),
                  "- 璧峰仠鍛戒护: " + (v.get("cmd") or "-"),
                  "- 鏈満澶嶇幇/鍘熷杈撳嚭: " + (v.get("raw") or "-"),
                  "- TDS 缁撹鍙? " + TDS_SENTENCE.get(c["id"], "")]
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
    log("[out] " + os.path.abspath(a.out) + "  锛坰ummary.md / report.json / certs_summary.txt / device_*.pcap锛?)


# ---------------------------------------------------------------- 閫傜敤鎬у垽瀹氾紙鎸夊叿浣撴祴璇曟儏鍐碉級
def confidentiality_protected(a):
    """鐩爣绔彛鏄笉鏄?TLS锛堣璇佹秷鎭粡缃戠粶鎺ュ彛浼犺緭鐨勬満瀵嗘€ф槸鍚﹀彈淇濇姢锛夈€?""
    if a.confidentiality == "protected":
        return True, "--confidentiality protected锛堜汉宸ユ寚瀹氾級"
    if a.confidentiality == "unprotected":
        return False, "--confidentiality unprotected锛堜汉宸ユ寚瀹氾級"
    rc, out = sh([OPENSSL, "s_client", "-connect", "%s:%d" % (a.host, a.port),
                  "-servername", a.sni or a.host], timeout=20)
    if "BEGIN CERTIFICATE" in out or "Verify return code" in out or "Protocol" in out:
        return True, "鐩爣 %s:%d 涓?TLS 鏈嶅姟锛岃璇佹秷鎭殑鏈哄瘑鎬х敱 TLS 淇濇姢" % (a.host, a.port)
    return False, "鏈兘鍦?%s:%d 涓婂缓绔?TLS锛堝彲鑳芥槸涓嶅姞瀵嗙殑鑷畾涔夊崗璁級锛屾寜鏈哄瘑鎬ф湭鍙椾繚鎶ゅ鐞? % (a.host, a.port)


def resolve_applicability(a):
    """閫愭潯鍒ゅ畾"杩欐鍒板簳瑕佷笉瑕佽窇"锛岃繑鍥?{id: (bool, 鐞嗙敱)}銆?""
    prot, why_prot = confidentiality_protected(a)
    out = {}
    for r in REQS:
        app = r.get("app", "always")
        if app == "always":
            out[r["id"]] = (True, "鏍囧噯鏃犳潯浠惰姹?)
        elif app == "cond:confidentiality":
            out[r["id"]] = ((not prot),
                            ("鏉′欢鎴愮珛锛?s" % why_prot) if not prot
                            else ("鏉′欢涓嶆垚绔?-> N/A锛?s锛涙爣鍑嗚鏉″彧鍦ㄦ満瀵嗘€ф湭鍙椾繚鎶ゆ椂鎵嶈姹? % why_prot))
        elif app == "cond:accounts":
            if a.accounts == "no":
                out[r["id"]] = (False, "鏉′欢涓嶆垚绔?-> N/A锛?-accounts no锛圖UT 涓婁笉瀛樺湪涔熸棤娉曞垱寤轰笉鍚岀敤鎴疯处鍙凤級")
            elif a.accounts == "yes":
                out[r["id"]] = (True, "鏉′欢鎴愮珛锛?-accounts yes锛堝瓨鍦?鍙垱寤轰笉鍚岀敤鎴疯处鍙凤級")
            else:
                out[r["id"]] = (True, "鎸夐€傜敤鎵ц锛?-accounts unknown锛屼笉鍚岃处鍙锋槸鍚﹀瓨鍦ㄩ渶浜哄伐纭锛?
                                      "鏈敤渚嬬粨鏋滄湰韬鍒ゅ畾鏈夋晥锛堝叾浠栧疄浣撶殑鍙椾俊浠昏瘉涔︿篃蹇呴』琚嫆锛?)
        else:
            out[r["id"]] = (True, "鏈煡閫傜敤鎬ц鍒欙紝鎸夐€傜敤澶勭悊")
    return out


def print_checklist(a, appl=None):
    """鎵撳嵃鏉℃瑕嗙洊娓呭崟锛氳繖鏉¤涓嶈璺戙€佺敤浠€涔堣瘉涔︺€佸垽瀹氭柟寮忋€?""
    print("")
    print("# [AU.AUM-3.CertificatePrivateKey] 瑕嗙洊娓呭崟锛?d 鏉★紝鏉℃暟鎸夊疄闄呮祴璇曟儏鍐靛喅瀹氾級" % len(REQS))
    print("")
    print("| 鐢ㄤ緥 | 鏍囧噯鏉℃ | 鐢ㄤ緥鍐呭 | 鎵€闇€鏉愭枡 | 閫傜敤鎬?|")
    print("|---|---|---|---|---|")
    for r in REQS:
        cert = r.get("cert") and (r["cert"] + ".pem") or ("鏈満 openssl 澶嶇幇" if r["runner"] == "mismatch_key"
                                                          else "褰曞埗+閲嶆斁")
        if appl:
            ok, why = appl[r["id"]]
            apptxt = ("閫傜敤" if ok else "N/A") + "锛? + why
        else:
            apptxt = {"always": "鏃犳潯浠堕€傜敤",
                      "cond:confidentiality": "浠呭綋鏈哄瘑鎬ф湭鍙椾繚鎶わ紙--confidentiality auto|protected|unprotected锛?,
                      "cond:accounts": "浠呭綋瀛樺湪涓嶅悓璐﹀彿锛?-accounts yes|no|unknown锛?}.get(r.get("app"), "-")
        print("| %s | %s | %s | %s | %s |" % (r["id"], r["clause"], r["title"], cert, apptxt))
    print("")
    print("鍒ゅ畾鍙ｅ緞锛欴UT 鎷掔粷涓斿憡璀﹀師鍥?璇ユ潯娆捐妫€鐨勫睘鎬?-> pass锛涙嫆缁濅絾鍘熷洜钀藉湪璇佷功閾?淇′换閿?-> pass*锛?)
    print("           DUT 瀹屾垚鎻℃墜 -> fail锛涚獥鍙ｅ唴娌℃湁鎻℃墜 -> skip锛涙潯浠朵笉鎴愮珛 -> n/a銆?)


def case_mismatched_key(a, case):
    """bullet1 鐨勭函绮瑰舰鎬侊細鎶?鐪熸湇鍔″櫒鐨勫彈淇′换璇佷功"涓?鏀诲嚮鑰呰嚜鏈夌殑绉侀挜"鍑戝湪涓€璧凤紝
    鐪嬭兘鍚︽瀯鎴愪竴涓彲鐢ㄧ殑璁よ瘉绔偣銆俹penssl 鍔犺浇鏃跺氨浼氭嫆缁濓紙key values mismatch锛夛紝
    涔熷氨鏄繖绉嶇粍鍚堟牴鏈棤娉曞紑濮嬫彙鎵?鈥斺€?鐢ㄩ敊璇閽ヤ笉鍙兘閫氳繃璁よ瘉銆?    璇佹嵁=鏈満 openssl 鐨勫師鏍疯緭鍑猴紙涓嶄緷璧?mitmproxy锛夈€?""
    realcert = os.path.join(a.certs_dir, "anchor_leaf.pem")
    wrongkey = os.path.join(a.certs_dir, "c1_wrong_key.key")
    port = a.mitm_port or 8443
    cmd = [OPENSSL, "s_server", "-accept", str(port), "-cert", realcert, "-key", wrongkey,
           "-www", "-naccept", "1"]
    rc, out = sh(cmd, timeout=8)
    if re.search(r"key values mismatch|no cert matches|cannot load", out, re.I):
        res, note = "pass", ("鍙椾俊浠昏瘉涔?+ 閿欒绉侀挜鏃犳硶鏋勬垚鍙敤绔偣锛歰penssl 鍔犺浇鍗虫姤 key values mismatch锛?
                             "鎻℃墜鏍规湰鏃犳硶寮€濮?鈥斺€?鐢ㄩ敊璇閽ユ棤娉曢€氳繃璁よ瘉")
    elif rc == 124:
        res, note = "fail", "璇ョ粍鍚堢珶鐒惰兘璧?TLS 绔偣骞剁瓑寰呰繛鎺ワ紝闇€浜哄伐澶嶆牳锛堝彈淇′换璇佷功涓庨敊璇閽ヤ负浣曡兘閰嶅锛?
    else:
        res, note = "skip", "鍒ゅ畾涓嶄簡锛歰penssl 杈撳嚭寮傚父 -> " + tail3(out)
    return dict(case=case, result=res, note=note, alerts=[], client_fail=[], ch=0, sh=0, cert=0,
                appdata=0, cmd=" ".join(cmd), raw=tail3(out))


# ---------------------------------------------------------------- 璧疯窇鍓嶇幆澧冧簰鏂ユ鏌?def resolve_one(host):
    """鎶?host 瑙ｆ瀽鎴?IPv4锛歩ptables 閲屽啓鍩熷悕浼氬湪 -A/-D 涓ゆ鍚勮嚜瑙ｆ瀽锛岃鍒欏鏄撳涓嶄笂锛?    璇佹嵁閲屼篃鐪嬩笉鎳傛槸鎵撳埌鍝釜鍦板潃銆傝繑鍥?(ip, 鍏ㄩ儴 A 璁板綍)銆?""
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
    """鎶?--intercept 閲岀殑鍩熷悕鎹㈡垚瑙ｆ瀽鍑虹殑 IP锛屽苟鎶婅В鏋愮粨鏋滆杩涜瘉鎹€?""
    out, mapping = [], {}
    for item in a.intercept:
        host, _, prt = item.partition(":")
        ip, ips = resolve_one(host)
        if len(ips) > 1:
            log("[warn] %s 瑙ｆ瀽鍒板涓湴鍧€ %s锛氭湰娆″彧鍔寔 %s锛涜嫢 DUT 杩炵殑鏄埆鐨勫湴鍧€锛岃鐩存帴鍐欓偅涓湴鍧€"
                % (host, ips, ip))
        mapping[host] = ips
        out.append("%s:%s" % (ip, prt or "443"))
        if ip != host:
            log("[info] 鍔寔鐩爣 %s -> %s锛圖NAT 鎸?IP 涓嬪彂锛岄伩鍏嶅煙鍚嶄簩娆¤В鏋愬涓嶄笂锛? % (host, ip))
    a.intercept, a.intercept_map = out, mapping
    return mapping


def precheck_env(a):
    """璧疯窇鍓嶆煡锛氭湁娌℃湁鍒殑 mitmproxy/鍔寔鑴氭湰鍦ㄨ窇銆佹湁娌℃湁鍒殑 DNAT 瑙勫垯鍘嬪湪 DUT 涓娿€?    涓よ矾鍚屾椂鍔寔蹇呯劧鎶婅瘉鎹悶鑴忥紙璋佹嫆鐨勩€佹嫆鐨勬槸鍝竴寮犺瘉涔﹂兘璇翠笉娓咃級锛屾墍浠ラ粯璁ゆ嫆缁濊捣璺戙€?""
    warns = []
    rc, txt = sh(["pgrep", "-af", "mitmdump|mitmproxy|mitm_"])
    for line in txt.splitlines():
        s = line.strip()
        if s and "pgrep" not in s and "aum3_cert_tests" not in s:
            warns.append("鏈夊埆鐨勫姭鎸佽繘绋嬪湪璺? " + s[:130])
    rc, txt = sh(["sudo", "iptables", "-t", "nat", "-S", "PREROUTING"])
    for line in txt.splitlines():
        s = line.strip()
        if "-j DNAT" in s and (not a.src or a.src in s):
            warns.append("PREROUTING 涓婂凡瀛樺湪鍒殑 DNAT 瑙勫垯: " + s)
    return warns


# ---------------------------------------------------------------- 涓绘祦绋?def build_parser():
    ap = argparse.ArgumentParser(description="[AU.AUM-3.CertificatePrivateKey] 浜斿紶閿欒璇佷功鍙栬瘉")
    ap.add_argument("--target", help="璁よ瘉瀵圭 host:port锛堜簯涓嬪彂鍦烘櫙濉簯鏈嶅姟鍦板潃锛屽 cloud.example.com:18888锛?)
    ap.add_argument("--sni", default=None, help="TLS SNI锛岄粯璁ゅ彇 target 涓绘満鍚?)
    ap.add_argument("--src", default=None, help="DUT IP锛堝彧鍔寔/鎶撹婧愮殑娴侀噺锛?)
    ap.add_argument("--proxy-host", default=None, help="DNAT 鐩殑鍦板潃锛堣窇 mitmproxy 鐨勬湰鏈?IP锛夛紱榛樿鑷姩閫変笌 DUT 鍚岀綉娈?)
    ap.add_argument("--intercept", action="append", default=[], help="瑕侀€忔槑鍔寔鐨?host:port锛堝彲澶氭锛?)
    ap.add_argument("--transparent", action="store_true", help="鐢?iptables DNAT 閫忔槑鍔寔锛堜腑闂寸洅鍦烘櫙锛?-intercept 缁欏畾鏃惰嚜鍔ㄩ殣鍚級")
    ap.add_argument("--mitm-port", type=int, default=8084)
    ap.add_argument("--mitm-insecure", action="store_true", help="mitmproxy 涓嶆牎楠屼笂娓歌瘉涔︼紙浜戠绉佹湁 PKI 寤鸿寮€锛?)
    ap.add_argument("--rules-only", action="store_true", help="鍙墦鍗板皢鎵ц鐨?iptables 瑙勫垯锛屼笉鐪熻窇")
    ap.add_argument("--gen-only", action="store_true", help="鍙敓鎴愪簲寮犺瘉涔?+ 鑷锛屼笉纰?DUT")
    ap.add_argument("--selftest", action="store_true", help="鐢?openssl verify 閫愬紶纭璇佷功纭疄涓嶅彲淇?)
    ap.add_argument("--regen", action="store_true", help="鍏堟竻绌?--certs-dir 鍐嶉噸寤哄疄楠屽 CA 涓庝簲寮犺瘉涔?)
    ap.add_argument("--certs-dir", default="aum3-certs")
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default="AUM3")
    ap.add_argument("--live", type=int, default=90, help="姣忎釜鐢ㄤ緥鐨勮瀵熺獥鍙ｇ鏁帮紙榛樿 90锛?)
    ap.add_argument("--no-kick", action="store_true", help="涓嶄富鍔ㄨ涪 DUT 鐨勯暱杩炴帴锛堥粯璁よ涪锛?)
    ap.add_argument("--no-capture", action="store_true", help="涓嶆姄璁惧渚?pcap")
    ap.add_argument("--cases", "--only", dest="cases", default="auto",
                    help="auto 鎴栭€楀彿鍒嗛殧鐨勬潯娆惧彿锛歊1a,R1b,R2,R3a,R3b,R3c,R4")
    ap.add_argument("--list", action="store_true", help="鍙墦鍗拌鐩栨竻鍗曪紙鏉℃/鐢ㄤ緥/閫傜敤鎬у垽瀹氭柟寮忥級锛屼笉鍔ㄨ澶?)
    ap.add_argument("--accounts", choices=["yes", "no", "unknown"], default="unknown",
                    help="DUT 涓婃槸鍚﹀瓨鍦?鍙垱寤轰笉鍚岀敤鎴疯处鍙凤細鍐冲畾 bullet4锛堝叾浠栧疄浣撹瘉涔︼級鏄惁閫傜敤")
    ap.add_argument("--confidentiality", choices=["auto", "protected", "unprotected"], default="auto",
                    help="璁よ瘉娑堟伅缁忕綉缁滄帴鍙ｄ紶杈撶殑鏈哄瘑鎬э細auto=鎸夌洰鏍囩鍙ｆ槸鍚?TLS 鑷姩鍒?)
    ap.add_argument("--replay", action="store_true", help="鐪熷仛鏉′欢椤?T2 鐨勯噸鏀惧疄楠岋紙榛樿鍒?N/A锛?)
    ap.add_argument("--expected-cn", default=None, help="鏈熸湜鐨勬湇鍔″櫒 CN/SAN锛岄粯璁や粠鐪熸湇鍔″櫒璇佷功鎻愬彇")
    ap.add_argument("--other-cn", default=None, help="T4 浣跨敤鐨勫彟涓€涓疄浣撶殑 CN")
    ap.add_argument("--lab-cn", default="AUM3-Lab-Root", help="瀹為獙瀹ゆ牴 CA 鐨?CN")
    ap.add_argument("--lab-ca-provisioned", action="store_true",
                    help="鑻ュ凡鎶婂疄楠屽 CA 棰勭疆杩?DUT锛氳繃鏈?鍚婇攢/璺ㄥ疄浣撳繀椤绘嬁鍒板悇鑷笓灞炲憡璀︼紝鍚﹀垯鍙兘绠?pass*")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--no-ask", action="store_true", help="涓嶄氦浜掞紝缂哄弬鐩存帴鎶ラ敊")
    ap.add_argument("--force", action="store_true", help="宸茬‘璁ら摼璺嫭鍗犳椂锛屽拷鐣ヨ捣璺戝墠鐨勫崰鐢ㄥ憡璀?)
    return ap


def wizard(a):
    print("")
    print("=== [AU.AUM-3.CertificatePrivateKey] 鍙栬瘉鍚戝锛堢洿鎺ュ洖杞︾敤鏂规嫭鍙烽噷鐨勯粯璁ゅ€硷級===")
    print("  鍦烘櫙鎻愮ず锛欴UT 鐢ㄨ瘉涔﹁璇佸绔€傝嫢瀵圭璇佷功鏉ヨ嚜浜戞湇鍔″櫒涓嬪彂锛?)
    print("  绗?1 闂濉€愪簯鏈嶅姟鍦板潃銆戯紝涓嶈濉?DUT 鑷繁鐨勫湴鍧€銆?)
    print("")
    a.target = ask("1/6 璁よ瘉瀵圭鍦板潃 host:port锛堜簯涓嬪彂锛氬 cloud.example.com:18888锛?, a.target or "")
    a.src = ask("2/6 琚祴璁惧 DUT 鐨?IP锛堝彧鍔寔瀹冪殑娴侀噺锛?, a.src or "")
    default_int = ",".join(a.intercept) or (a.target or "")
    a.intercept = [x for x in re.split(r"[,\s]+", ask("3/6 瑕侀€忔槑鍔寔鐨勭洰鏍?host:port锛堜竴鑸悓绗?1 闂級", default_int)) if x]
    a.proxy_host = ask("4/6 鏈満鍦?DUT 鍚岀綉娈电殑鍦板潃锛圖NAT 鐩殑锛涘洖杞﹁嚜鍔ㄦ帰娴嬶級", a.proxy_host or "")
    a.live = int(ask("5/6 姣忎釜鐢ㄤ緥瑙傚療绐楀彛绉掓暟", str(a.live)) or a.live)
    a.label = ask("6/6 璇佹嵁鏂囦欢鍚嶅墠缂€", a.label)
    return a


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if not sys.stdin.isatty():
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    a = build_parser().parse_args()
    if a.list:                      # 瑕嗙洊娓呭崟涓嶉渶瑕佺洰鏍囷紝鍏堟妸"瑕佽窇鍝嚑鏉?鎽婂紑缁欏鏍镐汉鐪?        print_checklist(a)
        return 0
    if a.target:
        a.target = a.target.replace("\ufeff", "").strip()
    if not a.target and not a.no_ask and sys.stdin.isatty():
        a = wizard(a)
    if not a.target:
        print("[error] 闇€瑕?--target锛堣璇佸绔?host:port锛夛紱浜や簰妯″紡璇峰幓鎺?--no-ask")
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
    if not a.intercept and a.transparent:
        a.intercept = ["%s:%d" % (a.host, a.port)]
    if a.intercept:
        normalize_intercept(a)      # 鍩熷悕涓€寰嬫崲鎴愯В鏋愬嚭鐨?IP锛岃鍒欎笌璇佹嵁閮借兘鐪嬫噦
    if a.transparent or a.rules_only:
        a.proxy_host, matched = pick_proxy_host(a.src, a.proxy_host)
        log("[info] DNAT 鐩爣鏈満鍦板潃 = %s %s" % (a.proxy_host,
             "(涓?DUT 鍚岀綉娈?" if matched else "(鏈尮閰嶅埌 DUT 缃戞锛岀敤 --proxy-host 鎸囧畾)"))
    if a.rules_only:
        log("[rules] 閫忔槑鍔寔瑙勫垯锛圖NAT 鍒版湰鏈?%d锛夛細" % a.mitm_port)
        for cmd in dnat_cmds(a, "-A"):
            log("  " + " ".join(cmd))
        log("[rules] 韪㈤暱杩炴帴瑙勫垯锛堝厛韪㈡帀宸插缓绔嬬殑闀胯繛鎺ワ紝鍚﹀垯绐楀彛鍐呯湅涓嶅埌鎻℃墜锛夛細")
        for cmd in kick_cmds(a, "-I"):
            log("  " + " ".join(cmd))
        log("[rules] 鍒犻櫎鏃舵妸 -A/-I 鎹㈡垚 -D锛屽叾浣欏弬鏁板畬鍏ㄧ浉鍚岋紙鑴氭湰浼氳嚜鍔ㄦ垚瀵瑰鍒狅級")
        log("[rules] 鍚屼竴鏃跺埢鍙厑璁镐竴璺姭鎸侊細璺戜箣鍓嶅厛纭娌℃湁鍒殑 mitm/鑴氭湰鍗犵潃杩欏彴鏈?)
        return 0

    log("[1/4] 鐢熸垚閿欒璇佷功锛堝疄楠屽 CA + 瀵圭収鐪熸湇鍔″櫒璇佷功锛涙潯鏁版寜瑕嗙洊娓呭崟锛?..")
    a.cert_map = gen_certs(a)
    if not a.cert_map:
        log("[error] 浜斿紶璇佷功鐢熸垚澶辫触锛堢湅涓婇潰鐨?openssl 鎶ラ敊锛夛紱鏈帴瑙?DUT")
        return 2
    if a.selftest and selftest(a) != 0:
        log("[error] 鑷涓嶉€氳繃锛氳瘉涔︿笉绗﹀悎棰勬湡锛屽厛鎺掓煡鍐嶈窇鐪熷疄绐楀彛")
        return 2
    if a.gen_only:
        log("[done] --gen-only锛氳瘉涔﹀凡鐢熸垚锛屾湭鎺ヨЕ DUT")
        print(open(os.path.join(a.out, "certs_summary.txt"), encoding="utf-8").read())
        return 0

    if not shutil.which(MITMDUMP):
        log("[error] 娌¤ mitmdump锛屾棤娉曞嚭绀哄亣璇佷功锛圖ebian/Kali: apt install -y mitmproxy锛?)
        return 2
    log("[2/4] 杩為€氭€т笌淇′换閿氭鏌?...")
    try:
        socket.create_connection((a.host, a.port), 5).close()
    except OSError as exc:
        log("[error] 杩炰笉涓?%s:%d (%s)" % (a.host, a.port, exc))
        return 2
    if not shutil.which("tshark"):
        log("[warn] 娌¤ tshark锛氳澶囦晶鎶撳寘鏃犳硶瑙ｆ瀽锛屽垽瀹氫細閫€鍖栵紝寤鸿鍏堣 wireshark-common")

    warns = precheck_env(a)
    for w in warns:
        log("[warn] " + w)
    if warns and not a.force:
        log("[error] 妫€娴嬪埌杩欐潯閾捐矾涓婂凡缁忔湁鍒殑鍔寔/瑙勫垯锛氫袱璺悓鏃惰窇浼氳璇佹嵁涓嶅彲鐢ㄣ€?
            "鍏堝仠鎺夐偅杈圭殑杩涚▼鍐嶈窇锛涚‘璁ょ嫭鍗犲悗鍙姞 --force 寮鸿缁х画")
        return 2
    appl = resolve_applicability(a)
    print_checklist(a, appl)
    wanted = [r["id"] for r in REQS] if a.cases in ("auto", "") else [x.strip() for x in a.cases.split(",")]
    if a.replay:
        for r in REQS:
            if r["id"] == "R2":
                r["runner"] = "replay"
        appl["R2"] = (True, "浜哄伐瑕佹眰锛?-replay 寮哄埗鍋氶噸鏀惧疄楠?)
    todo = [r for r in REQS if r["id"] in wanted]
    log("[3/4] 閫愭潯鎵ц锛堢 %d 椤硅捣锛屾瘡椤逛竴涓?%d 绉掔獥鍙ｏ級..." % (1, a.live))
    results = []
    for case in todo:
        ok, why = appl[case["id"]]
        if not ok:
            log("[%s] N/A 鈥斺€?%s" % (case["id"], why))
            results.append(dict(case=case, result="n/a", note=why, applicability="N/A锛? + why,
                                alerts=[], client_fail=[], ch=0, sh=0, cert=0, appdata=0))
            continue
        if case["runner"] == "mitm":
            pem = (a.cert_map or {}).get(case["id"], {}).get("pem")
            if not pem:
                results.append(dict(case=case, result="skip", note="缂鸿瘉涔︽潗鏂欙紙%s锛? % case["cert"],
                                    applicability=why, alerts=[], client_fail=[], ch=0, sh=0, cert=0,
                                    appdata=0))
                continue
            v = run_case(a, case, pem)
        elif case["runner"] == "mismatch_key":
            log("[%s] 鏈満澶嶇幇锛氬彈淇′换璇佷功 + 閿欒绉侀挜鑳藉惁鏋勬垚绔偣" % case["id"])
            v = case_mismatched_key(a, case)
        elif case["runner"] == "replay":
            v = replay_attempt(a, a.live)
        else:
            continue
        v.setdefault("applicability", why)
        results.append(v)
        time.sleep(2)
    write_outputs(a, results)
    log("[4/4] 姹囨€?)
    print("")
    print("  " + "  ".join("%s=%s" % (v["case"]["id"], v["result"]) for v in results))
    fails = [v for v in results if v["result"] == "fail"]
    skips = [v for v in results if v["result"] in ("skip", "error")]
    if fails:
        print("[verdict] 鏈夌敤渚嬩笉绗﹀悎锛坒ail锛夛細AUM-3 涓嶈兘鍒?PASS")
        return 1
    if skips:
        print("[verdict] 鏈夌敤渚嬭瘉鎹笉瓒筹紙skip/error锛夛細閲嶈窇杩欎簺绐楀彛鍚庡啀鍒ゅ畾")
        return 2
    print("[verdict] 鏈閫傜敤鐨勫繀娴嬮」鍧囪 DUT 鎷掔粷 鈥斺€?AUM-3 鍒?PASS锛坧ass* 椤圭殑灞€闄愬凡鍦?summary.md 鍐欐槑锛?
          "N/A 椤圭殑鐞嗙敱涔熻鍦?summary.md锛?)
    return 0


if __name__ == "__main__":
    sys.exit(main())
