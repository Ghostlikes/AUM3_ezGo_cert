#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls_evidence.py - 通用 TLS / 证书类取证脚本（TDS 的 AUM-3、SCM-2 等场景复用）

一次运行产出：基线握手、被替换证书、过期证书、以及（若端点要求客户端证书）客户端证书负向用例，
每条用例一个 txt + 一个 PNG + 一份 summary.md / report.json，可整包贴进 TDS。

环境：只需 openssl；需要伪造服务器证书时再加 mitmproxy（Kali: apt install -y mitmproxy）。
     PNG 需要 Pillow（Kali: apt install -y python3-pil）。

典型用法：
  # 1) 生成取证用证书（替换证书 / 过期证书 / CN 不符证书）
  python3 tls_evidence.py --gen-certs --anchor device.pem --certs-dir certs --cn 169.254.0.1
  # 2) 全自动取证
  python3 tls_evidence.py --target 192.0.2.10 --sni device.local --anchor certs/device.pem \\
          --certs-dir certs --out evidence --label AuthMech-04 --png
  # 3) 自检（不连目标机，用本机 s_server 验证判定逻辑）
  python3 tls_evidence.py --selftest --certs-dir certs
  # 4) 让人工客户端（上位机 App / 浏览器）当对端：起好 mitmproxy 后停住
  python3 tls_evidence.py --target 192.0.2.10 --anchor certs/device.pem --manage-mitm --pause

判定口径：用例声明 expect=ok 或 expect=reject；实际与声明不符即整体非 0 退出，避免把不合格写成 PASS。
"""

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
import tempfile
import time

OPENSSL = os.environ.get('OPENSSL_BIN', 'openssl')
MITMDUMP = os.environ.get('MITMDUMP_BIN', 'mitmdump')


# ---------------------------------------------------------------- 基础工具
def run(cmd, timeout=60):
    """执行命令并返回 (rc, 合并输出)。超时不再抛异常：返回 rc=124 + 已捕获输出，
    否则一次挂住的 s_client 会把整轮取证带崩。"""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           encoding='utf-8', errors='replace',
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or '')
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ''
        if isinstance(partial, bytes):
            partial = partial.decode('utf-8', 'replace')
        return 124, partial + '\n[TIMEOUT] 命令 %d 秒未结束：%s' % (timeout, ' '.join(cmd))
    except OSError as exc:
        return 127, '[ERROR] 无法执行 %s: %s' % (cmd[0], exc)


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def verify_ok(out):
    return 'Verify return code: 0 (ok)' in out


def interesting(out, limit=40):
    keep = []
    pat = re.compile(r'^(CONNECTED|depth=|verify|Verification|New,|Protocol|Cipher|Server certificate|subject=|issuer=|SSL handshake|Acceptable client certificate|No client certificate|---|Error|error)', re.I)
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if pat.search(s) or 'Verify return code' in s or 'untrusted' in s or 'expired' in s or 'self-signed' in s or 'alert' in s.lower():
            keep.append(s)
    return keep[:limit]


def resolve_path(cands):
    for c in cands:
        if c and os.path.exists(c):
            return os.path.abspath(c)
    return None


def png_of(text, path, title):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return False
    font = None
    for cand in ('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
                 '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                 'C:/Windows/Fonts/consola.ttf', 'C:/Windows/Fonts/arial.ttf'):
        try:
            font = ImageFont.truetype(cand, 15)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()
    lines = [title, ''] + text.splitlines()
    width = max(760, min(1700, 9 * (max((len(x) for x in lines), default=60) + 4)))
    img = Image.new('RGB', (width, 26 + 22 * len(lines)), 'white')
    draw = ImageDraw.Draw(img)
    y = 10
    for i, line in enumerate(lines):
        draw.text((12, y), line[:200], fill=('black' if i else 'navy'), font=font)
        y += 22
    img.save(path)
    return True


def save_case(a, case):
    name = case['file']
    body = ['# ' + ' '.join(case['cmd'])] + case['transcript']
    if case.get('mitm_log'):
        body += ['', '--- mitmproxy ---', case['mitm_log']]
    txt = os.path.join(a.out, name + '.txt')
    with open(txt, 'w', encoding='utf-8') as fh:
        fh.write(case['title'] + '\n' + '\n'.join(body) + '\n')
    png = os.path.join(a.out, name + '.png')
    made = png_of('\n'.join(body), png, case['title']) if (a.png and case['result'] != 'skip') else False
    case['txt'] = txt
    case['png'] = png if made else ''
    print('[%s] %s -> %s%s' % (case['result'], name, os.path.basename(txt),
                               ('  +  ' + os.path.basename(png)) if made else ''))


# ---------------------------------------------------------------- 证书生成
GEN_HELPER = '''
import sys, os, ipaddress, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
out, cn, mode = sys.argv[1], sys.argv[2], sys.argv[3]
now = datetime.datetime.now(datetime.timezone.utc)
if mode == 'expired':
    nb, na = now - datetime.timedelta(days=30), now - datetime.timedelta(days=1)
else:
    nb, na = now - datetime.timedelta(days=1), now + datetime.timedelta(days=3650)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
alt = []
try:
    alt.append(x509.IPAddress(ipaddress.ip_address(cn)))
except Exception:
    alt.append(x509.DNSName(cn))
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .sign(key, hashes.SHA256()))
with open(out, 'wb') as fh:
    fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    fh.write(cert.public_bytes(serialization.Encoding.PEM))
print(out, cert.not_valid_before_utc, cert.not_valid_after_utc)
'''


def gen_certs(a):
    os.makedirs(a.certs_dir, exist_ok=True)
    cn = a.cn
    if not cn and a.anchor and os.path.exists(a.anchor):
        rc, out = run([OPENSSL, 'x509', '-in', a.anchor, '-noout', '-subject'])
        m = re.search(r'CN\s*=\s*([^,/]+)', out)
        cn = m.group(1).strip() if m else None
    cn = cn or 'test-cn'
    helper = os.path.join(a.certs_dir, '_gen_cert.py')
    with open(helper, 'w', encoding='utf-8') as fh:
        fh.write(GEN_HELPER)
    made = []
    for fn, mode in (('substituted.pem', 'valid'), ('expired.pem', 'expired'), ('wrongcn.pem', 'valid')):
        this_cn = 'unauthorized-cn' if fn == 'wrongcn.pem' else cn
        target = os.path.join(a.certs_dir, fn)
        rc, out = run([sys.executable, helper, target, this_cn, mode], timeout=120)
        if rc != 0:
            rc, out = run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', target + '.key',
                           '-out', target, '-days', '2', '-subj', '/CN=' + this_cn], timeout=120)
            if rc != 0:
                print('[warn] 生成 %s 失败：%s' % (fn, out.strip().splitlines()[:1]))
                continue
            with open(target, 'a', encoding='ascii') as fh:
                fh.write(open(target + '.key', encoding='ascii').read())
            print('[warn] %s 用 openssl 生成（过期证书需 cryptography，已退化为有效期内的自签证书）' % fn)
        made.append(target)
        print('[gen] %s (CN=%s)' % (target, this_cn))
    print('[gen] 共 %d 个证书，目录 %s' % (len(made), os.path.abspath(a.certs_dir)))
    return 0 if made else 2


# ---------------------------------------------------------------- mitmproxy
class Mitm:
    def __init__(self, a):
        self.a = a
        self.proc = None
        self.log = ''
        self.cmd = []

    def _build_cmd(self, tag, cert, modern=True, multimode=True):
        cmd = [MITMDUMP, '--showhost']
        if self.a.transparent:
            if modern and multimode:
                # 透明口给设备（被 iptables 引流）；另开一个常规代理口给脚本自己的检查客户端：
                # 透明模式下用 -proxy 连透明口会把 CONNECT 当原始流量转出去 → 必然挂住
                self.client_proxy_port = self.a.proxy_local_port or (self.port + 1)
                cmd += ['--mode', 'transparent@%d' % self.port, '--mode', 'regular@%d' % self.client_proxy_port]
            elif modern:
                self.client_proxy_port = None      # 只开透明口：脚本自带客户端检查不可用，改用 --pause
                cmd += ['--mode', 'transparent@%d' % self.port]
            else:
                # mitmproxy <= 8.x：模式语法不带端口，监听口只能由 -p 指定，且一进程只支持单模式；
                # 用户环境（RasPi/Kali）实测 mitmdump 8.1.1 即属此类，"transparent@8084" 会被拒
                self.client_proxy_port = None
                cmd += ['-p', str(self.port), '--mode', 'transparent']
        else:
            self.client_proxy_port = self.port
            cmd += ['-p', str(self.port)]
        if cert:
            cmd += ['--set', 'certs=*=' + os.path.abspath(cert)]
        if getattr(self.a, 'mitm_insecure', False):
            cmd += ['--set', 'ssl_insecure=true']   # 云端用私有 PKI 时不校验上游，让劫持会话能走完
        addon = getattr(self.a, 'provision_addon', None)
        if addon:
            cmd += ['-s', addon]
        cmd += ['-w', os.path.join(self.a.out, 'flows_%s.mitm' % tag)]
        return cmd

    def _spawn(self):
        try:
            self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as exc:
            self.proc = None
            self.log += '[ERROR] 起不了 %s: %s（mitmproxy 未安装？Kali: sudo apt install -y mitmproxy）' % (self.cmd[0], exc)
            print('[error] ' + self.log.strip())
            return False
        target = self.client_proxy_port or self.port
        for _ in range(120):
            time.sleep(0.1)
            try:
                socket.create_connection(('127.0.0.1', target), 0.2).close()
                return True
            except OSError:
                if self.proc.poll() is not None:
                    self.log += (self.proc.stdout.read() if self.proc.stdout else '')
                    return False
        return False

    def start(self, cert):
        """cert=None 时只做代理（用于云下发替换：靠 addon 改响应体，不动服务器证书）。"""
        if self.a.proxy:
            self.port = int(self.a.proxy.split(':')[-1])
            self.client_proxy_port = self.port
            return True
        self.port = self.a.mitm_port or (8084 if self.a.transparent else free_port())
        tag = os.path.basename(cert).split('.')[0] if cert else 'provision'
        if getattr(self.a, 'provision_addon', None):
            tag = tag + '_provision'
        if self.a.transparent and not self.a.rules_only:
            if not add_intercept_rules(self.a):
                return False
        cands = [(True, True), (True, False), (False, False)] if self.a.transparent else [(True, True)]
        for modern, multimode in cands:
            self.log = ''
            self.cmd = self._build_cmd(tag, cert, modern, multimode)
            if self._spawn():
                if not (modern and multimode):
                    print('[warn] 已按本机 mitmdump 语法回退（%s）：本进程只开一个口，脚本自带的检查客户端会跳过，'
                          '请用真实设备/上位机配合 --live 或 --pause' % ('仅透明口' if modern else 'mitmproxy 8.x：-p + --mode transparent'))
                return True
            tail = (self.log.strip().splitlines() or [''])[-1][:160]
            print('[warn] mitmdump 启动失败（%s）: %s' % ('transparent@%d' % self.port if modern else '-p %d --mode transparent' % self.port, tail))
            if 'Invalid mode specification' not in self.log and 'invalid mode' not in self.log.lower():
                break          # 不是模式语法问题（缺 mitmdump / 端口被占），换语法也没用
        self.stop()            # 起不来也要把 iptables 劫持规则撤掉，否则设备链路被我们挡住
        return False

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                out, _ = self.proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                out, _ = self.proc.communicate()
            self.log += out or ''
            self.proc = None
        if self.a.transparent and not self.a.rules_only:
            del_intercept_rules(self.a)

    def reject_line(self):
        for line in self.log.splitlines():
            if re.search(r'handshake failed|does not trust|verify|self-signed|expired', line, re.I):
                return line.strip()
        return ''


# ---------------------------------------------------------------- 用例
def base_cmd(a, extra=None):
    cmd = [OPENSSL, 's_client', '-connect', '%s:%d' % (a.target, a.port), '-servername', a.sni,
           '-CAfile', a.anchor, '-partial_chain', '-verify_return_error']
    if extra:
        cmd += extra
    return cmd


def case_direct(a):
    cmd = base_cmd(a) + ['-showcerts']
    rc, out = run(cmd)
    ok = verify_ok(out)
    return {'file': a.label + '_baseline_direct', 'title': 'baseline: direct TLS handshake with the provisioned trust anchor (expect OK)',
            'expect': 'ok', 'result': 'pass' if ok else 'fail', 'cmd': cmd,
            'transcript': out.splitlines()[:60], 'mitm_log': ''}


def case_client_cert(a, certfile, label):
    cert = os.path.join(a.certs_dir, certfile)
    cmd = base_cmd(a, ['-cert', cert, '-key', cert])
    rc, out = run(cmd)
    ok = verify_ok(out)
    return {'file': a.label + '_' + label, 'title': 'client certificate case: %s (expect REJECT)' % certfile,
            'expect': 'reject', 'result': 'pass' if not ok else 'fail', 'cmd': cmd,
            'transcript': interesting(out, 30), 'mitm_log': ''}


def case_server_auth(a, certfile, label, title, pause=False):
    cert = os.path.join(a.certs_dir, certfile)
    if not os.path.exists(cert):
        return {'file': a.label + '_' + label, 'title': title, 'expect': 'reject', 'result': 'skip',
                'cmd': [], 'transcript': ['missing certificate: ' + cert], 'mitm_log': ''}
    m = Mitm(a)
    if not m.start(cert):
        return {'file': a.label + '_' + label, 'title': title, 'expect': 'reject', 'result': 'error',
                'cmd': m.cmd, 'transcript': (m.log.strip().splitlines()[:4] or ['mitmdump failed to start']),
                'mitm_log': ''}
    try:
        if m.client_proxy_port is None and not pause:
            return {'file': a.label + '_' + label, 'title': title, 'expect': 'reject', 'result': 'skip',
                    'cmd': m.cmd,
                    'transcript': ['当前只有透明口（mitmdump 不支持多模式，或未开常规口）：',
                                   '请加 --pause 让真实设备/上位机跑一次，',
                                   '或用 --proxy-local-port 指定一个常规代理口给脚本自带客户端'],
                    'mitm_log': ''}
        if pause:
            print('\n[mitmproxy] 透明口 %d / 检查客户端用 %s，出示证书 %s' % (m.port, m.client_proxy_port, cert))
            print('           point the real client (App/browser) at that proxy, then come back')
            input('           press Enter when done...')
            time.sleep(0.5)
            rc, out = 0, '(operator-driven; see mitmproxy log)'
        else:
            cmd = base_cmd(a, ['-proxy', '127.0.0.1:%d' % m.client_proxy_port])
            rc, out = run(cmd)
        mitm_line = m.reject_line()
    finally:
        m.stop()
        mitm_line = m.reject_line()
    rejected = (not verify_ok(out)) or rc != 0 or bool(mitm_line)
    return {'file': a.label + '_' + label, 'title': title, 'expect': 'reject',
            'result': 'pass' if rejected else 'fail', 'cmd': m.cmd,
            'transcript': interesting(out, 30), 'mitm_log': mitm_line}


def probe_client_cert(out):
    if 'No client certificate CA names sent' in out:
        return False, []
    names = []
    grab = False
    for line in out.splitlines():
        if 'Acceptable client certificate CA names' in line:
            grab = True
            continue
        if grab:
            if not line.strip() or line.startswith('---'):
                break
            names.append(line.strip())
    return (True if names else None), names


# ------------------------------------------------- 透明劫持（参考 mitm.py，修正其两个 bug）
def detect_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()


def local_ipv4_list():
    """本机 IPv4 列表 [(ip, prefix)]。Linux 用 `ip -4 -o addr show`（带掩码），
    失败退回 hostname -I，再失败退回默认路由地址。"""
    out = []
    try:
        p = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
        for line in p.stdout.splitlines():
            m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m:
                out.append((m.group(1), int(m.group(2))))
    except Exception:
        pass
    if not out:
        try:
            p = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            for tok in p.stdout.split():
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', tok):
                    out.append((tok, 24))
        except Exception:
            pass
    if not out:
        out.append((detect_local_ip(), 24))
    return out


def pick_proxy_host(client_ip, explicit=None):
    """选 DNAT 目标地址：优先与“设备/客户端 IP”同网段的本机地址。
    手工给了 --proxy-host 就用它；否则按 client_ip 的网段匹配；都不行用第一个候选。"""
    if explicit:
        return explicit, True
    cands = local_ipv4_list()
    if client_ip:
        try:
            import ipaddress
            dev = ipaddress.ip_address(str(client_ip))
            for ip, pfx in cands:
                if dev in ipaddress.ip_network('%s/%d' % (ip, pfx), strict=False):
                    return ip, True
        except Exception:
            pass
    return cands[0][0], False


def intercept_cmds(a, action):
    """生成/删除 iptables DNAT 规则。
    修正 mitm.py 的两个 bug：① 原来 mitmdump 带 --rawtcp（只转发字节、不伪造证书）；
    ② 删除规则时 --to-destination 写的是另一个地址，-D 匹配不上导致规则残留。
    这里增删用同一条规则，且目的地址只算一次。"""
    host = a.proxy_host or detect_local_ip()
    dst = '%s:%d' % (host, a.mitm_port or 8084)
    cmds = []
    for item in (a.intercept or []):
        tgt, _, prt = item.partition(':')
        cmd = ['sudo', 'iptables', '-t', 'nat', action, 'PREROUTING']
        if a.intercept_src:
            cmd += ['-s', a.intercept_src]
        cmd += ['-p', 'tcp', '-d', tgt, '--dport', str(int(prt or 443)),
                '-j', 'DNAT', '--to-destination', dst]
        cmds.append(cmd)
    return cmds


def add_intercept_rules(a):
    for cmd in intercept_cmds(a, '-A'):
        print('[iptables] ' + ' '.join(cmd))
        if a.rules_only:
            continue
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode != 0:
            print('[error] 加规则失败: %s' % (p.stdout or '').strip())
            del_intercept_rules(a)
            return False
    return True


def del_intercept_rules(a):
    for cmd in intercept_cmds(a, '-D'):
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('[iptables] 删除 -> %s' % ('ok' if p.returncode == 0 else (p.stdout or '').strip()))


def kick_cmds(a, action):
    """踢掉设备与云端之间“已建立”的长连接，逼它在劫持窗口内重新握手。
    为什么必须踢：nat/PREROUTING 的 DNAT 只对“新建”连接生效，MQTT/HTTP 长连接
    （keepalive 动辄几分钟）在窗口内根本不会重连，于是抓不到任何握手。
    老连接走 FORWARD，在那里 tcp-reset 掉它；设备重连的 SYN 属新建连接，
    在 PREROUTING 就被 DNAT 到 mitmproxy、不进 FORWARD，所以不影响我们自己的劫持会话。"""
    cmds = []
    for item in (a.intercept or []):
        tgt, _, prt = item.partition(':')
        cmd = ['sudo', 'iptables', action, 'FORWARD']
        if a.intercept_src:
            cmd += ['-s', a.intercept_src]
        cmd += ['-p', 'tcp', '-d', tgt, '--dport', str(int(prt or 443)),
                '-j', 'REJECT', '--reject-with', 'tcp-reset']
        cmds.append(cmd)
    return cmds


def add_kick_rules(a):
    ok = True
    for cmd in kick_cmds(a, '-I'):
        print('[kick] ' + ' '.join(cmd))
        if a.rules_only:
            continue
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode != 0:
            print('[warn] 踢连接规则加不上: %s' % (p.stdout or '').strip())
            ok = False
    return ok


def del_kick_rules(a):
    for cmd in kick_cmds(a, '-D'):
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('[kick] 删除 -> %s' % ('ok' if p.returncode == 0 else (p.stdout or '').strip()))


def kick_hits(a):
    """我们那条 REJECT 规则已经命中过多少个包（iptables -vnL 的第一列）。
    设备空闲时它一个包都不发，规则挂着也没用；一旦命中就说明真把它踢断了。"""
    n = 0
    p = subprocess.run(['sudo', 'iptables', '-vnL', 'FORWARD'], text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for line in (p.stdout or '').splitlines():
        if 'tcp-reset' in line:
            try:
                n += int(line.split()[0])
            except (ValueError, IndexError):
                pass
    return n


def kick_once(a, max_wait=60):
    """踢一次老长连接：加 REJECT 规则 → 等它命中（设备下一个报文）→ 立刻撤规则。
    规则必须尽快撤掉：未劫持的 baseline 场景里，一直挂着的 REJECT 会把设备重连的
    新 SYN 也 RST 掉，窗口内就永远握不上手。"""
    if not add_kick_rules(a):
        return 0
    t0 = time.time()
    hits = 0
    while time.time() - t0 < max_wait:
        time.sleep(1.0)
        hits = kick_hits(a)
        if hits:
            time.sleep(0.5)          # 让 RST 发出去
            break
    del_kick_rules(a)
    print('[kick] %s（命中 %d 个报文，规则已撤）' % ('已踢断设备与云端的长连接' if hits else '等待期内设备没有发包，没踢到',
                                                hits))
    return hits


# ------------------------------------------------- 云下发/OTA 证书替换（mitmproxy addon）
PROVISION_ADDON = '''# -*- coding: utf-8 -*-
"""由 tls_evidence.py 生成：把被劫持响应里的证书材料替换成取证用证书。
用于『云服务器下发证书』类项目：设备/上位机从云端取证书，我们替换成未授权/过期证书，
观察对端是否拒绝（TEST A/C）。"""
import re, time
from mitmproxy import http

OUR_CERT = open(r'__CERT__', 'r', encoding='ascii').read().strip()
LOG = r'__LOG__'
URL_RE = re.compile(r'__MATCH__')
CT_KEYS = ('cert', 'pkcs7', 'pkcs8', 'octet-stream', 'pem', 'x-x509')
CERT_RX = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def _log(msg):
    with open(LOG, 'a', encoding='utf-8') as fh:
        fh.write('%s %s\\n' % (time.strftime('%H:%M:%S'), msg))
    print('[provision] ' + msg)


def response(flow: http.HTTPFlow) -> None:
    ct = (flow.response.headers.get('content-type') or '').lower()
    body = flow.response.get_text(strict=False) or ''
    m = URL_RE.search(flow.request.pretty_url)
    has_pem = bool(CERT_RX.search(body))
    if not (m or has_pem or any(k in ct for k in CT_KEYS)):
        return
    if has_pem:
        new, n = CERT_RX.subn(OUR_CERT, body)
        flow.response.set_text(new)
        _log('SUBSTITUTED(pem) url=%s ct=%s blocks=%d' % (flow.request.pretty_url, ct, n))
        return
    if m:
        flow.response.set_text(OUR_CERT + '\\n')
        flow.response.headers['content-type'] = 'application/x-pem-file'
        _log('SUBSTITUTED(url) url=%s ct=%s' % (flow.request.pretty_url, ct))
        return
    _log('MATCHED-no-substitution url=%s ct=%s len=%d' % (flow.request.pretty_url, ct, len(body)))
'''


CERT_ALIASES = {
    'untrusted': 'substituted.pem', 'untrusted.pem': 'substituted.pem',
    'substituted': 'substituted.pem', 'substituted.pem': 'substituted.pem',
    'expired': 'expired.pem', 'expired.pem': 'expired.pem',
    'wrongcn': 'wrongcn.pem', 'wrongcn.pem': 'wrongcn.pem',
    'unauthorized': 'wrongcn.pem', 'unauthorized.pem': 'wrongcn.pem',
}


def resolve_cert_arg(a, name):
    """把 --provision-cert / --serve-cert 的值解析成实际文件：相对路径、certs-dir 内查找，
    以及别名（untrusted|substituted|expired|wrongcn|unauthorized）；找不到时列出可用文件。"""
    if not name:
        return None
    cands = [name, os.path.join(a.certs_dir, name)]
    alias = CERT_ALIASES.get(os.path.basename(name).lower())
    if alias:
        cands += [os.path.join(a.certs_dir, alias), alias]
    path = resolve_path(cands)
    if path and os.path.basename(path) != os.path.basename(name):
        print('[info] %s → 实际使用 %s（别名）' % (name, path))
    if not path:
        have = sorted(os.listdir(a.certs_dir)) if os.path.isdir(a.certs_dir) else []
        print('[error] 找不到证书: ' + str(name))
        print('        %s 下现有: %s' % (a.certs_dir, ', '.join(have) if have else '(空，先跑 --gen-certs)'))
        print('        可用别名: untrusted|substituted → substituted.pem, expired → expired.pem, wrongcn|unauthorized → wrongcn.pem')
    return path


def write_provision_addon(a):
    cert = resolve_cert_arg(a, a.provision_cert)
    if not cert:
        return None
    a.provision_cert = cert
    a.provision_log = os.path.join(a.out, 'provision_substitution.log')
    open(a.provision_log, 'w', encoding='utf-8').close()
    match = a.provision_match or r'cert|pki|\.pem|\.crt|provision|enroll|certificate'
    path = os.path.join(a.out, 'provision_addon.py')
    with open(path, 'w', encoding='utf-8') as fh:
        src = (PROVISION_ADDON.replace('__CERT__', cert.replace(chr(92), '/'))
               .replace('__LOG__', a.provision_log.replace(chr(92), '/'))
               .replace('__MATCH__', match))
        fh.write(src)
    print('[provision] addon 已生成: %s（匹配 %s）' % (path, match))
    return path


def case_provision(a, pause=False):
    """经代理取一次云下发接口，检查响应里的证书是否已被替换成我们的证书。"""
    if not (a.provision_url and a.provision_cert):
        return {'file': a.label + '_provision_substituted', 'title': 'cloud-issued certificate substitution',
                'expect': 'reject', 'result': 'skip', 'cmd': [], 'transcript': ['需要 --provision-url 与 --provision-cert'], 'mitm_log': ''}
    m = Mitm(a)
    if not m.start(None):
        return {'file': a.label + '_provision_substituted', 'title': 'cloud-issued certificate substitution',
                'expect': 'reject', 'result': 'error', 'cmd': m.cmd,
                'transcript': (m.log.strip().splitlines()[:4] or ['mitmdump failed to start']), 'mitm_log': ''}
    try:
        if m.client_proxy_port is None and not pause:
            return {'file': a.label + '_provision_substituted',
                    'title': 'cloud-issued certificate substitution',
                    'expect': 'reject', 'result': 'skip', 'cmd': m.cmd,
                    'transcript': ['当前只有透明口：请用 --pause 让真实设备跑一次下发，或用 --proxy-local-port 指定常规代理口'],
                    'mitm_log': ''}
        if pause:
            print('\n[provision] mitmproxy 透明口 %d / 检查客户端 %s；请让设备/上位机跑一次下发' % (m.port, m.client_proxy_port))
            input('            完成一次下发后按回车继续...')
            body, rc = '', 0
        else:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({'https': 'http://127.0.0.1:%d' % m.client_proxy_port}),
                urllib.request.HTTPSHandler(context=ctx))
            try:
                body = opener.open(a.provision_url, timeout=25).read().decode('utf-8', 'replace')
                rc = 0
            except Exception as exc:      # 取不到不算失败：可能接口要鉴权，日志仍有替换记录
                body, rc = 'fetch failed: %s' % exc, 1
    finally:
        m.stop()
    log = ''
    try:
        log = open(a.provision_log, encoding='utf-8').read().strip()
    except OSError:
        pass
    ours = cert_sha256(a.provision_cert)
    served = cert_sha256_from_text(body)
    done = ('SUBSTITUTED' in log) or (ours is not None and ours in served)
    return {'file': a.label + '_provision_substituted',
            'title': 'cloud-issued certificate substitution (device/app must reject the substituted certificate)',
            'expect': 'reject', 'result': 'pass' if done else 'fail', 'cmd': m.cmd,
            'transcript': interesting(body, 12) + ['', '我们的证书 SHA256: %s' % ours, '响应中的证书 SHA256: %s' % ', '.join(served) if served else '响应中未解析到证书',
                                                   '', '--- provision log ---'] + (log.splitlines()[-15:] or ['(no substitution logged)']),
            'mitm_log': (log.splitlines()[-1] if log else '')}


# ------------------------------------------------- 证书比对（TEST D / 唯一性）
def cert_sha256(pem_path):
    rc, out = run([OPENSSL, 'x509', '-in', pem_path, '-noout', '-fingerprint', '-sha256'])
    m = re.search(r'=([0-9A-Fa-f:]{20,})', out)
    return m.group(1).replace(':', '').upper() if m else None


def cert_sha256_from_text(text):
    out = []
    for blk in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text or '', re.S):
        tmp = os.path.join(tempfile.gettempdir(), 'cmp_tmp.pem')
        with open(tmp, 'w', encoding='ascii') as fh:
            fh.write(blk + '\n')
        v = cert_sha256(tmp)
        if v:
            out.append(v)
    return out


def fetch_leaf(host, port, sni, out_dir):
    cmd = [OPENSSL, 's_client', '-connect', '%s:%d' % (host, port), '-servername', sni or host, '-showcerts']
    rc, out = run(cmd)
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', out, re.S)
    if not blocks:
        return None
    path = os.path.join(out_dir, 'compare_%s_%d.pem' % (host.replace(':', '_'), port))
    with open(path, 'w', encoding='ascii') as fh:
        fh.write(blocks[0] + '\n')
    rc, info = run([OPENSSL, 'x509', '-in', path, '-noout', '-subject', '-issuer', '-serial', '-dates', '-fingerprint', '-sha256'])
    d = {'target': '%s:%d' % (host, port), 'pem': path, 'raw': info}
    for line in info.splitlines():
        k, _, v = line.partition('=')
        d[k.strip().lower().replace(' ', '_')] = v.strip()
    return d


def baseline_path(a):
    return os.path.join(a.out, 'device_baseline.pcap')


def verify_baseline(pcap, a):
    """TEST B 判据：设备到真服务器完成了握手 —— 抓到 ServerHello + Certificate（服务器侧），
    以及设备侧的应用数据记录。"""
    dut = a.intercept_src or a.client_ip or ''
    if not os.path.exists(pcap):
        return False, ['(没有 baseline pcap：tcpdump 未启用或权限不足)']
    if not shutil.which('tshark'):
        return False, ['(没装 tshark，无法解析 baseline)']
    rc, out = tshark_run(pcap, ['-Y', 'tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11',
                                '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tls.handshake.type'], timeout=180)
    rows = [l.strip() for l in out.splitlines() if re.match(r'^\d', l.strip())]
    ch = [r for r in rows if r.endswith('\t1') and dut in r.split('\t')[1]]
    sh = [r for r in rows if r.endswith('\t2') and dut not in r.split('\t')[1]]
    cert = [r for r in rows if r.endswith('\t11') and dut not in r.split('\t')[1]]
    rc, out2 = tshark_run(pcap, ['-Y', 'tls.record.content_type==23', '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ip.src'], timeout=180)
    appdata = [l.strip() for l in out2.splitlines() if dut and dut in l]
    lines = ['设备 ClientHello        : %d 次' % len(ch),
             '服务器 ServerHello      : %d 次' % len(sh),
             '服务器 Certificate      : %d 次' % len(cert),
             '设备侧应用数据记录      : %d 条（握手完成后有真实业务数据）' % len(appdata),
             '抓包网卡                : %s' % capture_iface(a)]
    if sh and cert and appdata:
        lines.append('=> 设备与真服务器握手并交换应用数据：链路正常（baseline OK）')
        return True, lines
    if sh and cert:
        lines.append('=> 握手完成但没有抓到应用数据（设备可能在握手后立即断开）')
        return False, lines
    lines.append('=> 没抓到服务器 ServerHello/Certificate：本窗口内设备未重新握手，延长 --baseline-live 或再踢一次')
    return False, lines


def case_baseline_live(a, seconds=90):
    """真实设备上的 TEST B：先踢掉长连接，再让设备自己与真服务器重新握手（无劫持）。"""
    cap = start_capture(a, 'device_baseline')
    if not getattr(a, 'no_kick', False):
        # 关键：设备空闲时一个包都不发，只 RST 老连接踢不动它（实测踢完能静默好几分钟）。
        # 先把设备到云的流量全 RST 掉，逼它进入“十几秒一次”的重连循环；等 pcap 里真看到它的
        # SYN 再撤规则 —— 此时它的下一次重连就是直连真服务器，抓到的握手才算 baseline。
        print('[kick] 挂着 REJECT 逼设备进入重连循环（最长 %d 秒，看到设备 SYN 就放开）...' % max(30, min(180, seconds)))
        add_kick_rules(a)
        t1 = time.time()
        while time.time() - t1 < max(30, min(180, seconds)):
            time.sleep(3)
            if count_device_syns(baseline_path(a), a.intercept_src or a.client_ip):
                break
        del_kick_rules(a)
        print('[kick] 已放开（等了 %d 秒）：设备下一次重连直连真服务器' % int(time.time() - t1))
    t0 = time.time()
    stdin_live = True
    try:
        import select
    except Exception:
        select = None
    try:
        while time.time() - t0 < seconds:
            if select is None or not stdin_live:
                time.sleep(0.5)
                continue
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
            if not r:
                continue
            line = sys.stdin.readline()
            if line == '':
                stdin_live = False
                continue
            break
    finally:
        stop_capture(cap)
    ok, lines = verify_baseline(baseline_path(a), a)
    return {'file': a.label + '_baseline_live', 'title': 'baseline on the real device: DUT completes TLS with the genuine server (expect OK)',
            'expect': 'ok', 'result': 'pass' if ok else 'fail', 'cmd': [],
            'transcript': ['[BASELINE] 实测窗口 %d 秒（无劫持、不替换证书）' % seconds, '结论: %s' % ('设备与真服务器握手成功（baseline 成立）' if ok else '证据不足')] + lines,
            'mitm_log': ''}


def case_live(a, seconds=120):
    """实测窗口：起好 mitmproxy + iptables 后停住，让真实设备/上位机跑一次，再按日志判定。"""
    cert = resolve_cert_arg(a, a.provision_cert or 'substituted.pem')
    if not cert:
        return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
                'expect': 'reject', 'result': 'error', 'cmd': [],
                'transcript': ['需要一张取证证书（--provision-cert，默认 substituted.pem）'], 'mitm_log': ''}
    m = Mitm(a)
    if not m.start(cert):
        return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
                'expect': 'reject', 'result': 'error', 'cmd': m.cmd,
                'transcript': (m.log.strip().splitlines()[:6] or ['mitmdump failed to start']), 'mitm_log': ''}
    print('')
    print('[LIVE] 劫持已生效（透明口 %s / 检查口 %s，出示 %s）' % (m.port, m.client_proxy_port, os.path.basename(cert)))
    print('       现在请在设备/上位机上触发一次注册/激活/重连；%d 秒内或按回车结束。' % seconds)
    if not getattr(a, 'no_kick', False):
        print('[kick] 挂着 REJECT 踢掉设备与云端的长连接（老连接走 FORWARD 被 RST；重连的新 SYN 在 PREROUTING 就被 DNAT 到本机，不受影响）')
        add_kick_rules(a)
    cap = start_capture(a)
    t0 = time.time()
    stdin_live = True
    try:
        import select
    except Exception:
        select = None
    try:
        while time.time() - t0 < seconds:
            if select is None or not stdin_live:
                time.sleep(0.5)
                continue
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
            if not r:
                continue
            line = sys.stdin.readline()
            if line == '':
                # 非交互/批处理里 stdin 直接 EOF：不能当作“按回车提前结束”，
                # 否则窗口 0 秒就收尾（脚本从 -m/管道跑时必踩），改成等满窗口
                stdin_live = False
                continue
            break                     # 真有输入（含单独一个回车）才提前结束
    finally:
        stop_capture(cap)
        m.stop()
        del_kick_rules(a)
    cap_lines, dev_conns, dev_events, hellos = decode_capture(a)
    log = m.log or ''
    # 只认“客户端侧”握手失败：mitmproxy 连上游失败也会打 CERTIFICATE_VERIFY_FAILED，
    # 那是我们到云端的错误、不是设备拒绝我们——混在一起会把证据误判成 PASS。
    upstream_err = [l.strip() for l in log.splitlines()
                    if re.search(r'cannot establish tls|server tls handshake failed|certificate_verify_failed|unable to get local issuer', l, re.I)]
    rejects = [l.strip() for l in log.splitlines()
               if re.search(r'client\s+tls\s+handshake\s+failed|client does not trust|client.*bad certificate|client.*unknown ca', l, re.I)
               and l.strip() not in upstream_err]
    served = [l.strip() for l in log.splitlines() if re.search(r'\b(GET|POST|PUT|CONNECT)\b\s+https?://', l)]
    sub = []
    try:
        plog = getattr(a, 'provision_log', None)
        if plog:
            sub = [l.strip() for l in open(plog, encoding='utf-8').read().splitlines() if l.strip()]
    except OSError:
        pass
    dut = a.intercept_src or a.client_ip or ''
    dev_log = [l.strip() for l in log.splitlines() if dut and dut in l]
    if (rejects or dev_events) and (hellos or dev_conns):
        result, note = 'pass', '设备主动发起握手后被拒（mitmproxy 记录客户端握手失败 / 设备侧 TLS alert·RST）—— TEST A/C 证据成立'
    elif hellos and (served or dev_log):
        result, note = 'fail', '设备与我们完成了 TLS 握手、没有拒绝被替换的证书 —— 属不符合，不能写 PASS'
    elif dev_conns == 0 and not hellos and not dev_log:
        result, note = 'skip', '本窗口内没有观察到设备流量：确认设备网关指向本机，或真正触发注册/激活/重连后重跑 --live'
    elif served or sub or dev_log:
        result, note = 'fail', '设备发起了连接但没有拒绝我们出示的证书 —— 属不符合，不能写 PASS'
    else:
        result, note = 'skip', '证据不足：请检查抓包权限与设备网关后重跑 --live'
    lines = ['[LIVE] 实测窗口 %d 秒，出示证书 %s' % (seconds, cert), '结论: %s' % note, '',
             '--- 设备侧抓包结论 (%s) ---' % capture_path(a)] + cap_lines + ['', '--- mitmproxy 日志（尾部 40 行）---']
    lines += (log.splitlines()[-40:] or ['(空：未观察到连接)'])
    if sub:
        lines += ['', '--- 云下发替换日志 ---'] + sub[-20:]
    return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
            'expect': 'reject', 'result': result, 'cmd': m.cmd,
            'transcript': lines, 'mitm_log': (rejects[0] if rejects else (sub[-1] if sub else ''))}


# ------------------------------------------------- 设备侧抓包（证明 DUT 真正发起并被拒）
def capture_path(a, tag='device_live'):
    return os.path.join(a.out, tag + '.pcap')


def capture_iface(a):
    """抓包网卡：显式 --capture-if 优先；否则选“与设备同网段”的那张网卡。
    -i any 在多网卡中间盒上会漏掉本地 DNAT 后的握手报文，实测只有落在
    设备侧网卡（如 srsRAN 的 srs_spgw_sgi）上才看得到 SYN/ClientHello。"""
    if getattr(a, 'capture_if', None):
        return a.capture_if
    dut = a.intercept_src or a.client_ip
    if dut:
        try:
            import ipaddress
            p = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, timeout=10)
            for line in p.stdout.splitlines():
                m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m and ipaddress.ip_address(dut) in ipaddress.ip_network('%s/%s' % (m.group(2), m.group(3)), strict=False):
                    return m.group(1).split('@')[0]
        except Exception:
            pass
    return 'any'


def start_capture(a, tag='device_live'):
    if getattr(a, 'no_capture', False):
        return None
    if not shutil.which('tcpdump'):
        print('[warn] 没装 tcpdump，跳过设备侧抓包（判定只依据 mitmproxy 日志）')
        return None
    src = a.intercept_src or a.client_ip
    ports = sorted({int(item.partition(':')[2] or 443) for item in (a.intercept or [])}) or [443]
    parts = []
    if src:
        parts.append('host %s' % src)
    parts.append('(' + ' or '.join('port %d' % p for p in ports) + ')')
    parts.append('tcp')
    user = os.environ.get('SUDO_USER') or os.environ.get('USER') or getpass.getuser()
    # -Z：让 tcpdump 把 pcap 写成当前用户所有。否则文件属于 tcpdump:tcpdump，
    # tshark 以 O_RDWR 打开会被拒（报 You don't have permission to read the file）。
    cmd = ['sudo', 'tcpdump', '-i', capture_iface(a), '-n', '-s', '0', '-U', '-Z', user,
           '-w', capture_path(a, tag), ' and '.join(parts)]
    print('[capture] ' + ' '.join(cmd))
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        print('[warn] 抓包启动失败: %s' % exc)
        return None


def stop_capture(proc):
    if proc is None:
        return
    time.sleep(0.8)
    proc.terminate()
    try:
        proc.wait(timeout=6)
    except Exception:
        proc.kill()


def tshark_run(pcap, extra, timeout=180):
    """tshark 按路径打开 pcap 在部分机器上会被拒（连 root 都报
    'You don't have permission to read the file'），但把文件从 stdin 喂进去
    （tshark -r -）完全正常 —— 统一走 stdin，保证证据解析真的发生。"""
    if not shutil.which('tshark') or not os.path.exists(pcap):
        return 1, ''
    try:
        with open(pcap, 'rb') as fh:
            p = subprocess.run(['tshark', '-r', '-'] + list(extra), stdin=fh,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return 1, ''
    return p.returncode, p.stdout.decode('utf-8', 'replace')


def count_device_syns(pcap, dut):
    """数 pcap 里设备发出的 SYN（判断“设备是否已经开始重连”）。"""
    if not dut or not shutil.which('tshark') or not os.path.exists(pcap):
        return 0
    rc, out = tshark_run(pcap, ['-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0', '-T', 'fields', '-e', 'ip.src'], timeout=60)
    return len([l for l in out.splitlines() if dut in l])


def decode_capture(a, tag='device_live'):
    """解析设备侧抓包：设备发起连接次数 + 拒绝类事件（TLS alert / RST）。"""
    pcap = capture_path(a, tag)
    dut = a.intercept_src or a.client_ip
    if not os.path.exists(pcap):
        return ['(没有 pcap 文件：tcpdump 未启用或权限不足)'], 0, 0, []
    syns, events = [], []
    if shutil.which('tshark'):
        rc, out = tshark_run(pcap, ['-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0', '-T', 'fields', '-e', 'ip.src'], timeout=180)
        syns = [l.strip() for l in out.splitlines() if re.match(r'^\d+\.\d+\.\d+\.\d+$', l.strip())]
        rc, out = tshark_run(pcap, ['-Y', 'tls.alert_message || tcp.flags.reset==1', '-T', 'fields',
                                    '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tls.handshake.type',
                                    '-e', 'tls.alert_message.desc', '-e', 'tcp.flags.str', '-e', '_ws.col.info'], timeout=180)
        events = [l.strip() for l in out.splitlines() if l.strip()]
    else:
        rc, out = run(['tcpdump', '-r', pcap, '-nn'], timeout=180)
        syns = [l for l in out.splitlines() if 'Flags [S]' in l]
        events = [l.strip() for l in out.splitlines() if 'Alert' in l or 'Flags [R]' in l or 'Flags [R.]' in l]
    dev_syns = [s for s in syns if (not dut or dut in s)]
    # 只看“设备自己发出的”拒绝：TLS alert / RST 的 ip.src 必须是设备；
    # 别人 RST 设备（ip.dst=设备）不算设备拒绝
    dev_events = []
    for e in events:
        fields = e.split('\t')
        src = fields[1].strip() if len(fields) > 1 else ''
        if not dut or src == dut:
            dev_events.append(e)
    hellos = []
    if shutil.which('tshark') and dut:
        rc, out = tshark_run(pcap, ['-Y', 'tls.handshake.type==1 && ip.src==%s' % dut, '-T', 'fields',
                                    '-e', 'frame.time_relative', '-e', 'tls.handshake.extensions_server_name'], timeout=180)
        hellos = [l.strip() for l in out.splitlines() if l.strip()]
    lines = ['设备发起连接（SYN）: %d 次（全部 SYN 源: %s）' % (len(dev_syns), ', '.join(sorted({s.split(' ')[0] for s in syns})) or '无')]
    snis = sorted({h.split('\t')[1] for h in hellos if '\t' in h and h.split('\t')[1]})
    lines.append('设备发出的 TLS ClientHello: %d 次%s' % (len(hellos), ('（SNI: %s）' % ', '.join(snis)) if snis else ''))
    if dev_events:
        lines += ['拒绝类事件（来自设备）: %d 条' % len(dev_events)] + ['  ' + e[:150] for e in dev_events[:20]]
    else:
        lines.append('设备侧没有发出 TLS alert / RST（TLS1.3 的 alert 是密文，抓包看不到时以 mitmproxy 日志为准）')
    return lines, len(dev_syns), len(dev_events), hellos


def case_compare(a, targets):
    rows = []
    for t in targets:
        host, _, prt = t.partition(':')
        d = fetch_leaf(host, int(prt or 443), a.sni if a.sni == host else host, a.out)
        if d:
            rows.append(d)
    lines = ['证书比对（每台/每个端点的叶子证书）', '']
    seen = {}
    dup = []
    for d in rows:
        lines += ['[%s]' % d['target'],
                  '  subject   : %s' % d.get('subject', '?'),
                  '  issuer    : %s' % d.get('issuer', '?'),
                  '  serial    : %s' % d.get('serial', '?'),
                  '  validity  : %s ~ %s' % (d.get('notbefore', '?'), d.get('notafter', '?')),
                  '  SHA256    : %s' % d.get('sha256_fingerprint', d.get('sha256_fingerprint', '?')),
                  '']
        key = (d.get('serial'), d.get('sha256_fingerprint'))
        if key in seen:
            dup.append('%s 与 %s 的证书完全相同（serial %s）' % (d['target'], seen[key], d.get('serial')))
        else:
            seen[key] = d['target']
    if len(rows) < 2:
        lines.append('（只取到 %d 个端点，至少给两个才构成唯一性比对）' % len(rows))
    lines += ['结论:', '  ' + ('；'.join(dup) if dup else '各端点证书互不相同（序列号/SHA256 均不一致）')]
    return {'file': a.label + '_cert_compare',
            'title': 'certificate uniqueness / other-entity key comparison (TEST D evidence)',
            'expect': 'reject', 'result': 'fail' if dup else 'pass', 'cmd': [],
            'transcript': lines, 'mitm_log': ''}


def tds_of(label):
    if 'baseline' in label:
        return 'TEST B'
    if 'compare' in label:
        return 'TEST D'
    if 'expired' in label or 'substituted' in label or 'clientcert' in label or 'provision' in label:
        return 'TEST A/C'
    return ''

# ---------------------------------------------------------------- 自检
def selftest(a):
    good = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.pem', 'untrusted.pem', 'expired.pem', 'wrongcn.pem')])
    crt = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.crt', 'untrusted.crt')])
    key = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.key', 'untrusted.key')])
    if good is None and (crt is None or key is None):
        print('[selftest] 需要 --certs-dir 下有 substituted.pem（或 substituted.crt/.key）；先跑 --gen-certs')
        return 2
    port = free_port()
    if good:
        certargs = ['-cert', good, '-key', good]
    else:
        certargs = ['-cert', crt, '-key', key]
    srv = subprocess.Popen([OPENSSL, 's_server', '-accept', str(port)] + certargs + ['-www', '-quiet'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        common = [OPENSSL, 's_client', '-connect', '127.0.0.1:%d' % port, '-verify_return_error']
        rc1, out1 = run(common + ['-CAfile', certargs[1], '-partial_chain'])
        for other in ('expired.pem', 'wrongcn.pem', 'substituted.pem'):
            p = os.path.join(a.certs_dir, other)
            if os.path.exists(p) and p != certargs[1]:
                anchor = p
                break
        else:
            print('[selftest] 缺少第二张不同证书用于负向对照')
            return 2
        rc2, out2 = run(common + ['-CAfile', anchor, '-partial_chain'])
        ok1, ok2 = verify_ok(out1), verify_ok(out2)
        print('[selftest] anchor == presented -> %s (expect ok)' % ('ok' if ok1 else 'NOT ok'))
        print('[selftest] anchor != presented -> %s (expect rejected)' % ('ACCEPTED(!)' if ok2 else 'rejected'))
        verdict = ok1 and not ok2
        print('[selftest] VERDICT: %s' % ('PASS' if verdict else 'FAIL'))
        return 0 if verdict else 1
    finally:
        srv.terminate()


def ask(prompt, default=None):
    tail = (' [%s]' % default) if default not in (None, '') else ''
    try:
        raw = input('%s%s: ' % (prompt, tail))
    except EOFError:
        raw = ''
    raw = raw.replace('\ufeff', '').replace('\x00', '').strip()
    return raw or (default or '')


def wizard(a):
    print('--- TLS 取证向导（直接回车用默认值）---')
    print('  场景 1 = 设备自持证书（TLS 端点在 DUT 上）')
    print('  场景 2 = 云服务器下发证书（证书由云端下发，DUT 上不一定跑 TLS）')
    sc = ask('1/7 场景 (1/2)', '1' if a.mode != 'cloud' else '2').strip()
    a.mode = 'cloud' if sc.startswith('2') else 'direct'
    tip = '2/7 目标 host[:port]（场景2 填云服务域名/地址）' if a.mode == 'cloud' else '2/7 被测设备 host[:port]'
    a.target = ask(tip, a.target or None)
    host = a.target.split(':')[0]
    a.sni = ask('3/7 SNI（证书里的名字，默认=目标）', a.sni or host)
    a.anchor = ask('4/7 信任锚证书（回车=自动从目标抓取；也可填设备已灌注证书文件）', a.anchor or 'auto')
    if a.mode == 'cloud':
        a.client_ip = ask('5/7 发起客户端 IP（设备/上位机，供 iptables 限源；可留空）', a.client_ip or '')
        a.provision_url = ask('6/7 云下发接口 URL（可留空；填了就自动验一次替换是否生效）', a.provision_url or '')
        a.transparent = ask('7/7 用透明劫持？(y=iptables+mitmproxy，需 Linux root；n=让客户端走代理) (y/n)', 'y').lower().startswith('y')
        if a.transparent:
            auto, ok = pick_proxy_host(a.client_ip or a.intercept_src)
            hint = auto if ok else (auto + '  ← 未找到与设备同网段的本机地址，请确认')
            a.proxy_host = ask('   DNAT 目标：本机在设备网段的地址（如 172.16.0.1）', hint)
            if '←' in a.proxy_host:
                a.proxy_host = a.proxy_host.split('←')[0].strip()
    else:
        a.certs_dir = ask('5/7 取证证书目录', a.certs_dir)
        a.label = ask('6/7 证据标签（如 AuthMech-04）', a.label)
        a.png = ask('7/7 是否渲染 PNG（需 Pillow）(y/n)', 'y').lower().startswith('y')
    if a.mode == 'cloud':
        a.certs_dir = ask('   取证证书目录', a.certs_dir)
        a.label = ask('   证据标签（如 AuthMech-04）', a.label)
        a.png = ask('   是否渲染 PNG（需 Pillow）(y/n)', 'y').lower().startswith('y')
        if a.transparent and not a.intercept:
            a.intercept = ['%s:%s' % (host, a.target.split(':')[1] if ':' in a.target else '443')]
        if a.client_ip and not a.intercept_src:
            a.intercept_src = a.client_ip
    return a


def fetch_anchor(a):
    os.makedirs(a.certs_dir, exist_ok=True)
    cmd = [OPENSSL, 's_client', '-connect', '%s:%d' % (a.target, a.port), '-servername', a.sni, '-showcerts']
    rc, out = run(cmd)
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', out, re.S)
    if not blocks:
        print('[error] 没能从 %s:%d 抓到证书（目标不可达或不是 TLS）' % (a.target, a.port))
        return None
    path = os.path.join(a.certs_dir, 'device.pem')
    with open(path, 'w', encoding='ascii') as fh:
        fh.write(blocks[0] + '\n')
    rc, info = run([OPENSSL, 'x509', '-in', path, '-noout', '-subject', '-issuer', '-dates', '-fingerprint', '-sha256'])
    with open(os.path.join(a.certs_dir, 'device.pem.info.txt'), 'w', encoding='utf-8') as fh:
        fh.write('fetched from %s:%d (SNI %s)\n' % (a.target, a.port, a.sni) + info)
    print('[anchor] 已自动抓取设备证书 -> %s' % path)
    for line in info.splitlines():
        print('         ' + line.strip())
    return path


# ---------------------------------------------------------------- 主流程
def build_parser():
    ap = argparse.ArgumentParser(description='通用 TLS/证书类取证脚本')
    ap.add_argument('--target', help='被测设备地址（可含 :端口）')
    ap.add_argument('--sni', default=None, help='TLS SNI，默认取 target')
    ap.add_argument('--anchor', default='auto', help='信任锚证书；auto=自动从目标抓取设备证书')
    ap.add_argument('--no-ask', action='store_true', help='不交互，缺参直接报错（CI/脚本用）')
    ap.add_argument('--ask', action='store_true', help='强制走交互向导（即使无 TTY）')
    ap.add_argument('--skip-selftest', action='store_true', help='跳过开跑前的自检')
    ap.add_argument('--regen-certs', action='store_true', help='强制重新生成取证证书')
    ap.add_argument('--certs-dir', default='tls-evidence-certs', help='替换/过期证书目录')
    ap.add_argument('--out', default=None, help='取证输出目录')
    ap.add_argument('--label', default='TLS', help='证据文件名前缀，如 AuthMech-04')
    ap.add_argument('--png', action='store_true', help='同时渲染 PNG（需 Pillow）')
    ap.add_argument('--manage-mitm', action='store_true', help='由脚本起停 mitmdump（默认自动探测）')
    ap.add_argument('--proxy', default='', help='用已存在的 mitmproxy，形如 127.0.0.1:8084')
    ap.add_argument('--mitm-port', type=int, default=0, help='mitmdump 固定端口')
    ap.add_argument('--pause', action='store_true', help='人工客户端模式：起好 mitmproxy 后停住等操作')
    ap.add_argument('--cases', default='auto', help='auto 或逗号分隔：baseline,substituted,expired,clientcert')
    ap.add_argument('--gen-certs', action='store_true', help='只生成取证用证书后退出')
    ap.add_argument('--cn', default=None, help='生成证书用的 CN（默认从 --anchor 提取）')
    ap.add_argument('--selftest', action='store_true', help='本机 s_server 自检，不连目标')
    ap.add_argument('--config', default=None, help='从 JSON 载入参数（命令行优先）')
    ap.add_argument('--save-config', default=None, help='把本次参数存成 JSON')
    ap.add_argument('--mode', choices=['auto', 'direct', 'cloud'], default='auto',
                    help='auto=按参数推断；direct=设备自持证书（直连 DUT）；cloud=云服务器下发证书（劫持云端下发通道）')
    ap.add_argument('--client-ip', default=None, help='发起客户端 IP（设备/上位机），等价于 --intercept-src')
    ap.add_argument('--transparent', action='store_true', help='mitmproxy 透明模式 + iptables DNAT 劫持（Linux；参考 mitm.py 并修正其 bug）')
    ap.add_argument('--intercept', action='append', default=[], help='透明劫持目标 host:port，可多次（如云下发服务器）')
    ap.add_argument('--intercept-src', default=None, help='只劫持来自该源 IP 的流量（设备/上位机 IP）')
    ap.add_argument('--proxy-host', default=None, help='DNAT 目的地址（跑 mitmproxy 的本机 IP），默认自动探测并按设备同网段匹配')
    ap.add_argument('--proxy-local-port', type=int, default=0, help='透明模式下另开的常规代理口（脚本自带客户端用它做检查），默认 透明口+1')
    ap.add_argument('--rules-only', action='store_true', help='只打印 iptables 规则不真正执行（dry-run）')
    ap.add_argument('--provision-cert', default=None, help='云下发场景：把响应里的证书材料替换成该 PEM')
    ap.add_argument('--provision-url', default=None, help='云下发接口 URL（自动取一次并校验替换是否生效）')
    ap.add_argument('--provision-match', default=None, help='云下发替换的 URL 匹配正则（默认 cert|pki|pem|provision|enroll 等）')
    ap.add_argument('--compare', nargs='*', default=None, help='证书比对模式：host:port [host:port ...]（TEST D 证据）')
    ap.add_argument('--serve-cert', action='store_true', help='用本机 openssl s_server 出示 --provision-cert，供客户端指到本机做下发实验')
    ap.add_argument('--no-capture', action='store_true', help='--live 时不抓设备侧 pcap（默认抓）')
    ap.add_argument('--no-kick', action='store_true', help='--live 时不主动踢掉设备与云端已建立的长连接（默认踢：长连接不会自己重连，不踢就抓不到握手）')
    ap.add_argument('--capture-if', default=None, help='设备侧抓包网卡（默认自动选与设备同网段的那张；多网卡中间盒上不要用 any）')
    ap.add_argument('--baseline-live', nargs='?', const=90, type=int, default=None,
                    help='真实设备 baseline 窗口：踢掉长连接后让设备与真服务器重新握手 N 秒（默认 90），证据=ServerHello+Certificate+应用数据（TEST B）')
    ap.add_argument('--mitm-insecure', action='store_true', help='mitmproxy 不校验上游证书（cloud 私有 PKI 场景让劫持会话能走完）')
    ap.add_argument('--live', nargs='?', const=120, type=int, default=None, help='实测窗口：起好劫持后停住 N 秒（默认 120），期间在设备上触发注册/激活，自动判定是否被拒（TEST A/C 真证据）')
    ap.add_argument('--timeout', type=int, default=60)
    return ap


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if not sys.stdin.isatty():
            sys.stdin.reconfigure(encoding='utf-8', errors='replace')   # 管道输入统一按 UTF-8 解
    except Exception:
        pass
    ap = build_parser()
    a = ap.parse_args()
    if a.config and os.path.exists(a.config):
        with open(a.config, encoding='utf-8') as fh:
            data = json.load(fh)
        for k, v in data.items():
            if getattr(a, k.replace('-', '_'), None) in (None, '', 0, False, 'auto', 'tls-evidence-certs'):
                setattr(a, k.replace('-', '_'), v)
    if a.save_config:
        with open(a.save_config, 'w', encoding='utf-8') as fh:
            json.dump({k: v for k, v in vars(a).items() if v not in (None, '')}, fh, ensure_ascii=False, indent=2)
    if a.gen_certs:
        return gen_certs(a)
    if a.selftest:
        return selftest(a)

    if a.mode == 'auto':
        a.mode = 'cloud' if (a.provision_url or a.provision_cert or a.intercept) else 'direct'

    # ---- 只打印 iptables 规则（dry-run，便于先在设备上核对）----
    if (a.transparent or a.rules_only) and a.intercept:
        # DNAT 目标必须先按“与设备同网段”定位，否则 dry-run 会印出默认路由地址（如 192.168.2.106），
        # 在被测设备网段里根本不通 —— 这正是最容易踩的坑（应为 172.16.0.1）。
        a.proxy_host, _ph = pick_proxy_host(a.intercept_src or a.client_ip, a.proxy_host)
    if a.rules_only:
        cmds = intercept_cmds(a, '-A')
        if not cmds:
            print('[error] --rules-only 需要 --intercept host:port（可多次）')
            return 2
        print('[rules] 将执行的 iptables 规则（DNAT 到 mitmproxy 端口 %d）：' % (a.mitm_port or 8084))
        for cmd in cmds:
            print('  ' + ' '.join(cmd))
        print('[rules] 删除时把 -A 换成 -D、其余参数完全相同（本工具会自动成对增删）')
        return 0

    # ---- 证书比对模式（TEST D：其他实体的私钥/证书是否可用）----
    if a.compare is not None:
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        a.out = a.out or os.path.join('evidence', '%s_%s' % (a.label, stamp))
        os.makedirs(a.out, exist_ok=True)
        targets = list(a.compare)
        if not targets and a.target:
            targets = [a.target]
        if len(targets) < 2:
            print('[error] --compare 至少给两个 host:port（如 --compare 192.0.2.10:443 192.0.2.11:443）')
            return 2
        c = case_compare(a, targets)
        save_case(a, c)
        print('\n'.join(c['transcript']))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else 1

    # ---- 本机出示被替换的证书（云下发/OTA 实验的服务端替身）----
    if a.serve_cert:
        cert = resolve_cert_arg(a, a.provision_cert)
        if not cert:
            print('[serve] --serve-cert 需要 --provision-cert 指定 cert+key 合一的 PEM（可用别名见上）')
            return 2
        port = a.mitm_port or 8443
        print('[serve] openssl s_server 在 0.0.0.0:%d 出示 %s（Ctrl+C 结束）' % (port, cert))
        print('[serve] 让设备/上位机把下发地址指到本机该端口，或用 --transparent 把它重定向过来')
        return subprocess.call(['openssl', 's_server', '-accept', str(port), '-cert', cert, '-key', cert, '-www'])

    if a.ask or (not a.no_ask and not a.target and sys.stdin.isatty()):
        a = wizard(a)
    if not a.target:
        print('[error] 需要 --target（或去掉 --no-ask 用向导交互）')
        return 2
    a.target = a.target.replace('\ufeff', '').strip()
    if a.sni:
        a.sni = a.sni.replace('\ufeff', '').strip()
    if ':' in a.target:
        a.target, port = a.target.split(':', 1)
        a.port = int(port)
    else:
        a.port = 443
    a.sni = a.sni or a.target
    if a.anchor in ('auto', '', None):
        a.anchor = fetch_anchor(a)
        if not a.anchor:
            print('[warn] 没能自动抓取信任锚 → baseline 用例跳过（云下发场景常见，继续做替换/下发/比对用例）')
    else:
        anchor = resolve_path([a.anchor, os.path.join(a.certs_dir, a.anchor), os.path.join(os.getcwd(), a.anchor)])
        if not anchor:
            print('[error] 找不到信任锚 %s' % a.anchor)
            return 2
        a.anchor = anchor
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    a.out = a.out or os.path.join('evidence', '%s_%s' % (a.label, stamp))
    os.makedirs(a.out, exist_ok=True)
    try:
        socket.create_connection((a.target, a.port), 5).close()
    except OSError as exc:
        if a.mode == 'cloud':
            print('[warn] 连不上 %s:%d (%s)：baseline 跳过，替换/下发用例仍可做' % (a.target, a.port, exc))
        else:
            print('[error] 连不上 %s:%d (%s)' % (a.target, a.port, exc))
            print('        若这是「云服务器下发证书」的项目：用 --mode cloud（target 填云服务地址），或向导里选场景 2')
            return 2
    if a.provision_cert:
        path = write_provision_addon(a)
        if not path:
            return 2
        a.provision_addon = path
    need_gen = a.regen_certs or any(not os.path.exists(os.path.join(a.certs_dir, n))
                                   for n in ('substituted.pem', 'expired.pem', 'wrongcn.pem'))
    if need_gen:
        print('[1/3] 生成取证证书 ...')
        gen_certs(a)
    if not a.skip_selftest:
        print('[2/3] 自检判定逻辑 ...')
        rc_st = selftest(a)
        if rc_st != 0:
            print('[error] 自检失败：取证判定逻辑不可信，先排查再跑（--skip-selftest 可跳过）')
            return rc_st
    if a.baseline_live is not None:
        print('[baseline] 真实设备 baseline：%d 秒窗口内让设备与真服务器重新握手（不做任何劫持）...' % a.baseline_live)
        c = case_baseline_live(a, a.baseline_live)
        save_case(a, c)
        print('')
        print('\n'.join(c['transcript']))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else 1

    if a.live is not None:
        print('[live] 起劫持并在 %d 秒窗口内观察真实设备（设备需把该域名路由到本机）...' % a.live)
        c = case_live(a, a.live)
        save_case(a, c)
        print('')
        print('\n'.join(c['transcript'][:8]))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else (2 if c['result'] == 'skip' else 1)

    print('[3/3] 采集证据 ...')
    if a.transparent:
        a.proxy_host, matched = pick_proxy_host(a.intercept_src or a.client_ip, a.proxy_host)
        print('[info] DNAT 目标本机地址 = %s %s' % (a.proxy_host, '(与设备同网段)' if matched else '(未匹配到设备网段，候选: %s；可用 --proxy-host 指定)' % ', '.join('%s/%d' % c for c in local_ipv4_list())))
    if a.intercept_src and not a.client_ip:
        a.client_ip = a.intercept_src
    if a.mode == 'cloud' and a.transparent and not a.intercept:
        a.intercept = ['%s:%d' % (a.target, a.port)]
    have_mitm = bool(shutil.which(MITMDUMP)) or bool(a.proxy)
    if not have_mitm:
        print('[hint] 未检测到 mitmdump：被替换/过期证书用例将跳过；装好后重跑本脚本即可（Kali: sudo apt install -y mitmproxy）')
    print('[info] target=%s:%d sni=%s anchor=%s' % (a.target, a.port, a.sni, a.anchor))
    print('[info] mitmproxy=%s output=%s' % ('yes' if have_mitm else 'no (跳过伪造证书用例)', a.out))

    selected = a.cases
    results = []
    if a.anchor:
        quiet = base_cmd(a) + ['-showcerts']
        rc, out = run(quiet)
        need_cc, ca_names = probe_client_cert(out)
        print('[info] 服务端是否要求客户端证书: %s%s' % (need_cc, (' (CA: %s)' % ', '.join(ca_names[:2])) if ca_names else ''))
    else:
        need_cc, ca_names = None, []
        print('[info] 无信任锚：跳过 baseline 与客户端证书探测')

    run_baseline = (selected == 'auto' or 'baseline' in selected) and bool(a.anchor)
    run_sub = selected == 'auto' or 'substituted' in selected
    run_exp = selected == 'auto' or 'expired' in selected
    run_cc = (selected == 'auto' or 'clientcert' in selected) and need_cc is True

    if run_baseline:
        c = case_direct(a)
        save_case(a, c)
        results.append(c)
    for flag, certfile, label, title in (
            (run_sub, 'substituted.pem', 'substituted_cert', 'substituted server certificate (untrusted identity) must be rejected'),
            (run_exp, 'expired.pem', 'expired_cert', 'expired server certificate must be rejected')):
        if not flag:
            continue
        if not have_mitm:
            c = {'file': a.label + '_' + label, 'title': title, 'expect': 'reject', 'result': 'skip',
                 'cmd': [], 'transcript': ['mitmproxy 未安装：安装后重跑（Kali: apt install -y mitmproxy）'], 'mitm_log': ''}
            save_case(a, c)
            results.append(c)
            continue
        c = case_server_auth(a, certfile, label, title, pause=a.pause)
        save_case(a, c)
        results.append(c)
    if run_cc:
        for certfile, label in (('wrongcn.pem', 'clientcert_wrong_identity'), ('expired.pem', 'clientcert_expired')):
            c = case_client_cert(a, certfile, label)
            save_case(a, c)
            results.append(c)
    run_prov = (selected == 'auto' or 'provision' in selected) and bool(a.provision_cert)
    if run_prov:
        if not have_mitm:
            c = {'file': a.label + '_provision_substituted', 'title': 'cloud-issued certificate substitution',
                 'expect': 'reject', 'result': 'skip', 'cmd': [],
                 'transcript': ['mitmproxy 未安装：安装后重跑（Kali: apt install -y mitmproxy）'], 'mitm_log': ''}
        else:
            c = case_provision(a, pause=a.pause)
        save_case(a, c)
        results.append(c)

    lines = ['# TLS evidence summary', '',
             '- target: %s:%d (SNI %s)' % (a.target, a.port, a.sni),
             '- anchor: %s' % a.anchor,
             '- server requests client certificate: %s' % need_cc,
             '- mitmproxy available: %s' % have_mitm, '',
             '| case | TDS | expect | result | file |', '|---|---|---|---|---|']
    for c in results:
        lbl = c['file'].replace(a.label + '_', '')
        lines.append('| %s | %s | %s | %s | %s |' % (lbl, tds_of(lbl), c['expect'], c['result'],
                                                os.path.basename(c['txt'])))
    lines += ['', '注：expect=ok 的用例必须 Verify return code: 0 (ok)；expect=reject 的用例必须握手被拒',
              '    （客户端 verify 失败 / mitmproxy 记录 does not trust the proxy certificate）。',
              '    result=fail 表示实际行为与声明不符 —— 不能写成 PASS。']
    with open(os.path.join(a.out, 'summary.md'), 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')
    with open(os.path.join(a.out, 'report.json'), 'w', encoding='utf-8') as fh:
        json.dump({'target': a.target, 'port': a.port, 'sni': a.sni, 'anchor': a.anchor,
                   'client_cert_required': need_cc, 'mitmproxy': have_mitm,
                   'cases': [{k: c[k] for k in ('file', 'expect', 'result')} for c in results]}, fh, ensure_ascii=False, indent=2)
    print('')
    print('\n'.join(lines))
    bad = [c['file'] for c in results if c['result'] not in ('pass', 'skip')]
    print('\n[out] %s' % os.path.abspath(a.out))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
