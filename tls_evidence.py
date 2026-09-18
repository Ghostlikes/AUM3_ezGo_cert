#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls_evidence.py - 閫氱敤 TLS / 璇佷功绫诲彇璇佽剼鏈紙TDS 鐨?AUM-3銆丼CM-2 绛夊満鏅鐢級

涓€娆¤繍琛屼骇鍑猴細鍩虹嚎鎻℃墜銆佽鏇挎崲璇佷功銆佽繃鏈熻瘉涔︺€佷互鍙婏紙鑻ョ鐐硅姹傚鎴风璇佷功锛夊鎴风璇佷功璐熷悜鐢ㄤ緥锛?姣忔潯鐢ㄤ緥涓€涓?txt + 涓€涓?PNG + 涓€浠?summary.md / report.json锛屽彲鏁村寘璐磋繘 TDS銆?
鐜锛氬彧闇€ openssl锛涢渶瑕佷吉閫犳湇鍔″櫒璇佷功鏃跺啀鍔?mitmproxy锛圞ali: apt install -y mitmproxy锛夈€?     PNG 闇€瑕?Pillow锛圞ali: apt install -y python3-pil锛夈€?
鍏稿瀷鐢ㄦ硶锛?  # 1) 鐢熸垚鍙栬瘉鐢ㄨ瘉涔︼紙鏇挎崲璇佷功 / 杩囨湡璇佷功 / CN 涓嶇璇佷功锛?  python3 tls_evidence.py --gen-certs --anchor device.pem --certs-dir certs --cn 169.254.0.1
  # 2) 鍏ㄨ嚜鍔ㄥ彇璇?  python3 tls_evidence.py --target 192.0.2.10 --sni device.local --anchor certs/device.pem \\
          --certs-dir certs --out evidence --label AuthMech-04 --png
  # 3) 鑷锛堜笉杩炵洰鏍囨満锛岀敤鏈満 s_server 楠岃瘉鍒ゅ畾閫昏緫锛?  python3 tls_evidence.py --selftest --certs-dir certs
  # 4) 璁╀汉宸ュ鎴风锛堜笂浣嶆満 App / 娴忚鍣級褰撳绔細璧峰ソ mitmproxy 鍚庡仠浣?  python3 tls_evidence.py --target 192.0.2.10 --anchor certs/device.pem --manage-mitm --pause

鍒ゅ畾鍙ｅ緞锛氱敤渚嬪０鏄?expect=ok 鎴?expect=reject锛涘疄闄呬笌澹版槑涓嶇鍗虫暣浣撻潪 0 閫€鍑猴紝閬垮厤鎶婁笉鍚堟牸鍐欐垚 PASS銆?"""

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


# ---------------------------------------------------------------- 鍩虹宸ュ叿
def run(cmd, timeout=60):
    """鎵ц鍛戒护骞惰繑鍥?(rc, 鍚堝苟杈撳嚭)銆傝秴鏃朵笉鍐嶆姏寮傚父锛氳繑鍥?rc=124 + 宸叉崟鑾疯緭鍑猴紝
    鍚﹀垯涓€娆℃寕浣忕殑 s_client 浼氭妸鏁磋疆鍙栬瘉甯﹀穿銆?""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           encoding='utf-8', errors='replace',
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or '')
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ''
        if isinstance(partial, bytes):
            partial = partial.decode('utf-8', 'replace')
        return 124, partial + '\n[TIMEOUT] 鍛戒护 %d 绉掓湭缁撴潫锛?s' % (timeout, ' '.join(cmd))
    except OSError as exc:
        return 127, '[ERROR] 鏃犳硶鎵ц %s: %s' % (cmd[0], exc)


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


# ---------------------------------------------------------------- 璇佷功鐢熸垚
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
                print('[warn] 鐢熸垚 %s 澶辫触锛?s' % (fn, out.strip().splitlines()[:1]))
                continue
            with open(target, 'a', encoding='ascii') as fh:
                fh.write(open(target + '.key', encoding='ascii').read())
            print('[warn] %s 鐢?openssl 鐢熸垚锛堣繃鏈熻瘉涔﹂渶 cryptography锛屽凡閫€鍖栦负鏈夋晥鏈熷唴鐨勮嚜绛捐瘉涔︼級' % fn)
        made.append(target)
        print('[gen] %s (CN=%s)' % (target, this_cn))
    print('[gen] 鍏?%d 涓瘉涔︼紝鐩綍 %s' % (len(made), os.path.abspath(a.certs_dir)))
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
                # 閫忔槑鍙ｇ粰璁惧锛堣 iptables 寮曟祦锛夛紱鍙﹀紑涓€涓父瑙勪唬鐞嗗彛缁欒剼鏈嚜宸辩殑妫€鏌ュ鎴风锛?                # 閫忔槑妯″紡涓嬬敤 -proxy 杩為€忔槑鍙ｄ細鎶?CONNECT 褰撳師濮嬫祦閲忚浆鍑哄幓 鈫?蹇呯劧鎸備綇
                self.client_proxy_port = self.a.proxy_local_port or (self.port + 1)
                cmd += ['--mode', 'transparent@%d' % self.port, '--mode', 'regular@%d' % self.client_proxy_port]
            elif modern:
                self.client_proxy_port = None      # 鍙紑閫忔槑鍙ｏ細鑴氭湰鑷甫瀹㈡埛绔鏌ヤ笉鍙敤锛屾敼鐢?--pause
                cmd += ['--mode', 'transparent@%d' % self.port]
            else:
                # mitmproxy <= 8.x锛氭ā寮忚娉曚笉甯︾鍙ｏ紝鐩戝惉鍙ｅ彧鑳界敱 -p 鎸囧畾锛屼笖涓€杩涚▼鍙敮鎸佸崟妯″紡锛?                # 鐢ㄦ埛鐜锛圧asPi/Kali锛夊疄娴?mitmdump 8.1.1 鍗冲睘姝ょ被锛?transparent@8084" 浼氳鎷?                self.client_proxy_port = None
                cmd += ['-p', str(self.port), '--mode', 'transparent']
        else:
            self.client_proxy_port = self.port
            cmd += ['-p', str(self.port)]
        if cert:
            cmd += ['--set', 'certs=*=' + os.path.abspath(cert)]
        if getattr(self.a, 'mitm_insecure', False):
            cmd += ['--set', 'ssl_insecure=true']   # 浜戠鐢ㄧ鏈?PKI 鏃朵笉鏍￠獙涓婃父锛岃鍔寔浼氳瘽鑳借蛋瀹?        addon = getattr(self.a, 'provision_addon', None)
        if addon:
            cmd += ['-s', addon]
        cmd += ['-w', os.path.join(self.a.out, 'flows_%s.mitm' % tag)]
        return cmd

    def _spawn(self):
        try:
            self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as exc:
            self.proc = None
            self.log += '[ERROR] 璧蜂笉浜?%s: %s锛坢itmproxy 鏈畨瑁咃紵Kali: sudo apt install -y mitmproxy锛? % (self.cmd[0], exc)
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
        """cert=None 鏃跺彧鍋氫唬鐞嗭紙鐢ㄤ簬浜戜笅鍙戞浛鎹細闈?addon 鏀瑰搷搴斾綋锛屼笉鍔ㄦ湇鍔″櫒璇佷功锛夈€?""
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
                    print('[warn] 宸叉寜鏈満 mitmdump 璇硶鍥為€€锛?s锛夛細鏈繘绋嬪彧寮€涓€涓彛锛岃剼鏈嚜甯︾殑妫€鏌ュ鎴风浼氳烦杩囷紝'
                          '璇风敤鐪熷疄璁惧/涓婁綅鏈洪厤鍚?--live 鎴?--pause' % ('浠呴€忔槑鍙? if modern else 'mitmproxy 8.x锛?p + --mode transparent'))
                return True
            tail = (self.log.strip().splitlines() or [''])[-1][:160]
            print('[warn] mitmdump 鍚姩澶辫触锛?s锛? %s' % ('transparent@%d' % self.port if modern else '-p %d --mode transparent' % self.port, tail))
            if 'Invalid mode specification' not in self.log and 'invalid mode' not in self.log.lower():
                break          # 涓嶆槸妯″紡璇硶闂锛堢己 mitmdump / 绔彛琚崰锛夛紝鎹㈣娉曚篃娌＄敤
        self.stop()            # 璧蜂笉鏉ヤ篃瑕佹妸 iptables 鍔寔瑙勫垯鎾ゆ帀锛屽惁鍒欒澶囬摼璺鎴戜滑鎸′綇
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


# ---------------------------------------------------------------- 鐢ㄤ緥
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
                    'transcript': ['褰撳墠鍙湁閫忔槑鍙ｏ紙mitmdump 涓嶆敮鎸佸妯″紡锛屾垨鏈紑甯歌鍙ｏ級锛?,
                                   '璇峰姞 --pause 璁╃湡瀹炶澶?涓婁綅鏈鸿窇涓€娆★紝',
                                   '鎴栫敤 --proxy-local-port 鎸囧畾涓€涓父瑙勪唬鐞嗗彛缁欒剼鏈嚜甯﹀鎴风'],
                    'mitm_log': ''}
        if pause:
            print('\n[mitmproxy] 閫忔槑鍙?%d / 妫€鏌ュ鎴风鐢?%s锛屽嚭绀鸿瘉涔?%s' % (m.port, m.client_proxy_port, cert))
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


# ------------------------------------------------- 閫忔槑鍔寔锛堝弬鑰?mitm.py锛屼慨姝ｅ叾涓や釜 bug锛?def detect_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()


def local_ipv4_list():
    """鏈満 IPv4 鍒楄〃 [(ip, prefix)]銆侺inux 鐢?`ip -4 -o addr show`锛堝甫鎺╃爜锛夛紝
    澶辫触閫€鍥?hostname -I锛屽啀澶辫触閫€鍥為粯璁よ矾鐢卞湴鍧€銆?""
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
    """閫?DNAT 鐩爣鍦板潃锛氫紭鍏堜笌鈥滆澶?瀹㈡埛绔?IP鈥濆悓缃戞鐨勬湰鏈哄湴鍧€銆?    鎵嬪伐缁欎簡 --proxy-host 灏辩敤瀹冿紱鍚﹀垯鎸?client_ip 鐨勭綉娈靛尮閰嶏紱閮戒笉琛岀敤绗竴涓€欓€夈€?""
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
    """鐢熸垚/鍒犻櫎 iptables DNAT 瑙勫垯銆?    淇 mitm.py 鐨勪袱涓?bug锛氣憼 鍘熸潵 mitmdump 甯?--rawtcp锛堝彧杞彂瀛楄妭銆佷笉浼€犺瘉涔︼級锛?    鈶?鍒犻櫎瑙勫垯鏃?--to-destination 鍐欑殑鏄彟涓€涓湴鍧€锛?D 鍖归厤涓嶄笂瀵艰嚧瑙勫垯娈嬬暀銆?    杩欓噷澧炲垹鐢ㄥ悓涓€鏉¤鍒欙紝涓旂洰鐨勫湴鍧€鍙畻涓€娆°€?""
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
            print('[error] 鍔犺鍒欏け璐? %s' % (p.stdout or '').strip())
            del_intercept_rules(a)
            return False
    return True


def del_intercept_rules(a):
    for cmd in intercept_cmds(a, '-D'):
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('[iptables] 鍒犻櫎 -> %s' % ('ok' if p.returncode == 0 else (p.stdout or '').strip()))


def kick_cmds(a, action):
    """韪㈡帀璁惧涓庝簯绔箣闂粹€滃凡寤虹珛鈥濈殑闀胯繛鎺ワ紝閫煎畠鍦ㄥ姭鎸佺獥鍙ｅ唴閲嶆柊鎻℃墜銆?    涓轰粈涔堝繀椤昏涪锛歯at/PREROUTING 鐨?DNAT 鍙鈥滄柊寤衡€濊繛鎺ョ敓鏁堬紝MQTT/HTTP 闀胯繛鎺?    锛坘eepalive 鍔ㄨ緞鍑犲垎閽燂級鍦ㄧ獥鍙ｅ唴鏍规湰涓嶄細閲嶈繛锛屼簬鏄姄涓嶅埌浠讳綍鎻℃墜銆?    鑰佽繛鎺ヨ蛋 FORWARD锛屽湪閭ｉ噷 tcp-reset 鎺夊畠锛涜澶囬噸杩炵殑 SYN 灞炴柊寤鸿繛鎺ワ紝
    鍦?PREROUTING 灏辫 DNAT 鍒?mitmproxy銆佷笉杩?FORWARD锛屾墍浠ヤ笉褰卞搷鎴戜滑鑷繁鐨勫姭鎸佷細璇濄€?""
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
            print('[warn] 韪㈣繛鎺ヨ鍒欏姞涓嶄笂: %s' % (p.stdout or '').strip())
            ok = False
    return ok


def del_kick_rules(a):
    for cmd in kick_cmds(a, '-D'):
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print('[kick] 鍒犻櫎 -> %s' % ('ok' if p.returncode == 0 else (p.stdout or '').strip()))


def kick_hits(a):
    """鎴戜滑閭ｆ潯 REJECT 瑙勫垯宸茬粡鍛戒腑杩囧灏戜釜鍖咃紙iptables -vnL 鐨勭涓€鍒楋級銆?    璁惧绌洪棽鏃跺畠涓€涓寘閮戒笉鍙戯紝瑙勫垯鎸傜潃涔熸病鐢紱涓€鏃﹀懡涓氨璇存槑鐪熸妸瀹冭涪鏂簡銆?""
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
    """韪竴娆¤€侀暱杩炴帴锛氬姞 REJECT 瑙勫垯 鈫?绛夊畠鍛戒腑锛堣澶囦笅涓€涓姤鏂囷級鈫?绔嬪埢鎾よ鍒欍€?    瑙勫垯蹇呴』灏藉揩鎾ゆ帀锛氭湭鍔寔鐨?baseline 鍦烘櫙閲岋紝涓€鐩存寕鐫€鐨?REJECT 浼氭妸璁惧閲嶈繛鐨?    鏂?SYN 涔?RST 鎺夛紝绐楀彛鍐呭氨姘歌繙鎻′笉涓婃墜銆?""
    if not add_kick_rules(a):
        return 0
    t0 = time.time()
    hits = 0
    while time.time() - t0 < max_wait:
        time.sleep(1.0)
        hits = kick_hits(a)
        if hits:
            time.sleep(0.5)          # 璁?RST 鍙戝嚭鍘?            break
    del_kick_rules(a)
    print('[kick] %s锛堝懡涓?%d 涓姤鏂囷紝瑙勫垯宸叉挙锛? % ('宸茶涪鏂澶囦笌浜戠鐨勯暱杩炴帴' if hits else '绛夊緟鏈熷唴璁惧娌℃湁鍙戝寘锛屾病韪㈠埌',
                                                hits))
    return hits


# ------------------------------------------------- 浜戜笅鍙?OTA 璇佷功鏇挎崲锛坢itmproxy addon锛?PROVISION_ADDON = '''# -*- coding: utf-8 -*-
"""鐢?tls_evidence.py 鐢熸垚锛氭妸琚姭鎸佸搷搴旈噷鐨勮瘉涔︽潗鏂欐浛鎹㈡垚鍙栬瘉鐢ㄨ瘉涔︺€?鐢ㄤ簬銆庝簯鏈嶅姟鍣ㄤ笅鍙戣瘉涔︺€忕被椤圭洰锛氳澶?涓婁綅鏈轰粠浜戠鍙栬瘉涔︼紝鎴戜滑鏇挎崲鎴愭湭鎺堟潈/杩囨湡璇佷功锛?瑙傚療瀵圭鏄惁鎷掔粷锛圱EST A/C锛夈€?""
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
    """鎶?--provision-cert / --serve-cert 鐨勫€艰В鏋愭垚瀹為檯鏂囦欢锛氱浉瀵硅矾寰勩€乧erts-dir 鍐呮煡鎵撅紝
    浠ュ強鍒悕锛坲ntrusted|substituted|expired|wrongcn|unauthorized锛夛紱鎵句笉鍒版椂鍒楀嚭鍙敤鏂囦欢銆?""
    if not name:
        return None
    cands = [name, os.path.join(a.certs_dir, name)]
    alias = CERT_ALIASES.get(os.path.basename(name).lower())
    if alias:
        cands += [os.path.join(a.certs_dir, alias), alias]
    path = resolve_path(cands)
    if path and os.path.basename(path) != os.path.basename(name):
        print('[info] %s 鈫?瀹為檯浣跨敤 %s锛堝埆鍚嶏級' % (name, path))
    if not path:
        have = sorted(os.listdir(a.certs_dir)) if os.path.isdir(a.certs_dir) else []
        print('[error] 鎵句笉鍒拌瘉涔? ' + str(name))
        print('        %s 涓嬬幇鏈? %s' % (a.certs_dir, ', '.join(have) if have else '(绌猴紝鍏堣窇 --gen-certs)'))
        print('        鍙敤鍒悕: untrusted|substituted 鈫?substituted.pem, expired 鈫?expired.pem, wrongcn|unauthorized 鈫?wrongcn.pem')
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
    print('[provision] addon 宸茬敓鎴? %s锛堝尮閰?%s锛? % (path, match))
    return path


def case_provision(a, pause=False):
    """缁忎唬鐞嗗彇涓€娆′簯涓嬪彂鎺ュ彛锛屾鏌ュ搷搴旈噷鐨勮瘉涔︽槸鍚﹀凡琚浛鎹㈡垚鎴戜滑鐨勮瘉涔︺€?""
    if not (a.provision_url and a.provision_cert):
        return {'file': a.label + '_provision_substituted', 'title': 'cloud-issued certificate substitution',
                'expect': 'reject', 'result': 'skip', 'cmd': [], 'transcript': ['闇€瑕?--provision-url 涓?--provision-cert'], 'mitm_log': ''}
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
                    'transcript': ['褰撳墠鍙湁閫忔槑鍙ｏ細璇风敤 --pause 璁╃湡瀹炶澶囪窇涓€娆′笅鍙戯紝鎴栫敤 --proxy-local-port 鎸囧畾甯歌浠ｇ悊鍙?],
                    'mitm_log': ''}
        if pause:
            print('\n[provision] mitmproxy 閫忔槑鍙?%d / 妫€鏌ュ鎴风 %s锛涜璁╄澶?涓婁綅鏈鸿窇涓€娆′笅鍙? % (m.port, m.client_proxy_port))
            input('            瀹屾垚涓€娆′笅鍙戝悗鎸夊洖杞︾户缁?..')
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
            except Exception as exc:      # 鍙栦笉鍒颁笉绠楀け璐ワ細鍙兘鎺ュ彛瑕侀壌鏉冿紝鏃ュ織浠嶆湁鏇挎崲璁板綍
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
            'transcript': interesting(body, 12) + ['', '鎴戜滑鐨勮瘉涔?SHA256: %s' % ours, '鍝嶅簲涓殑璇佷功 SHA256: %s' % ', '.join(served) if served else '鍝嶅簲涓湭瑙ｆ瀽鍒拌瘉涔?,
                                                   '', '--- provision log ---'] + (log.splitlines()[-15:] or ['(no substitution logged)']),
            'mitm_log': (log.splitlines()[-1] if log else '')}


# ------------------------------------------------- 璇佷功姣斿锛圱EST D / 鍞竴鎬э級
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
    """TEST B 鍒ゆ嵁锛氳澶囧埌鐪熸湇鍔″櫒瀹屾垚浜嗘彙鎵?鈥斺€?鎶撳埌 ServerHello + Certificate锛堟湇鍔″櫒渚э級锛?    浠ュ強璁惧渚х殑搴旂敤鏁版嵁璁板綍銆?""
    dut = a.intercept_src or a.client_ip or ''
    if not os.path.exists(pcap):
        return False, ['(娌℃湁 baseline pcap锛歵cpdump 鏈惎鐢ㄦ垨鏉冮檺涓嶈冻)']
    if not shutil.which('tshark'):
        return False, ['(娌¤ tshark锛屾棤娉曡В鏋?baseline)']
    rc, out = tshark_run(pcap, ['-Y', 'tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11',
                                '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tls.handshake.type'], timeout=180)
    rows = [l.strip() for l in out.splitlines() if re.match(r'^\d', l.strip())]
    ch = [r for r in rows if r.endswith('\t1') and dut in r.split('\t')[1]]
    sh = [r for r in rows if r.endswith('\t2') and dut not in r.split('\t')[1]]
    cert = [r for r in rows if r.endswith('\t11') and dut not in r.split('\t')[1]]
    rc, out2 = tshark_run(pcap, ['-Y', 'tls.record.content_type==23', '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ip.src'], timeout=180)
    appdata = [l.strip() for l in out2.splitlines() if dut and dut in l]
    lines = ['璁惧 ClientHello        : %d 娆? % len(ch),
             '鏈嶅姟鍣?ServerHello      : %d 娆? % len(sh),
             '鏈嶅姟鍣?Certificate      : %d 娆? % len(cert),
             '璁惧渚у簲鐢ㄦ暟鎹褰?     : %d 鏉★紙鎻℃墜瀹屾垚鍚庢湁鐪熷疄涓氬姟鏁版嵁锛? % len(appdata),
             '鎶撳寘缃戝崱                : %s' % capture_iface(a)]
    if sh and cert and appdata:
        lines.append('=> 璁惧涓庣湡鏈嶅姟鍣ㄦ彙鎵嬪苟浜ゆ崲搴旂敤鏁版嵁锛氶摼璺甯革紙baseline OK锛?)
        return True, lines
    if sh and cert:
        lines.append('=> 鎻℃墜瀹屾垚浣嗘病鏈夋姄鍒板簲鐢ㄦ暟鎹紙璁惧鍙兘鍦ㄦ彙鎵嬪悗绔嬪嵆鏂紑锛?)
        return False, lines
    lines.append('=> 娌℃姄鍒版湇鍔″櫒 ServerHello/Certificate锛氭湰绐楀彛鍐呰澶囨湭閲嶆柊鎻℃墜锛屽欢闀?--baseline-live 鎴栧啀韪竴娆?)
    return False, lines


def case_baseline_live(a, seconds=90):
    """鐪熷疄璁惧涓婄殑 TEST B锛氬厛韪㈡帀闀胯繛鎺ワ紝鍐嶈璁惧鑷繁涓庣湡鏈嶅姟鍣ㄩ噸鏂版彙鎵嬶紙鏃犲姭鎸侊級銆?""
    cap = start_capture(a, 'device_baseline')
    if not getattr(a, 'no_kick', False):
        # 鍏抽敭锛氳澶囩┖闂叉椂涓€涓寘閮戒笉鍙戯紝鍙?RST 鑰佽繛鎺ヨ涪涓嶅姩瀹冿紙瀹炴祴韪㈠畬鑳介潤榛樺ソ鍑犲垎閽燂級銆?        # 鍏堟妸璁惧鍒颁簯鐨勬祦閲忓叏 RST 鎺夛紝閫煎畠杩涘叆鈥滃崄鍑犵涓€娆♀€濈殑閲嶈繛寰幆锛涚瓑 pcap 閲岀湡鐪嬪埌瀹冪殑
        # SYN 鍐嶆挙瑙勫垯 鈥斺€?姝ゆ椂瀹冪殑涓嬩竴娆￠噸杩炲氨鏄洿杩炵湡鏈嶅姟鍣紝鎶撳埌鐨勬彙鎵嬫墠绠?baseline銆?        print('[kick] 鎸傜潃 REJECT 閫艰澶囪繘鍏ラ噸杩炲惊鐜紙鏈€闀?%d 绉掞紝鐪嬪埌璁惧 SYN 灏辨斁寮€锛?..' % max(30, min(180, seconds)))
        add_kick_rules(a)
        t1 = time.time()
        while time.time() - t1 < max(30, min(180, seconds)):
            time.sleep(3)
            if count_device_syns(baseline_path(a), a.intercept_src or a.client_ip):
                break
        del_kick_rules(a)
        print('[kick] 宸叉斁寮€锛堢瓑浜?%d 绉掞級锛氳澶囦笅涓€娆￠噸杩炵洿杩炵湡鏈嶅姟鍣? % int(time.time() - t1))
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
            'transcript': ['[BASELINE] 瀹炴祴绐楀彛 %d 绉掞紙鏃犲姭鎸併€佷笉鏇挎崲璇佷功锛? % seconds, '缁撹: %s' % ('璁惧涓庣湡鏈嶅姟鍣ㄦ彙鎵嬫垚鍔燂紙baseline 鎴愮珛锛? if ok else '璇佹嵁涓嶈冻')] + lines,
            'mitm_log': ''}


def case_live(a, seconds=120):
    """瀹炴祴绐楀彛锛氳捣濂?mitmproxy + iptables 鍚庡仠浣忥紝璁╃湡瀹炶澶?涓婁綅鏈鸿窇涓€娆★紝鍐嶆寜鏃ュ織鍒ゅ畾銆?""
    cert = resolve_cert_arg(a, a.provision_cert or 'substituted.pem')
    if not cert:
        return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
                'expect': 'reject', 'result': 'error', 'cmd': [],
                'transcript': ['闇€瑕佷竴寮犲彇璇佽瘉涔︼紙--provision-cert锛岄粯璁?substituted.pem锛?], 'mitm_log': ''}
    m = Mitm(a)
    if not m.start(cert):
        return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
                'expect': 'reject', 'result': 'error', 'cmd': m.cmd,
                'transcript': (m.log.strip().splitlines()[:6] or ['mitmdump failed to start']), 'mitm_log': ''}
    print('')
    print('[LIVE] 鍔寔宸茬敓鏁堬紙閫忔槑鍙?%s / 妫€鏌ュ彛 %s锛屽嚭绀?%s锛? % (m.port, m.client_proxy_port, os.path.basename(cert)))
    print('       鐜板湪璇峰湪璁惧/涓婁綅鏈轰笂瑙﹀彂涓€娆℃敞鍐?婵€娲?閲嶈繛锛?d 绉掑唴鎴栨寜鍥炶溅缁撴潫銆? % seconds)
    if not getattr(a, 'no_kick', False):
        print('[kick] 鎸傜潃 REJECT 韪㈡帀璁惧涓庝簯绔殑闀胯繛鎺ワ紙鑰佽繛鎺ヨ蛋 FORWARD 琚?RST锛涢噸杩炵殑鏂?SYN 鍦?PREROUTING 灏辫 DNAT 鍒版湰鏈猴紝涓嶅彈褰卞搷锛?)
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
                # 闈炰氦浜?鎵瑰鐞嗛噷 stdin 鐩存帴 EOF锛氫笉鑳藉綋浣溾€滄寜鍥炶溅鎻愬墠缁撴潫鈥濓紝
                # 鍚﹀垯绐楀彛 0 绉掑氨鏀跺熬锛堣剼鏈粠 -m/绠￠亾璺戞椂蹇呰俯锛夛紝鏀规垚绛夋弧绐楀彛
                stdin_live = False
                continue
            break                     # 鐪熸湁杈撳叆锛堝惈鍗曠嫭涓€涓洖杞︼級鎵嶆彁鍓嶇粨鏉?    finally:
        stop_capture(cap)
        m.stop()
        del_kick_rules(a)
    cap_lines, dev_conns, dev_events, hellos = decode_capture(a)
    log = m.log or ''
    # 鍙鈥滃鎴风渚р€濇彙鎵嬪け璐ワ細mitmproxy 杩炰笂娓稿け璐ヤ篃浼氭墦 CERTIFICATE_VERIFY_FAILED锛?    # 閭ｆ槸鎴戜滑鍒颁簯绔殑閿欒銆佷笉鏄澶囨嫆缁濇垜浠€斺€旀贩鍦ㄤ竴璧蜂細鎶婅瘉鎹鍒ゆ垚 PASS銆?    upstream_err = [l.strip() for l in log.splitlines()
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
        result, note = 'pass', '璁惧涓诲姩鍙戣捣鎻℃墜鍚庤鎷掞紙mitmproxy 璁板綍瀹㈡埛绔彙鎵嬪け璐?/ 璁惧渚?TLS alert路RST锛夆€斺€?TEST A/C 璇佹嵁鎴愮珛'
    elif hellos and (served or dev_log):
        result, note = 'fail', '璁惧涓庢垜浠畬鎴愪簡 TLS 鎻℃墜銆佹病鏈夋嫆缁濊鏇挎崲鐨勮瘉涔?鈥斺€?灞炰笉绗﹀悎锛屼笉鑳藉啓 PASS'
    elif dev_conns == 0 and not hellos and not dev_log:
        result, note = 'skip', '鏈獥鍙ｅ唴娌℃湁瑙傚療鍒拌澶囨祦閲忥細纭璁惧缃戝叧鎸囧悜鏈満锛屾垨鐪熸瑙﹀彂娉ㄥ唽/婵€娲?閲嶈繛鍚庨噸璺?--live'
    elif served or sub or dev_log:
        result, note = 'fail', '璁惧鍙戣捣浜嗚繛鎺ヤ絾娌℃湁鎷掔粷鎴戜滑鍑虹ず鐨勮瘉涔?鈥斺€?灞炰笉绗﹀悎锛屼笉鑳藉啓 PASS'
    else:
        result, note = 'skip', '璇佹嵁涓嶈冻锛氳妫€鏌ユ姄鍖呮潈闄愪笌璁惧缃戝叧鍚庨噸璺?--live'
    lines = ['[LIVE] 瀹炴祴绐楀彛 %d 绉掞紝鍑虹ず璇佷功 %s' % (seconds, cert), '缁撹: %s' % note, '',
             '--- 璁惧渚ф姄鍖呯粨璁?(%s) ---' % capture_path(a)] + cap_lines + ['', '--- mitmproxy 鏃ュ織锛堝熬閮?40 琛岋級---']
    lines += (log.splitlines()[-40:] or ['(绌猴細鏈瀵熷埌杩炴帴)'])
    if sub:
        lines += ['', '--- 浜戜笅鍙戞浛鎹㈡棩蹇?---'] + sub[-20:]
    return {'file': a.label + '_device_live', 'title': 'live interception of the real device (TEST A/C)',
            'expect': 'reject', 'result': result, 'cmd': m.cmd,
            'transcript': lines, 'mitm_log': (rejects[0] if rejects else (sub[-1] if sub else ''))}


# ------------------------------------------------- 璁惧渚ф姄鍖咃紙璇佹槑 DUT 鐪熸鍙戣捣骞惰鎷掞級
def capture_path(a, tag='device_live'):
    return os.path.join(a.out, tag + '.pcap')


def capture_iface(a):
    """鎶撳寘缃戝崱锛氭樉寮?--capture-if 浼樺厛锛涘惁鍒欓€夆€滀笌璁惧鍚岀綉娈碘€濈殑閭ｅ紶缃戝崱銆?    -i any 鍦ㄥ缃戝崱涓棿鐩掍笂浼氭紡鎺夋湰鍦?DNAT 鍚庣殑鎻℃墜鎶ユ枃锛屽疄娴嬪彧鏈夎惤鍦?    璁惧渚х綉鍗★紙濡?srsRAN 鐨?srs_spgw_sgi锛変笂鎵嶇湅寰楀埌 SYN/ClientHello銆?""
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
        print('[warn] 娌¤ tcpdump锛岃烦杩囪澶囦晶鎶撳寘锛堝垽瀹氬彧渚濇嵁 mitmproxy 鏃ュ織锛?)
        return None
    src = a.intercept_src or a.client_ip
    ports = sorted({int(item.partition(':')[2] or 443) for item in (a.intercept or [])}) or [443]
    parts = []
    if src:
        parts.append('host %s' % src)
    parts.append('(' + ' or '.join('port %d' % p for p in ports) + ')')
    parts.append('tcp')
    user = os.environ.get('SUDO_USER') or os.environ.get('USER') or getpass.getuser()
    # -Z锛氳 tcpdump 鎶?pcap 鍐欐垚褰撳墠鐢ㄦ埛鎵€鏈夈€傚惁鍒欐枃浠跺睘浜?tcpdump:tcpdump锛?    # tshark 浠?O_RDWR 鎵撳紑浼氳鎷掞紙鎶?You don't have permission to read the file锛夈€?    cmd = ['sudo', 'tcpdump', '-i', capture_iface(a), '-n', '-s', '0', '-U', '-Z', user,
           '-w', capture_path(a, tag), ' and '.join(parts)]
    print('[capture] ' + ' '.join(cmd))
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        print('[warn] 鎶撳寘鍚姩澶辫触: %s' % exc)
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
    """tshark 鎸夎矾寰勬墦寮€ pcap 鍦ㄩ儴鍒嗘満鍣ㄤ笂浼氳鎷掞紙杩?root 閮芥姤
    'You don't have permission to read the file'锛夛紝浣嗘妸鏂囦欢浠?stdin 鍠傝繘鍘?    锛坱shark -r -锛夊畬鍏ㄦ甯?鈥斺€?缁熶竴璧?stdin锛屼繚璇佽瘉鎹В鏋愮湡鐨勫彂鐢熴€?""
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
    """鏁?pcap 閲岃澶囧彂鍑虹殑 SYN锛堝垽鏂€滆澶囨槸鍚﹀凡缁忓紑濮嬮噸杩炩€濓級銆?""
    if not dut or not shutil.which('tshark') or not os.path.exists(pcap):
        return 0
    rc, out = tshark_run(pcap, ['-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0', '-T', 'fields', '-e', 'ip.src'], timeout=60)
    return len([l for l in out.splitlines() if dut in l])


def decode_capture(a, tag='device_live'):
    """瑙ｆ瀽璁惧渚ф姄鍖咃細璁惧鍙戣捣杩炴帴娆℃暟 + 鎷掔粷绫讳簨浠讹紙TLS alert / RST锛夈€?""
    pcap = capture_path(a, tag)
    dut = a.intercept_src or a.client_ip
    if not os.path.exists(pcap):
        return ['(娌℃湁 pcap 鏂囦欢锛歵cpdump 鏈惎鐢ㄦ垨鏉冮檺涓嶈冻)'], 0, 0, []
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
    # 鍙湅鈥滆澶囪嚜宸卞彂鍑虹殑鈥濇嫆缁濓細TLS alert / RST 鐨?ip.src 蹇呴』鏄澶囷紱
    # 鍒汉 RST 璁惧锛坕p.dst=璁惧锛変笉绠楄澶囨嫆缁?    dev_events = []
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
    lines = ['璁惧鍙戣捣杩炴帴锛圫YN锛? %d 娆★紙鍏ㄩ儴 SYN 婧? %s锛? % (len(dev_syns), ', '.join(sorted({s.split(' ')[0] for s in syns})) or '鏃?)]
    snis = sorted({h.split('\t')[1] for h in hellos if '\t' in h and h.split('\t')[1]})
    lines.append('璁惧鍙戝嚭鐨?TLS ClientHello: %d 娆?s' % (len(hellos), ('锛圫NI: %s锛? % ', '.join(snis)) if snis else ''))
    if dev_events:
        lines += ['鎷掔粷绫讳簨浠讹紙鏉ヨ嚜璁惧锛? %d 鏉? % len(dev_events)] + ['  ' + e[:150] for e in dev_events[:20]]
    else:
        lines.append('璁惧渚ф病鏈夊彂鍑?TLS alert / RST锛圱LS1.3 鐨?alert 鏄瘑鏂囷紝鎶撳寘鐪嬩笉鍒版椂浠?mitmproxy 鏃ュ織涓哄噯锛?)
    return lines, len(dev_syns), len(dev_events), hellos


def case_compare(a, targets):
    rows = []
    for t in targets:
        host, _, prt = t.partition(':')
        d = fetch_leaf(host, int(prt or 443), a.sni if a.sni == host else host, a.out)
        if d:
            rows.append(d)
    lines = ['璇佷功姣斿锛堟瘡鍙?姣忎釜绔偣鐨勫彾瀛愯瘉涔︼級', '']
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
            dup.append('%s 涓?%s 鐨勮瘉涔﹀畬鍏ㄧ浉鍚岋紙serial %s锛? % (d['target'], seen[key], d.get('serial')))
        else:
            seen[key] = d['target']
    if len(rows) < 2:
        lines.append('锛堝彧鍙栧埌 %d 涓鐐癸紝鑷冲皯缁欎袱涓墠鏋勬垚鍞竴鎬ф瘮瀵癸級' % len(rows))
    lines += ['缁撹:', '  ' + ('锛?.join(dup) if dup else '鍚勭鐐硅瘉涔︿簰涓嶇浉鍚岋紙搴忓垪鍙?SHA256 鍧囦笉涓€鑷达級')]
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

# ---------------------------------------------------------------- 鑷
def selftest(a):
    good = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.pem', 'untrusted.pem', 'expired.pem', 'wrongcn.pem')])
    crt = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.crt', 'untrusted.crt')])
    key = resolve_path([os.path.join(a.certs_dir, n) for n in ('substituted.key', 'untrusted.key')])
    if good is None and (crt is None or key is None):
        print('[selftest] 闇€瑕?--certs-dir 涓嬫湁 substituted.pem锛堟垨 substituted.crt/.key锛夛紱鍏堣窇 --gen-certs')
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
            print('[selftest] 缂哄皯绗簩寮犱笉鍚岃瘉涔︾敤浜庤礋鍚戝鐓?)
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
    print('--- TLS 鍙栬瘉鍚戝锛堢洿鎺ュ洖杞︾敤榛樿鍊硷級---')
    print('  鍦烘櫙 1 = 璁惧鑷寔璇佷功锛圱LS 绔偣鍦?DUT 涓婏級')
    print('  鍦烘櫙 2 = 浜戞湇鍔″櫒涓嬪彂璇佷功锛堣瘉涔︾敱浜戠涓嬪彂锛孌UT 涓婁笉涓€瀹氳窇 TLS锛?)
    sc = ask('1/7 鍦烘櫙 (1/2)', '1' if a.mode != 'cloud' else '2').strip()
    a.mode = 'cloud' if sc.startswith('2') else 'direct'
    tip = '2/7 鐩爣 host[:port]锛堝満鏅? 濉簯鏈嶅姟鍩熷悕/鍦板潃锛? if a.mode == 'cloud' else '2/7 琚祴璁惧 host[:port]'
    a.target = ask(tip, a.target or None)
    host = a.target.split(':')[0]
    a.sni = ask('3/7 SNI锛堣瘉涔﹂噷鐨勫悕瀛楋紝榛樿=鐩爣锛?, a.sni or host)
    a.anchor = ask('4/7 淇′换閿氳瘉涔︼紙鍥炶溅=鑷姩浠庣洰鏍囨姄鍙栵紱涔熷彲濉澶囧凡鐏屾敞璇佷功鏂囦欢锛?, a.anchor or 'auto')
    if a.mode == 'cloud':
        a.client_ip = ask('5/7 鍙戣捣瀹㈡埛绔?IP锛堣澶?涓婁綅鏈猴紝渚?iptables 闄愭簮锛涘彲鐣欑┖锛?, a.client_ip or '')
        a.provision_url = ask('6/7 浜戜笅鍙戞帴鍙?URL锛堝彲鐣欑┖锛涘～浜嗗氨鑷姩楠屼竴娆℃浛鎹㈡槸鍚︾敓鏁堬級', a.provision_url or '')
        a.transparent = ask('7/7 鐢ㄩ€忔槑鍔寔锛?y=iptables+mitmproxy锛岄渶 Linux root锛沶=璁╁鎴风璧颁唬鐞? (y/n)', 'y').lower().startswith('y')
        if a.transparent:
            auto, ok = pick_proxy_host(a.client_ip or a.intercept_src)
            hint = auto if ok else (auto + '  鈫?鏈壘鍒颁笌璁惧鍚岀綉娈电殑鏈満鍦板潃锛岃纭')
            a.proxy_host = ask('   DNAT 鐩爣锛氭湰鏈哄湪璁惧缃戞鐨勫湴鍧€锛堝 172.16.0.1锛?, hint)
            if '鈫? in a.proxy_host:
                a.proxy_host = a.proxy_host.split('鈫?)[0].strip()
    else:
        a.certs_dir = ask('5/7 鍙栬瘉璇佷功鐩綍', a.certs_dir)
        a.label = ask('6/7 璇佹嵁鏍囩锛堝 AuthMech-04锛?, a.label)
        a.png = ask('7/7 鏄惁娓叉煋 PNG锛堥渶 Pillow锛?y/n)', 'y').lower().startswith('y')
    if a.mode == 'cloud':
        a.certs_dir = ask('   鍙栬瘉璇佷功鐩綍', a.certs_dir)
        a.label = ask('   璇佹嵁鏍囩锛堝 AuthMech-04锛?, a.label)
        a.png = ask('   鏄惁娓叉煋 PNG锛堥渶 Pillow锛?y/n)', 'y').lower().startswith('y')
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
        print('[error] 娌¤兘浠?%s:%d 鎶撳埌璇佷功锛堢洰鏍囦笉鍙揪鎴栦笉鏄?TLS锛? % (a.target, a.port))
        return None
    path = os.path.join(a.certs_dir, 'device.pem')
    with open(path, 'w', encoding='ascii') as fh:
        fh.write(blocks[0] + '\n')
    rc, info = run([OPENSSL, 'x509', '-in', path, '-noout', '-subject', '-issuer', '-dates', '-fingerprint', '-sha256'])
    with open(os.path.join(a.certs_dir, 'device.pem.info.txt'), 'w', encoding='utf-8') as fh:
        fh.write('fetched from %s:%d (SNI %s)\n' % (a.target, a.port, a.sni) + info)
    print('[anchor] 宸茶嚜鍔ㄦ姄鍙栬澶囪瘉涔?-> %s' % path)
    for line in info.splitlines():
        print('         ' + line.strip())
    return path


# ---------------------------------------------------------------- 涓绘祦绋?def build_parser():
    ap = argparse.ArgumentParser(description='閫氱敤 TLS/璇佷功绫诲彇璇佽剼鏈?)
    ap.add_argument('--target', help='琚祴璁惧鍦板潃锛堝彲鍚?:绔彛锛?)
    ap.add_argument('--sni', default=None, help='TLS SNI锛岄粯璁ゅ彇 target')
    ap.add_argument('--anchor', default='auto', help='淇′换閿氳瘉涔︼紱auto=鑷姩浠庣洰鏍囨姄鍙栬澶囪瘉涔?)
    ap.add_argument('--no-ask', action='store_true', help='涓嶄氦浜掞紝缂哄弬鐩存帴鎶ラ敊锛圕I/鑴氭湰鐢級')
    ap.add_argument('--ask', action='store_true', help='寮哄埗璧颁氦浜掑悜瀵硷紙鍗充娇鏃?TTY锛?)
    ap.add_argument('--skip-selftest', action='store_true', help='璺宠繃寮€璺戝墠鐨勮嚜妫€')
    ap.add_argument('--regen-certs', action='store_true', help='寮哄埗閲嶆柊鐢熸垚鍙栬瘉璇佷功')
    ap.add_argument('--certs-dir', default='tls-evidence-certs', help='鏇挎崲/杩囨湡璇佷功鐩綍')
    ap.add_argument('--out', default=None, help='鍙栬瘉杈撳嚭鐩綍')
    ap.add_argument('--label', default='TLS', help='璇佹嵁鏂囦欢鍚嶅墠缂€锛屽 AuthMech-04')
    ap.add_argument('--png', action='store_true', help='鍚屾椂娓叉煋 PNG锛堥渶 Pillow锛?)
    ap.add_argument('--manage-mitm', action='store_true', help='鐢辫剼鏈捣鍋?mitmdump锛堥粯璁よ嚜鍔ㄦ帰娴嬶級')
    ap.add_argument('--proxy', default='', help='鐢ㄥ凡瀛樺湪鐨?mitmproxy锛屽舰濡?127.0.0.1:8084')
    ap.add_argument('--mitm-port', type=int, default=0, help='mitmdump 鍥哄畾绔彛')
    ap.add_argument('--pause', action='store_true', help='浜哄伐瀹㈡埛绔ā寮忥細璧峰ソ mitmproxy 鍚庡仠浣忕瓑鎿嶄綔')
    ap.add_argument('--cases', default='auto', help='auto 鎴栭€楀彿鍒嗛殧锛歜aseline,substituted,expired,clientcert')
    ap.add_argument('--gen-certs', action='store_true', help='鍙敓鎴愬彇璇佺敤璇佷功鍚庨€€鍑?)
    ap.add_argument('--cn', default=None, help='鐢熸垚璇佷功鐢ㄧ殑 CN锛堥粯璁や粠 --anchor 鎻愬彇锛?)
    ap.add_argument('--selftest', action='store_true', help='鏈満 s_server 鑷锛屼笉杩炵洰鏍?)
    ap.add_argument('--config', default=None, help='浠?JSON 杞藉叆鍙傛暟锛堝懡浠よ浼樺厛锛?)
    ap.add_argument('--save-config', default=None, help='鎶婃湰娆″弬鏁板瓨鎴?JSON')
    ap.add_argument('--mode', choices=['auto', 'direct', 'cloud'], default='auto',
                    help='auto=鎸夊弬鏁版帹鏂紱direct=璁惧鑷寔璇佷功锛堢洿杩?DUT锛夛紱cloud=浜戞湇鍔″櫒涓嬪彂璇佷功锛堝姭鎸佷簯绔笅鍙戦€氶亾锛?)
    ap.add_argument('--client-ip', default=None, help='鍙戣捣瀹㈡埛绔?IP锛堣澶?涓婁綅鏈猴級锛岀瓑浠蜂簬 --intercept-src')
    ap.add_argument('--transparent', action='store_true', help='mitmproxy 閫忔槑妯″紡 + iptables DNAT 鍔寔锛圠inux锛涘弬鑰?mitm.py 骞朵慨姝ｅ叾 bug锛?)
    ap.add_argument('--intercept', action='append', default=[], help='閫忔槑鍔寔鐩爣 host:port锛屽彲澶氭锛堝浜戜笅鍙戞湇鍔″櫒锛?)
    ap.add_argument('--intercept-src', default=None, help='鍙姭鎸佹潵鑷婧?IP 鐨勬祦閲忥紙璁惧/涓婁綅鏈?IP锛?)
    ap.add_argument('--proxy-host', default=None, help='DNAT 鐩殑鍦板潃锛堣窇 mitmproxy 鐨勬湰鏈?IP锛夛紝榛樿鑷姩鎺㈡祴骞舵寜璁惧鍚岀綉娈靛尮閰?)
    ap.add_argument('--proxy-local-port', type=int, default=0, help='閫忔槑妯″紡涓嬪彟寮€鐨勫父瑙勪唬鐞嗗彛锛堣剼鏈嚜甯﹀鎴风鐢ㄥ畠鍋氭鏌ワ級锛岄粯璁?閫忔槑鍙?1')
    ap.add_argument('--rules-only', action='store_true', help='鍙墦鍗?iptables 瑙勫垯涓嶇湡姝ｆ墽琛岋紙dry-run锛?)
    ap.add_argument('--provision-cert', default=None, help='浜戜笅鍙戝満鏅細鎶婂搷搴旈噷鐨勮瘉涔︽潗鏂欐浛鎹㈡垚璇?PEM')
    ap.add_argument('--provision-url', default=None, help='浜戜笅鍙戞帴鍙?URL锛堣嚜鍔ㄥ彇涓€娆″苟鏍￠獙鏇挎崲鏄惁鐢熸晥锛?)
    ap.add_argument('--provision-match', default=None, help='浜戜笅鍙戞浛鎹㈢殑 URL 鍖归厤姝ｅ垯锛堥粯璁?cert|pki|pem|provision|enroll 绛夛級')
    ap.add_argument('--compare', nargs='*', default=None, help='璇佷功姣斿妯″紡锛歨ost:port [host:port ...]锛圱EST D 璇佹嵁锛?)
    ap.add_argument('--serve-cert', action='store_true', help='鐢ㄦ湰鏈?openssl s_server 鍑虹ず --provision-cert锛屼緵瀹㈡埛绔寚鍒版湰鏈哄仛涓嬪彂瀹為獙')
    ap.add_argument('--no-capture', action='store_true', help='--live 鏃朵笉鎶撹澶囦晶 pcap锛堥粯璁ゆ姄锛?)
    ap.add_argument('--no-kick', action='store_true', help='--live 鏃朵笉涓诲姩韪㈡帀璁惧涓庝簯绔凡寤虹珛鐨勯暱杩炴帴锛堥粯璁よ涪锛氶暱杩炴帴涓嶄細鑷繁閲嶈繛锛屼笉韪㈠氨鎶撲笉鍒版彙鎵嬶級')
    ap.add_argument('--capture-if', default=None, help='璁惧渚ф姄鍖呯綉鍗★紙榛樿鑷姩閫変笌璁惧鍚岀綉娈电殑閭ｅ紶锛涘缃戝崱涓棿鐩掍笂涓嶈鐢?any锛?)
    ap.add_argument('--baseline-live', nargs='?', const=90, type=int, default=None,
                    help='鐪熷疄璁惧 baseline 绐楀彛锛氳涪鎺夐暱杩炴帴鍚庤璁惧涓庣湡鏈嶅姟鍣ㄩ噸鏂版彙鎵?N 绉掞紙榛樿 90锛夛紝璇佹嵁=ServerHello+Certificate+搴旂敤鏁版嵁锛圱EST B锛?)
    ap.add_argument('--mitm-insecure', action='store_true', help='mitmproxy 涓嶆牎楠屼笂娓歌瘉涔︼紙cloud 绉佹湁 PKI 鍦烘櫙璁╁姭鎸佷細璇濊兘璧板畬锛?)
    ap.add_argument('--live', nargs='?', const=120, type=int, default=None, help='瀹炴祴绐楀彛锛氳捣濂藉姭鎸佸悗鍋滀綇 N 绉掞紙榛樿 120锛夛紝鏈熼棿鍦ㄨ澶囦笂瑙﹀彂娉ㄥ唽/婵€娲伙紝鑷姩鍒ゅ畾鏄惁琚嫆锛圱EST A/C 鐪熻瘉鎹級')
    ap.add_argument('--timeout', type=int, default=60)
    return ap


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if not sys.stdin.isatty():
            sys.stdin.reconfigure(encoding='utf-8', errors='replace')   # 绠￠亾杈撳叆缁熶竴鎸?UTF-8 瑙?    except Exception:
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

    # ---- 鍙墦鍗?iptables 瑙勫垯锛坉ry-run锛屼究浜庡厛鍦ㄨ澶囦笂鏍稿锛?---
    if (a.transparent or a.rules_only) and a.intercept:
        # DNAT 鐩爣蹇呴』鍏堟寜鈥滀笌璁惧鍚岀綉娈碘€濆畾浣嶏紝鍚﹀垯 dry-run 浼氬嵃鍑洪粯璁よ矾鐢卞湴鍧€锛堝 192.168.2.106锛夛紝
        # 鍦ㄨ娴嬭澶囩綉娈甸噷鏍规湰涓嶉€?鈥斺€?杩欐鏄渶瀹规槗韪╃殑鍧戯紙搴斾负 172.16.0.1锛夈€?        a.proxy_host, _ph = pick_proxy_host(a.intercept_src or a.client_ip, a.proxy_host)
    if a.rules_only:
        cmds = intercept_cmds(a, '-A')
        if not cmds:
            print('[error] --rules-only 闇€瑕?--intercept host:port锛堝彲澶氭锛?)
            return 2
        print('[rules] 灏嗘墽琛岀殑 iptables 瑙勫垯锛圖NAT 鍒?mitmproxy 绔彛 %d锛夛細' % (a.mitm_port or 8084))
        for cmd in cmds:
            print('  ' + ' '.join(cmd))
        print('[rules] 鍒犻櫎鏃舵妸 -A 鎹㈡垚 -D銆佸叾浣欏弬鏁板畬鍏ㄧ浉鍚岋紙鏈伐鍏蜂細鑷姩鎴愬澧炲垹锛?)
        return 0

    # ---- 璇佷功姣斿妯″紡锛圱EST D锛氬叾浠栧疄浣撶殑绉侀挜/璇佷功鏄惁鍙敤锛?---
    if a.compare is not None:
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        a.out = a.out or os.path.join('evidence', '%s_%s' % (a.label, stamp))
        os.makedirs(a.out, exist_ok=True)
        targets = list(a.compare)
        if not targets and a.target:
            targets = [a.target]
        if len(targets) < 2:
            print('[error] --compare 鑷冲皯缁欎袱涓?host:port锛堝 --compare 192.0.2.10:443 192.0.2.11:443锛?)
            return 2
        c = case_compare(a, targets)
        save_case(a, c)
        print('\n'.join(c['transcript']))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else 1

    # ---- 鏈満鍑虹ず琚浛鎹㈢殑璇佷功锛堜簯涓嬪彂/OTA 瀹為獙鐨勬湇鍔＄鏇胯韩锛?---
    if a.serve_cert:
        cert = resolve_cert_arg(a, a.provision_cert)
        if not cert:
            print('[serve] --serve-cert 闇€瑕?--provision-cert 鎸囧畾 cert+key 鍚堜竴鐨?PEM锛堝彲鐢ㄥ埆鍚嶈涓婏級')
            return 2
        port = a.mitm_port or 8443
        print('[serve] openssl s_server 鍦?0.0.0.0:%d 鍑虹ず %s锛圕trl+C 缁撴潫锛? % (port, cert))
        print('[serve] 璁╄澶?涓婁綅鏈烘妸涓嬪彂鍦板潃鎸囧埌鏈満璇ョ鍙ｏ紝鎴栫敤 --transparent 鎶婂畠閲嶅畾鍚戣繃鏉?)
        return subprocess.call(['openssl', 's_server', '-accept', str(port), '-cert', cert, '-key', cert, '-www'])

    if a.ask or (not a.no_ask and not a.target and sys.stdin.isatty()):
        a = wizard(a)
    if not a.target:
        print('[error] 闇€瑕?--target锛堟垨鍘绘帀 --no-ask 鐢ㄥ悜瀵间氦浜掞級')
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
            print('[warn] 娌¤兘鑷姩鎶撳彇淇′换閿?鈫?baseline 鐢ㄤ緥璺宠繃锛堜簯涓嬪彂鍦烘櫙甯歌锛岀户缁仛鏇挎崲/涓嬪彂/姣斿鐢ㄤ緥锛?)
    else:
        anchor = resolve_path([a.anchor, os.path.join(a.certs_dir, a.anchor), os.path.join(os.getcwd(), a.anchor)])
        if not anchor:
            print('[error] 鎵句笉鍒颁俊浠婚敋 %s' % a.anchor)
            return 2
        a.anchor = anchor
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    a.out = a.out or os.path.join('evidence', '%s_%s' % (a.label, stamp))
    os.makedirs(a.out, exist_ok=True)
    try:
        socket.create_connection((a.target, a.port), 5).close()
    except OSError as exc:
        if a.mode == 'cloud':
            print('[warn] 杩炰笉涓?%s:%d (%s)锛歜aseline 璺宠繃锛屾浛鎹?涓嬪彂鐢ㄤ緥浠嶅彲鍋? % (a.target, a.port, exc))
        else:
            print('[error] 杩炰笉涓?%s:%d (%s)' % (a.target, a.port, exc))
            print('        鑻ヨ繖鏄€屼簯鏈嶅姟鍣ㄤ笅鍙戣瘉涔︺€嶇殑椤圭洰锛氱敤 --mode cloud锛坱arget 濉簯鏈嶅姟鍦板潃锛夛紝鎴栧悜瀵奸噷閫夊満鏅?2')
            return 2
    if a.provision_cert:
        path = write_provision_addon(a)
        if not path:
            return 2
        a.provision_addon = path
    need_gen = a.regen_certs or any(not os.path.exists(os.path.join(a.certs_dir, n))
                                   for n in ('substituted.pem', 'expired.pem', 'wrongcn.pem'))
    if need_gen:
        print('[1/3] 鐢熸垚鍙栬瘉璇佷功 ...')
        gen_certs(a)
    if not a.skip_selftest:
        print('[2/3] 鑷鍒ゅ畾閫昏緫 ...')
        rc_st = selftest(a)
        if rc_st != 0:
            print('[error] 鑷澶辫触锛氬彇璇佸垽瀹氶€昏緫涓嶅彲淇★紝鍏堟帓鏌ュ啀璺戯紙--skip-selftest 鍙烦杩囷級')
            return rc_st
    if a.baseline_live is not None:
        print('[baseline] 鐪熷疄璁惧 baseline锛?d 绉掔獥鍙ｅ唴璁╄澶囦笌鐪熸湇鍔″櫒閲嶆柊鎻℃墜锛堜笉鍋氫换浣曞姭鎸侊級...' % a.baseline_live)
        c = case_baseline_live(a, a.baseline_live)
        save_case(a, c)
        print('')
        print('\n'.join(c['transcript']))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else 1

    if a.live is not None:
        print('[live] 璧峰姭鎸佸苟鍦?%d 绉掔獥鍙ｅ唴瑙傚療鐪熷疄璁惧锛堣澶囬渶鎶婅鍩熷悕璺敱鍒版湰鏈猴級...' % a.live)
        c = case_live(a, a.live)
        save_case(a, c)
        print('')
        print('\n'.join(c['transcript'][:8]))
        print('[out] ' + os.path.abspath(a.out))
        return 0 if c['result'] == 'pass' else (2 if c['result'] == 'skip' else 1)

    print('[3/3] 閲囬泦璇佹嵁 ...')
    if a.transparent:
        a.proxy_host, matched = pick_proxy_host(a.intercept_src or a.client_ip, a.proxy_host)
        print('[info] DNAT 鐩爣鏈満鍦板潃 = %s %s' % (a.proxy_host, '(涓庤澶囧悓缃戞)' if matched else '(鏈尮閰嶅埌璁惧缃戞锛屽€欓€? %s锛涘彲鐢?--proxy-host 鎸囧畾)' % ', '.join('%s/%d' % c for c in local_ipv4_list())))
    if a.intercept_src and not a.client_ip:
        a.client_ip = a.intercept_src
    if a.mode == 'cloud' and a.transparent and not a.intercept:
        a.intercept = ['%s:%d' % (a.target, a.port)]
    have_mitm = bool(shutil.which(MITMDUMP)) or bool(a.proxy)
    if not have_mitm:
        print('[hint] 鏈娴嬪埌 mitmdump锛氳鏇挎崲/杩囨湡璇佷功鐢ㄤ緥灏嗚烦杩囷紱瑁呭ソ鍚庨噸璺戞湰鑴氭湰鍗冲彲锛圞ali: sudo apt install -y mitmproxy锛?)
    print('[info] target=%s:%d sni=%s anchor=%s' % (a.target, a.port, a.sni, a.anchor))
    print('[info] mitmproxy=%s output=%s' % ('yes' if have_mitm else 'no (璺宠繃浼€犺瘉涔︾敤渚?', a.out))

    selected = a.cases
    results = []
    if a.anchor:
        quiet = base_cmd(a) + ['-showcerts']
        rc, out = run(quiet)
        need_cc, ca_names = probe_client_cert(out)
        print('[info] 鏈嶅姟绔槸鍚﹁姹傚鎴风璇佷功: %s%s' % (need_cc, (' (CA: %s)' % ', '.join(ca_names[:2])) if ca_names else ''))
    else:
        need_cc, ca_names = None, []
        print('[info] 鏃犱俊浠婚敋锛氳烦杩?baseline 涓庡鎴风璇佷功鎺㈡祴')

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
                 'cmd': [], 'transcript': ['mitmproxy 鏈畨瑁咃細瀹夎鍚庨噸璺戯紙Kali: apt install -y mitmproxy锛?], 'mitm_log': ''}
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
                 'transcript': ['mitmproxy 鏈畨瑁咃細瀹夎鍚庨噸璺戯紙Kali: apt install -y mitmproxy锛?], 'mitm_log': ''}
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
    lines += ['', '娉細expect=ok 鐨勭敤渚嬪繀椤?Verify return code: 0 (ok)锛沞xpect=reject 鐨勭敤渚嬪繀椤绘彙鎵嬭鎷?,
              '    锛堝鎴风 verify 澶辫触 / mitmproxy 璁板綍 does not trust the proxy certificate锛夈€?,
              '    result=fail 琛ㄧず瀹為檯琛屼负涓庡０鏄庝笉绗?鈥斺€?涓嶈兘鍐欐垚 PASS銆?]
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
