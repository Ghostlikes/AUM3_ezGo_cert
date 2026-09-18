# TLS / 证书类取证工具集（TDS 用）

面向 **EN 18031-1 / IEC 62443-4-2 TDS** 证据采集的两个脚本：把「证书 / TLS 类测试项」做成一条命令可复现、可复核、可留档的证据包。

| 脚本 | 用途 |
|---|---|
| `aum3_cert_tests.py` |  **[AU.AUM-3.CertificatePrivateKey]** 条款驱动取证：按标准原文四个 bullet 生成错误证书、逐条对被测设备实施中间人并判定（含条件项自动判 N/A） |
| `tls_evidence.py` | 通用 TLS/证书取证：信任锚、基线握手、被替换证书、过期证书、客户端证书负向用例、证书唯一性比对 |
| `xlsx_dump.py` | 只读导出 xlsx 单元格（核对 E-Info 表格时用） |
| `mitm.py` | 早期的 iptables+mitmproxy 透明劫持小脚本（已被上面两个脚本吸收，保留作参考） |

## 依赖

- 必须：`openssl`（1.1.1+ / 3.x）
- 出示假证书：`mitmdump`（`apt install -y mitmproxy`）
- 设备侧证据（强烈建议）：`tcpdump` + `tshark`

## 快速开始

```bash
# AUM-3：先看覆盖清单（哪几条要跑、为什么）
python3 aum3_cert_tests.py --list

# 只生成证书 + 离线自检（不碰设备）
python3 aum3_cert_tests.py --target cloud.example.com:18888 --gen-only --selftest

# 中间盒上跑全套（透明劫持 + 踢长连接 + 设备侧抓包 + 判定）
sudo python3 aum3_cert_tests.py --target cloud.example.com:18888 --src 172.16.0.4 \
  --proxy-host 172.16.0.1 --intercept cloud.example.com:18888 --mitm-insecure --live 60

# 通用 TLS 证据
python3 tls_evidence.py --target 192.0.2.10 --sni device.local --anchor certs/device.pem --png
```

无参数运行 `aum3_cert_tests.py` 会进交互向导（6 问，回车用默认值）。

## 判据口径（重要）

| 结果 | 含义 |
|---|---|
| `pass` | 被测设备拒绝，且拒绝原因正是该条款要检的属性（如过期证书给出 `certificate_expired`） |
| `pass*` | 设备拒绝，但告警原因落在**证书链/信任锚**检查上（`unknown_ca`）——只证明设备会校验证书，不能单独证明该属性；要单测需先把实验室 CA 预置进设备再 `--lab-ca-provisioned` 复跑 |
| `fail` | 设备完成了握手（接受了错误证书）→ 不符合，不能写 PASS |
| `skip` | 窗口内没有观察到握手（设备重连退避等）→ 重跑该窗口，不冒充 PASS |
| `n/a` | 条件项不成立并写出理由（如重放：机密性已由 TLS 保护） |

退出码：全部 `pass/pass*` → 0；出现 `fail` → 1；出现 `skip/error` → 2。

## 中间盒/透明劫持的四个硬坑（脚本已处理）

1. **DNAT 只对新建连接生效**：MQTT 这类长连接空闲时可静默数分钟，不先踢掉老连接，窗口内根本抓不到握手 → 脚本用 `FORWARD REJECT --reject-with tcp-reset` 踢（设备重连的 SYN 在 PREROUTING 就被 DNAT 走，不受该规则影响）。
2. **DNAT 目的地址必须是设备同网段的本机地址**（如设备在 172.16.0.0/24，就要写 172.16.0.1，而不是默认路由那个地址）。
3. **`--intercept` 里的域名先解析成 IP 再下发规则**：域名在 `-A`/`-D` 两次各自解析容易对不上，证据里也看不出打到哪个地址。
4. **判定按"连接"而不是按整段 pcap 统计**：只有"同一条连接既被出示了我们的证书、又出现设备应用数据"才算接受，避免把被踢断前的老连接误判成认证成功。

另：部分发行版的 `tshark` 按路径打开 pcap 会被拒（连 root 都报权限错误），脚本统一用 `tshark -r -` 从 stdin 读。

## 产物

每次运行输出到 `<out>/`：

- `summary.md`：结论表 + 逐条证据（含可直接粘贴的 TDS 结论句）
- `report.json`：机器可读结果
- `certs_summary.txt`：所用错误证书的 subject/issuer/序列号/有效期/指纹
- `device_*.pcap`：设备侧原始抓包

## 用途声明

仅用于**已获授权**的产品安全测试与合规取证。请勿用于未授权目标。
