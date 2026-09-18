# TLS / 证书类取证工具集（TDS 用）

面向 **EN 18031-1 / IEC 62443-4-2 TDS** 证据采集：把「证书 / TLS 类测试项」做成一条命令可复现、可复核、可留档的证据包。

| 脚本 | 用途 |
|---|---|
| `aum3_cert_tests.py` | **[AU.AUM-3.CertificatePrivateKey]** 条款驱动取证：按标准原文四个 bullet 生成错误证书、逐条执行并判定（含条件项自动判 N/A）；**支持两种拓扑** |
| `tls_evidence.py` | 通用 TLS/证书取证：信任锚、基线握手、被替换证书、过期证书、客户端证书负向用例、证书唯一性比对 |
| `xlsx_dump.py` | 只读导出 xlsx 单元格（核对 E-Info 表格时用） |
| `mitm.py` | 早期的 iptables+mitmproxy 透明劫持脚本（已被上面两个吸收，留作参考） |

## 两种拓扑（脚本启动时先选，或 `--topology` 指定）

| 拓扑 | 谁出示证书 / 谁做校验 | 脚本怎么做 | 用例 |
|---|---|---|---|
| **client**（默认） | DUT 作 TLS **客户端**，校验云端/上位机的证书 | 脚本站在中间：iptables DNAT 透明劫持 + mitmproxy 出示错误证书，看 DUT 是否拒绝 | R1a 错误私钥+受信任身份、R1b 真证书+错误私钥、R2 重放（条件项）、R3a 不受信任链、R3b 过期、R3c 吊销、R4 其他实体 |
| **server** | DUT 作 TLS **服务端**（本地 web TLS 服务出示证书给 web 管理客户端） | 脚本先直连该端口采集证书与 TLS 参数（S0，核对 E-Info 文档），再在本机扮演"该设备"用错误证书起 TLS 服务，看严格校验的客户端是否会被骗过 | S0 证书属性基线、S1 设备证书+攻击者私钥、S2 重放（条件项）、S3a/S3b/S3c/S4 冒用实验 |

```bash
# 交互向导：第 1 问就选拓扑
python3 aum3_cert_tests.py

# client 拓扑（DUT 作客户端，中间盒上跑）
sudo python3 aum3_cert_tests.py --topology client --target cloud.example.com:18888 --src 172.16.0.4 \
     --proxy-host 172.16.0.1 --intercept cloud.example.com:18888 --mitm-insecure --live 60

# server 拓扑（DUT 作服务端，本地 web TLS 服务）
python3 aum3_cert_tests.py --topology server --target 192.0.2.10:443 \
     --expected-cn device.local --expect-tls TLSv1.3

# 先看覆盖清单（不用给目标）
python3 aum3_cert_tests.py --list --topology server
```

> server 拓扑下**不需要** iptables/mitmproxy，也不做中间人：设备本身是证书出示方。因此该拓扑产出的是
> ①设备证书/TLS 参数的合规基线（S0）、②证书**不可被冒用**的验证（S1/S3a/S3b/S3c/S4）。
> 若设备在 web TLS 上**要求客户端证书**（脚本会自动打印探测结果），才存在"设备校验对端证书"的路径。

## 依赖

- 必须：`openssl`（1.1.1+ / 3.x）
- client 拓扑还需：`mitmdump`（`apt install -y mitmproxy`）、`tcpdump` + `tshark`（设备侧证据）

## 判据口径

| 结果 | 含义 |
|---|---|
| `pass` | 与声明一致：client 拓扑=设备拒绝且告警原因正是该条款要检的属性；server 拓扑=证书属性合规 / 该证书无法冒用 |
| `pass*` | （client 拓扑）设备拒绝，但告警原因落在**证书链/信任锚**检查上（`unknown_ca`）——只证明设备会校验证书，不能单独证明该属性；要单测需先把实验室 CA 预置进设备再 `--lab-ca-provisioned` 复跑 |
| `fail` | 不符合：client=设备完成握手（接受了错误证书）；server=证书属性与文档不一致，或错误证书竟被客户端接受 |
| `skip` | 证据不足（窗口内没有握手 / 材料缺失）→ 重跑，不冒充 PASS |
| `n/a` | 条件项不成立并写出理由（如重放：机密性已由 TLS 保护） |

退出码：全部 `pass/pass*` → 0；出现 `fail` → 1；出现 `skip/error` → 2。

## client 拓扑的四个硬坑（脚本已处理）

1. **DNAT 只对新建连接生效**：MQTT 这类长连接空闲时可静默数分钟，不先踢掉老连接，窗口内抓不到握手 → 用 `FORWARD REJECT --reject-with tcp-reset` 踢。
2. **DNAT 目的地址必须是设备同网段的本机地址**（设备在 172.16.0.0/24 就写 172.16.0.1）。
3. **`--intercept` 里的域名先解析成 IP 再下发规则**（域名在 `-A`/`-D` 两次解析容易对不上）。
4. **判定按"连接"统计**：只有"同一条连接既被出示了我们的证书、又出现设备应用数据"才算接受。

起跑前还会检查链路上是否已有别的 mitmproxy/残留 DNAT（两路同时劫持会让证据不可用），有则拒绝起跑，`--force` 可跳过。

## 产物

每次运行输出到 `<out>/`：

- `summary.md`：结论表 + 逐条证据（含可直接粘贴的 TDS 结论句）
- `report.json`：机器可读结果
- `certs_summary.txt`：所用错误证书的 subject/issuer/序列号/有效期/指纹
- `device_cert_facts.txt`（server 拓扑）：设备出示的证书与 TLS 参数、s_client 原文
- `device_*.pcap`（client 拓扑）：设备侧原始抓包

## 用途声明

仅用于**已获授权**的产品安全测试与合规取证。请勿用于未授权目标。
