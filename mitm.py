#!/usr/bin/env python3
import readline
import subprocess

介绍 = """----中间人攻击自动脚本(iptables+mitmproxy)----
- 根据输入的IP地址与端口自动添加iptables规则
- 自动启动mitmproxy
- 支持多个服务器域名或ip
- 退出mitmproxy后自动删除iptables规则
"""

print(介绍)

src_ip = input("源地址(设备ip): ")
src_port = input("源端口(可选，留空则不指定): ").strip()
dst_ips = (
    input("目的地址(服务器地址,可以是域名? 多个使用逗号分隔): ").strip().split(",")
)
dst_port = input("目的端口(可选，留空则不指定): ").strip()

for ip in dst_ips:
    ip = ip.strip()
    # 构造iptables命令
    iptables_cmd = [
        "sudo",
        "iptables",
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-s",
        src_ip,
        "-p",
        "tcp",
        "-d",
        ip,
    ]
    if src_port:
        iptables_cmd += ["--sport", src_port]
    if dst_port:
        iptables_cmd += ["--dport", dst_port]
    iptables_cmd += ["-j", "DNAT", "--to-destination", "172.16.0.1:8084"]
    print(f"添加iptables规则: {ip}")

    try:
        subprocess.run(iptables_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"添加iptables规则失败: {e}")
        exit(1)

    # 显示当前规则
    subprocess.run(["sudo", "iptables", "-t", "nat", "-L", "--line-numbers"])

    input("按回车继续，验证完毕后将删除规则...")

    # 启动mitmproxy
    mitmproxy_cmd = [
        "mitmdump",
        "--rawtcp",
        "-p",
        "8084",
        "--mode",
        "transparent",
        "--showhost",
    ]
    print("启动mitmproxy，按Ctrl+C退出...")
    try:
        subprocess.call(mitmproxy_cmd)
    except KeyboardInterrupt:
        print("mitmproxy已退出，准备删除iptables规则。")
    finally:
    # 删除刚才添加的规则
        iptables_del_cmd = [
            "sudo",
            "iptables",
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-s",
            src_ip,
            "-p",
            "tcp",
            "-d",
            ip,
        ]
        if src_port:
            iptables_del_cmd += ["--sport", src_port]
        if dst_port:
            iptables_del_cmd += ["--dport", dst_port]
        iptables_del_cmd += ["-j", "DNAT", "--to-destination", "192.168.12.1:8084"]
        try:
            subprocess.run(iptables_del_cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"删除iptables规则失败: {e}")
            exit(1)
        print(f"已删除iptables规则: {ip}\n")
