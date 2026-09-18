#!/usr/bin/env python3
import readline
import subprocess

浠嬬粛 = """----涓棿浜烘敾鍑昏嚜鍔ㄨ剼鏈?iptables+mitmproxy)----
- 鏍规嵁杈撳叆鐨処P鍦板潃涓庣鍙ｈ嚜鍔ㄦ坊鍔爄ptables瑙勫垯
- 鑷姩鍚姩mitmproxy
- 鏀寔澶氫釜鏈嶅姟鍣ㄥ煙鍚嶆垨ip
- 閫€鍑簃itmproxy鍚庤嚜鍔ㄥ垹闄ptables瑙勫垯
"""

print(浠嬬粛)

src_ip = input("婧愬湴鍧€(璁惧ip): ")
src_port = input("婧愮鍙?鍙€夛紝鐣欑┖鍒欎笉鎸囧畾): ").strip()
dst_ips = (
    input("鐩殑鍦板潃(鏈嶅姟鍣ㄥ湴鍧€,鍙互鏄煙鍚? 澶氫釜浣跨敤閫楀彿鍒嗛殧): ").strip().split(",")
)
dst_port = input("鐩殑绔彛(鍙€夛紝鐣欑┖鍒欎笉鎸囧畾): ").strip()

for ip in dst_ips:
    ip = ip.strip()
    # 鏋勯€爄ptables鍛戒护
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
    print(f"娣诲姞iptables瑙勫垯: {ip}")

    try:
        subprocess.run(iptables_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"娣诲姞iptables瑙勫垯澶辫触: {e}")
        exit(1)

    # 鏄剧ず褰撳墠瑙勫垯
    subprocess.run(["sudo", "iptables", "-t", "nat", "-L", "--line-numbers"])

    input("鎸夊洖杞︾户缁紝楠岃瘉瀹屾瘯鍚庡皢鍒犻櫎瑙勫垯...")

    # 鍚姩mitmproxy
    mitmproxy_cmd = [
        "mitmdump",
        "--rawtcp",
        "-p",
        "8084",
        "--mode",
        "transparent",
        "--showhost",
    ]
    print("鍚姩mitmproxy锛屾寜Ctrl+C閫€鍑?..")
    try:
        subprocess.call(mitmproxy_cmd)
    except KeyboardInterrupt:
        print("mitmproxy宸查€€鍑猴紝鍑嗗鍒犻櫎iptables瑙勫垯銆?)
    finally:
    # 鍒犻櫎鍒氭墠娣诲姞鐨勮鍒?        iptables_del_cmd = [
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
            print(f"鍒犻櫎iptables瑙勫垯澶辫触: {e}")
            exit(1)
        print(f"宸插垹闄ptables瑙勫垯: {ip}\n")
