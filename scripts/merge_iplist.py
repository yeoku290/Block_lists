#!/usr/bin/env python3
import re
import ipaddress
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# ★ 在這裡填入你要匯集的 IP 名單來源 URL
# ─────────────────────────────────────────────
SOURCES = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/bruteforce.txt",
    # 繼續新增...
]

OUTPUT_IP   = Path("ip_blocklist.txt")
OUTPUT_CIDR = Path("cidr_blocklist.txt")

# ─────────────────────────────────────────────
# 解析邏輯
# ─────────────────────────────────────────────

def parse_line(line: str) -> tuple[str, str] | tuple[None, None]:
    """
    回傳 (value, type) 其中 type 是 'ip' 或 'cidr'，無效則回傳 (None, None)
    支援：
      - 純 IP：1.2.3.4
      - CIDR：1.2.3.0/24
      - ipsum 格式：1.2.3.4  5  （IP + 出現次數，取第一欄）
      - 註解行 # ! 開頭 → 忽略
    """
    line = line.strip()
    if not line or line.startswith('#') or line.startswith(';') or line.startswith('!'):
        return None, None

    # 取第一個 token（忽略行尾註解與額外欄位）
    token = line.split()[0]

    # 移除可能夾帶的引號或多餘符號
    token = token.strip('"\'')

    try:
        if '/' in token:
            net = ipaddress.ip_network(token, strict=False)
            return str(net), 'cidr'
        else:
            ip = ipaddress.ip_address(token)
            return str(ip), 'ip'
    except ValueError:
        return None, None


def fetch_source(url: str) -> list[str]:
    print(f"  下載中：{url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'iplist-merger/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"  ⚠️  無法取得 {url}：{e}")
        return []


def make_header(kind: str, count: int, source_count: int) -> str:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    return (
        f"# IP Blocklist ({kind})\n"
        f"# 自動合併自 {source_count} 個來源\n"
        f"# 最後更新：{now}\n"
        f"# 總計筆數：{count:,}\n"
        f"#\n"
        f"# 來源：\n"
        + "".join(f"#   {u}\n" for u in SOURCES)
        + "#\n"
    )


def main():
    print("=" * 55)
    print("  IP Blocklist Merger")
    print("=" * 55)

    all_ips:  set[str] = set()
    all_cidr: set[str] = set()
    source_stats = []

    for url in SOURCES:
        lines = fetch_source(url)
        before_ip   = len(all_ips)
        before_cidr = len(all_cidr)

        for line in lines:
            value, kind = parse_line(line)
            if kind == 'ip':
                all_ips.add(value)
            elif kind == 'cidr':
                all_cidr.add(value)

        added_ip   = len(all_ips)   - before_ip
        added_cidr = len(all_cidr)  - before_cidr
        source_stats.append((url, added_ip, added_cidr))
        print(f"     IP 新增：{added_ip:>6} 筆 | CIDR 新增：{added_cidr:>6} 筆")

    sorted_ips  = sorted(all_ips,  key=lambda x: ipaddress.ip_address(x))
    sorted_cidr = sorted(all_cidr, key=lambda x: ipaddress.ip_network(x, strict=False))

    OUTPUT_IP.write_text(
        make_header('單一 IP', len(sorted_ips), len(SOURCES))
        + '\n'.join(sorted_ips) + '\n',
        encoding='utf-8'
    )
    OUTPUT_CIDR.write_text(
        make_header('CIDR 範圍', len(sorted_cidr), len(SOURCES))
        + '\n'.join(sorted_cidr) + '\n',
        encoding='utf-8'
    )

    print()
    print("─" * 55)
    print(f"  ✅ 完成！單一 IP：{len(sorted_ips):,} 筆 | CIDR：{len(sorted_cidr):,} 筆")
    print(f"  📄 {OUTPUT_IP} / {OUTPUT_CIDR}")
    print("─" * 55)
    print("\n來源統計：")
    for url, a_ip, a_cidr in source_stats:
        short = url.split('/')[-1]
        print(f"  {short:<45} IP:{a_ip:>6}  CIDR:{a_cidr:>6}")


if __name__ == '__main__':
    main()
