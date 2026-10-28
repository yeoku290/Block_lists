#!/usr/bin/env python3
import re
import ipaddress
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

SOURCES = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/bruteforce.txt",
    "https://raw.githubusercontent.com/gazpitchy92/ip-blocklist/refs/heads/main/list/blacklist.txt",
    # 繼續新增...
]

OUTPUT_IP = Path("ip_blocklist.txt")

def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith('#') or line.startswith(';') or line.startswith('!'):
        return None

    token = line.split()[0].strip('"\'')

    # CIDR 直接略過
    if '/' in token:
        return None

    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None

def fetch_source(url: str) -> list[str]:
    print(f"  下載中：{url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'iplist-merger/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"  ⚠️  無法取得 {url}：{e}")
        return []

def main():
    print("=" * 55)
    print("  IP Blocklist Merger")
    print("=" * 55)

    all_ips: set[str] = set()
    source_stats = []

    for url in SOURCES:
        before = len(all_ips)
        for line in fetch_source(url):
            ip = parse_line(line)
            if ip:
                all_ips.add(ip)
        added = len(all_ips) - before
        source_stats.append((url, added))
        print(f"     新增：{added:>6} 筆")

    sorted_ips = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    header = (
        f"# IP Blocklist\n"
        f"# 自動合併自 {len(SOURCES)} 個來源\n"
        f"# 最後更新：{now}\n"
        f"# 總計筆數：{len(sorted_ips):,}\n#\n"
        f"# 來源：\n"
        + "".join(f"#   {u}\n" for u in SOURCES)
        + "#\n"
    )

    OUTPUT_IP.write_text(header + '\n'.join(sorted_ips) + '\n', encoding='utf-8')

    print()
    print("─" * 55)
    print(f"  ✅ 完成！共 {len(sorted_ips):,} 個唯一 IP")
    print("─" * 55)
    print("\n來源統計：")
    for url, added in source_stats:
        print(f"  {url.split('/')[-1]:<45} 新增：{added:>6} 筆")

if __name__ == '__main__':
    main()
