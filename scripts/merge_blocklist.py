#!/usr/bin/env python3
import re
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
    # 在這裡繼續新增你要的來源 URL
]

OUTPUT_FILE = Path("blocklist.txt")

DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)

def is_valid_domain(s):
    return bool(DOMAIN_RE.match(s)) and len(s) <= 253

def parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('!'):
        return None
    line = re.split(r'\s*#.*$', line)[0].strip()
    line = re.split(r'\s*!.*$', line)[0].strip()
    if not line:
        return None
    adblock_match = re.match(r'^(?:@@)?\|\|([^\^/\s]+)\^?(?:\$.*)?$', line)
    if adblock_match:
        domain = adblock_match.group(1).lower().strip('.')
        return domain if is_valid_domain(domain) else None
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(\S+)', line)
    if hosts_match:
        domain = hosts_match.group(1).lower().strip('.')
        if domain in ('localhost', 'broadcasthost', 'local', '0.0.0.0', '::1'):
            return None
        return domain if is_valid_domain(domain) else None
    candidate = line.split()[0].lower().strip('.').lstrip('@|').rstrip('^')
    return candidate if is_valid_domain(candidate) else None

def fetch_source(url):
    print(f"  下載中：{url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'blocklist-merger/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"  ⚠️  無法取得 {url}：{e}")
        return []

def main():
    all_domains = set()
    source_stats = []

    for url in SOURCES:
        lines = fetch_source(url)
        before = len(all_domains)
        parsed = 0
        for line in lines:
            domain = parse_line(line)
            if domain:
                all_domains.add(domain)
                parsed += 1
        added = len(all_domains) - before
        source_stats.append((url, parsed, added))
        print(f"     解析：{parsed:>6} 筆 | 新增：{added:>6} 筆（去重後）")

    sorted_domains = sorted(all_domains)
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    header = (
        f"# Domain Blocklist\n"
        f"# 自動合併自 {len(SOURCES)} 個來源\n"
        f"# 最後更新：{now}\n"
        f"# 總計網域數：{len(sorted_domains):,}\n#\n"
        f"# 來源：\n"
        + "".join(f"#   {u}\n" for u in SOURCES)
        + "#\n"
    )

    OUTPUT_FILE.write_text(header + '\n'.join(sorted_domains) + '\n', encoding='utf-8')

    print(f"\n✅ 完成！共 {len(sorted_domains):,} 個唯一網域")
    for url, parsed, added in source_stats:
        print(f"  {url.split('/')[-1]:<40} {parsed:>6} 筆 / 新增 {added:>6} 筆")

if __name__ == '__main__':
    main()
