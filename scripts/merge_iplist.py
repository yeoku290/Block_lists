#!/usr/bin/env python3
import ipaddress
import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCES = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/bruteforce.txt",
    "https://raw.githubusercontent.com/gazpitchy92/ip-blocklist/refs/heads/main/list/blacklist.txt",
    # 繼續新增...
]

OUTPUT_IP = Path("ip_blocklist.txt")
DOMAIN_WHITELIST_FILE = Path("whitelist.txt")  # 你原本用來放 Domain 的檔案
IP_WHITELIST_FILE = Path("ip_whitelist.txt")  # 新增專門放 IP / CIDR 的檔案


def load_ip_whitelist():
  """讀取 ip_whitelist.txt，支援單一 IP 與 CIDR 網段"""
  if not IP_WHITELIST_FILE.exists():
    return []

  networks = []
  for line in IP_WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if (
        not line
        or line.startswith("#")
        or line.startswith(";")
        or line.startswith("!")
    ):
      continue

    token = line.split()[0].strip('"\'')
    try:
      net = ipaddress.ip_network(token, strict=False)
      networks.append(net)
    except ValueError:
      print(f"  ⚠️ 無效的 IP 白名單格式（已略過）：{token}")
  return networks


def load_domain_whitelist():
  """讀取 whitelist.txt 的網域，並自動解析成 IP 集合"""
  if not DOMAIN_WHITELIST_FILE.exists():
    return set()

  domains = set()
  for line in DOMAIN_WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if (
        not line
        or line.startswith("#")
        or line.startswith(";")
        or line.startswith("!")
    ):
      continue

    token = line.split()[0].strip('"\'')
    # 如果裡面不小心直接寫了 IP，也相容處理
    try:
      ipaddress.ip_address(token)
      continue  # 略過，留給 ip_whitelist.txt 處理
    except ValueError:
      domains.add(token.lower())

  resolved_ips = set()
  for domain in domains:
    try:
      ip_infos = socket.getaddrinfo(domain, None)
      for info in ip_infos:
        ip_str = info[4][0]
        resolved_ips.add(ipaddress.ip_address(ip_str))
      print(f"  ✅ 成功解析白名單網域: {domain}")
    except socket.gaierror:
      print(f"  ⚠️ 無法解析網域（可能已失效或不存在）: {domain}")

  return resolved_ips


def is_whitelisted(ip_str: str, ip_networks, resolved_ips) -> bool:
  """檢查該 IP 是否在 IP 網段內，或是在網域解析出的 IP 內"""
  try:
    ip_obj = ipaddress.ip_address(ip_str)
  except ValueError:
    return False

  # 1. 檢查是否在網域解析出的 IP 清單中
  if ip_obj in resolved_ips:
    return True

  # 2. 檢查是否落在 IP/CIDR 白名單網段內
  for net in ip_networks:
    if ip_obj in net:
      return True

  return False


def parse_line(line: str) -> str | None:
  line = line.strip()
  if (
      not line
      or line.startswith("#")
      or line.startswith(";")
      or line.startswith("!")
  ):
    return None

  token = line.split()[0].strip('"\'')

  if "/" in token:
    return None

  try:
    return str(ipaddress.ip_address(token))
  except ValueError:
    return None


def fetch_source(url: str) -> list[str]:
  print(f"  下載中：{url}")
  try:
    req = urllib.request.Request(
        url, headers={"User-Agent": "iplist-merger/1.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
      return resp.read().decode("utf-8", errors="ignore").splitlines()
  except Exception as e:
    print(f"  ⚠️  無法取得 {url}：{e}")
    return []


def main():
  print("=" * 55)
  print("  IP Blocklist Merger")
  print("=" * 55)

  # 載入雙軌白名單
  ip_networks = load_ip_whitelist()
  resolved_ips = load_domain_whitelist()
  print(
      f"  📝 已載入 IP/CIDR 規則：{len(ip_networks)} 筆 | 網域解析 IP："
      f" {len(resolved_ips)} 筆"
  )

  all_ips: set[str] = set()
  source_stats = []
  total_excluded = 0

  for url in SOURCES:
    before = len(all_ips)
    source_excluded = 0
    for line in fetch_source(url):
      ip = parse_line(line)
      if ip:
        if is_whitelisted(ip, ip_networks, resolved_ips):
          total_excluded += 1
          source_excluded += 1
          continue
        all_ips.add(ip)
    added = len(all_ips) - before
    source_stats.append((url, added))
    print(f"     新增：{added:>6} 筆 (白名單排除：{source_excluded} 筆)")

  sorted_ips = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))
  now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

  header = (
      f"# IP Blocklist\n"
      f"# 自動合併自 {len(SOURCES)} 個來源（已過濾白名單）\n"
      f"# 最後更新：{now}\n"
      f"# 總計筆數：{len(sorted_ips):,}\n#\n"
      f"# 來源：\n"
      + "".join(f"#   {u}\n" for u in SOURCES)
      + "#\n"
  )

  OUTPUT_IP.write_text(header + "\n".join(sorted_ips) + "\n", encoding="utf-8")

  print()
  print("─" * 55)
  print(
      f"  ✅ 完成！共 {len(sorted_ips):,} 個唯一 IP (累計白名單排除"
      f" {total_excluded:,} 筆)"
  )
  print("─" * 55)
  print("\n來源統計：")
  for url, added in source_stats:
    print(f"  {url.split('/')[-1]:<45} 新增：{added:>6} 筆")


if __name__ == "__main__":
  main()
