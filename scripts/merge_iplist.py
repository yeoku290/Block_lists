#!/usr/bin/env python3
import ipaddress
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
WHITELIST_FILE = Path(
    "whitelist.txt"
)  # 白名單檔案路徑（支援單一 IP 或 CIDR 網段）


def load_whitelist() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
  """讀取白名單檔案，支援單一 IP 與 CIDR 網段"""
  if not WHITELIST_FILE.exists():
    return []

  networks = []
  for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
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
      # strict=False 允許將單一 IP 或 CIDR 正確解析為網路範圍
      net = ipaddress.ip_network(token, strict=False)
      networks.append(net)
    except ValueError:
      print(f"  ⚠️ 無效的白名單格式（已略過）：{token}")
  return networks


def is_whitelisted(
    ip_str: str, whitelist_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
  """檢查該 IP 是否落在白名單的網段或單一 IP 中"""
  try:
    ip_obj = ipaddress.ip_address(ip_str)
  except ValueError:
    return False

  for net in whitelist_nets:
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

  # CIDR 直接略過（來源清單中的 CIDR，如果你希望保留來源的 CIDR 可以拿掉這行，但你原本腳本有加這行）
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

  # 1. 載入白名單
  whitelist_nets = load_whitelist()
  if whitelist_nets:
    print(f"  📝 已載入白名單規則：{len(whitelist_nets)} 筆")
  else:
    print("  📝 未發現 whitelist.txt 或白名單為空")

  all_ips: set[str] = set()
  source_stats = []
  total_excluded = 0

  for url in SOURCES:
    before = len(all_ips)
    source_excluded = 0
    for line in fetch_source(url):
      ip = parse_line(line)
      if ip:
        # 檢查是否在白名單內
        if is_whitelisted(ip, whitelist_nets):
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
