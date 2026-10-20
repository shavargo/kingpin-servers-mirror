# kingpin-servers-mirror

Daily merged Kingpin server address list for launchers and tools.

**Mirror (use this):** https://raw.githubusercontent.com/shavargo/kingpin-servers-mirror/main/servers.txt

## Sources

| Source | How |
|--------|-----|
| `extras.txt` | Always-included addresses (pinned servers) |
| [hambloch.com/kingpin/servers_active.php?gameport=1](https://hambloch.com/kingpin/servers_active.php?gameport=1) | HTTP scrape (M-Browser seed) |
| `master.333networks.com` (+ errorist, newbiesplayground, kingpin.info, …) | Gamespy v0 TCP list on **28900** |
| `master.hambloch.com` / `master.kingpin.info` | Quake II UDP `query` on **27900** (when reachable) |

Addresses are unioned and deduped. Gamespy entries are Kingpin *query* ports; the list also includes **query+10** (standard KP game/connect ports per [kingpin.info ports](https://kingpin.info/?p=ports)).

## Why

Hitting Hambloch on every launcher refresh can look like abuse and get client IPs blocked. One GitHub Action run per day pulls upstream so apps can use a stable raw URL.

## Update schedule

- Cron: daily at 12:17 UTC
- Manual: Actions → **Update servers.txt** → Run workflow

## Local / CI

```bash
python3 scripts/fetch_servers.py
```

## Attribution

Server list data originates from [M. Hambloch](https://hambloch.com/kingpin/), [333networks](https://master.333networks.com/s/kingpin), and other community masters. Unofficial cache — not affiliated with those operators.
