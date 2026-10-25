# kingpin-servers-mirror

Daily merged Kingpin server address list for launchers and tools.

**Mirror (use this):** https://raw.githubusercontent.com/shavargo/kingpin-servers-mirror/main/servers.txt

Addresses are **game (connect) ports** — what you pass to `+connect`. Live name/map/players come from UDP `status` (usually on **gameport − 10**, the query port).

## Sources

| Source | How |
|--------|-----|
| Previous `servers.txt` | Always merged back in (cache; no TTL) so master outages do not drop known IPs |
| `master.hambloch.com`, `master.shavargo.com` | Quake II UDP `query` on **27900** (Kingpin-native master software) |
| `master.errorist.eu`, `master.333networks.com`, `master.frag-net.com` | GameSpy v0 TCP list on **28900** (query ports → stored as query+10) |

Addresses are unioned and deduped. We do **not** list both query and game ports for the same server.

## Why

Hitting masters on every launcher refresh can look like abuse and get client IPs blocked. One GitHub Action run per day pulls upstream so apps can use a stable raw URL.

## Update schedule

- Cron: daily at 12:17 UTC
- Manual: Actions → **Update servers.txt** → Run workflow

## Local / CI

```bash
python3 scripts/fetch_servers.py
```

## Attribution

Server list data originates from [M. Hambloch](https://hambloch.com/kingpin/), [333networks](https://master.333networks.com/s/kingpin), and other community masters. Unofficial cache — not affiliated with those operators.
