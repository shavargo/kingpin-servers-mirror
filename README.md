# kingpin-servers-mirror

Daily mirror of Hambloch’s Kingpin server list for launchers and tools.

**Source (authoritative):** https://hambloch.com/kingpin/servers_active.php?gameport=1  
**Mirror (use this):** https://raw.githubusercontent.com/shavargo/kingpin-servers-mirror/main/servers.txt

## Why

Hitting Hambloch on every launcher refresh can look like abuse and get client IPs blocked. This repo fetches the list about once a day (GitHub Actions) so apps can pull a stable raw URL instead.

## Update schedule

- Cron: daily at 12:17 UTC
- Manual: Actions → **Update servers.txt** → Run workflow

## Attribution

Server list data originates from [M. Hambloch / hambloch.com](https://hambloch.com/kingpin/). This is an unofficial cache for the Kingpin community — not affiliated with Hambloch.
