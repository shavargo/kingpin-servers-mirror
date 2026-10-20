#!/usr/bin/env python3
"""Build a merged Kingpin address list from Hambloch + community masters.

List entries are **game (connect) ports** only — what `+connect` uses.
UDP status normally answers on query port = game − 10 (Kingpin convention).
"""

from __future__ import annotations

import re
import socket
import struct
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GAMENAME = "kingpin"
# Public GameSpy gamekey for Kingpin (gslist.cfg / maraakate gsmaster).
GAMEKEY = b"QFWxY2"

# Preferred public endpoints (per M. Hambloch). Use servers_active.php endpoints.
HAMBLOCH_GAMEPORT_URL = (
	"https://hambloch.com/kingpin/servers_active.php?gameport=1"
)

# Gamespy v0 list servers (TCP 28900). UDP 27900 is for heartbeats only.
GAMESPY_MASTERS = [
	"master.333networks.com",
	"master.errorist.eu",
	"master1.kingpin.info",
	"master.newbiesplayground.net",
	"master.frag-net.com",
]

# Quake II–style masters (UDP 27900, "query" → packed server list).
Q2_MASTERS = [
	"master.hambloch.com",
	"master.kingpin.info",
	"master0.kingpin.info",
	"master3.kingpin.info",
]

ADDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
IP_KV_RE = re.compile(rb"\\ip\\(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})")


def gs_validate(challenge: bytes, key: bytes) -> str:
	"""GameSpy secure/validate (enctype 0) — aluigi gsmsalg."""
	if not challenge or len(challenge) > 65:
		raise ValueError("bad challenge")
	enctmp = list(range(256))
	a = 0
	keysz = len(key)
	for i in range(256):
		a = (a + enctmp[i] + key[i % keysz]) & 0xFF
		enctmp[a], enctmp[i] = enctmp[i], enctmp[a]

	tmp = bytearray()
	a = 0
	b = 0
	for ch in challenge:
		a = (a + ch + 1) & 0xFF
		x = enctmp[a]
		b = (b + x) & 0xFF
		y = enctmp[b]
		enctmp[b], enctmp[a] = x, y
		tmp.append(ch ^ enctmp[(x + y) & 0xFF])

	while len(tmp) % 3:
		tmp.append(0)

	def enc(reg: int) -> str:
		if reg < 26:
			return chr(reg + ord("A"))
		if reg < 52:
			return chr(reg + ord("G"))
		if reg < 62:
			return chr(reg - 4)
		if reg == 62:
			return "+"
		return "/"

	out = []
	for i in range(0, len(tmp), 3):
		x, y, z = tmp[i], tmp[i + 1], tmp[i + 2]
		out.append(enc(x >> 2))
		out.append(enc(((x & 3) << 4) | (y >> 4)))
		out.append(enc(((y & 15) << 2) | (z >> 6)))
		out.append(enc(z & 63))
	return "".join(out)


def parse_kv(data: bytes) -> dict[str, bytes]:
	parts = data.split(b"\\")
	out: dict[str, bytes] = {}
	i = 1 if parts and parts[0] == b"" else 0
	while i + 1 < len(parts):
		out[parts[i].decode("ascii", "replace").lower()] = parts[i + 1]
		i += 2
	return out


def parse_packed_servers(data: bytes) -> list[str]:
	"""Parse Q2 'servers\\n' + 6-byte (ip4 + port BE) records."""
	addrs: list[str] = []
	if data.startswith(b"\xff\xff\xff\xff"):
		data = data[4:]
	idx = data.find(b"servers")
	if idx < 0:
		return addrs
	payload = data[idx + len(b"servers") :]
	if payload.startswith(b"\n"):
		payload = payload[1:]
	elif payload.startswith(b"Response"):
		return addrs

	for i in range(0, len(payload) - 5, 6):
		chunk = payload[i : i + 6]
		if chunk == b"\x00" * 6:
			break
		ip = ".".join(str(b) for b in chunk[:4])
		(port,) = struct.unpack("!H", chunk[4:6])
		if port == 0:
			continue
		addrs.append(f"{ip}:{port}")
	return addrs


def parse_compressed_cmp(data: bytes) -> list[str]:
	"""Parse Gamespy \\list\\cmp\\ body: raw 6-byte records (no \\ip\\ markers)."""
	addrs: list[str] = []
	end = data.find(b"\\final\\")
	if end >= 0:
		data = data[:end]
	if b"\\ip\\" in data:
		return addrs
	for i in range(0, len(data) - 5, 6):
		chunk = data[i : i + 6]
		ip = ".".join(str(b) for b in chunk[:4])
		(port,) = struct.unpack("!H", chunk[4:6])
		if port == 0 or any(b > 255 for b in chunk[:4]):
			continue
		addrs.append(f"{ip}:{port}")
	return addrs


def query_to_game_port(query_addr: str) -> str | None:
	"""Gamespy masters advertise Kingpin *query* ports; connect is query + 10."""
	norm = normalize(query_addr)
	if not norm:
		return None
	ip, port_s = norm.split(":")
	game = int(port_s) + 10
	if not (1 <= game <= 65535):
		return None
	return f"{ip}:{game}"


def fetch_gamespy_master(host: str, port: int = 28900, timeout: float = 12.0) -> list[str]:
	sock = socket.create_connection((host, port), timeout=timeout)
	sock.settimeout(timeout)
	try:
		hello = sock.recv(512)
		kv = parse_kv(hello)
		secure = kv.get("secure", b"")
		if not secure:
			raise RuntimeError(f"no secure challenge in {hello!r}")

		validate = gs_validate(secure, GAMEKEY)
		req = (
			f"\\gamename\\{GAMENAME}\\gamever\\1.21\\location\\0"
			f"\\validate\\{validate}\\enctype\\0\\final\\"
			f"\\list\\\\gamename\\{GAMENAME}\\final\\"
		).encode("ascii")
		sock.sendall(req)

		buf = bytearray()
		while True:
			try:
				chunk = sock.recv(8192)
			except socket.timeout:
				break
			if not chunk:
				break
			buf.extend(chunk)
			if b"\\final\\" in buf:
				break

		data = bytes(buf)
		addrs = [m.decode("ascii") for m in IP_KV_RE.findall(data)]
		if not addrs:
			addrs = parse_compressed_cmp(data)
		# Store game ports only (no query+game duplicates).
		game_ports: list[str] = []
		for a in addrs:
			g = query_to_game_port(a)
			if g:
				game_ports.append(g)
		return list(dict.fromkeys(game_ports))
	finally:
		sock.close()


def fetch_q2_master(host: str, port: int = 27900, timeout: float = 5.0) -> list[str]:
	payload = b"\xff\xff\xff\xffquery"
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	try:
		sock.sendto(payload, (host, port))
		chunks: list[bytes] = []
		sock.settimeout(timeout)
		try:
			while True:
				data, _ = sock.recvfrom(65535)
				chunks.append(data)
				sock.settimeout(0.4)
		except socket.timeout:
			pass
		if not chunks:
			raise RuntimeError("no response")
		addrs: list[str] = []
		for data in chunks:
			addrs.extend(parse_packed_servers(data))
		return list(dict.fromkeys(addrs))
	finally:
		sock.close()


def parse_addr_file(text: str) -> list[str]:
	addrs: list[str] = []
	for line in text.splitlines():
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		m = ADDR_RE.match(line)
		if m:
			addrs.append(f"{m.group(1)}:{m.group(2)}")
	return addrs


def fetch_hambloch_gameports() -> list[str]:
	req = urllib.request.Request(
		HAMBLOCH_GAMEPORT_URL,
		headers={
			"User-Agent": (
				"kingpin-servers-mirror/1.2 "
				"(+https://github.com/shavargo/kingpin-servers-mirror)"
			)
		},
	)
	with urllib.request.urlopen(req, timeout=60) as resp:
		text = resp.read().decode("utf-8", "replace")
	return parse_addr_file(text)


def load_extras(root: Path) -> list[str]:
	path = root / "extras.txt"
	if not path.is_file():
		return []
	return parse_addr_file(path.read_text(encoding="utf-8"))


def normalize(addr: str) -> str | None:
	m = ADDR_RE.match(addr.strip())
	if not m:
		return None
	ip, port = m.group(1), int(m.group(2))
	if not (1 <= port <= 65535):
		return None
	octets = [int(x) for x in ip.split(".")]
	if any(o > 255 for o in octets):
		return None
	return f"{ip}:{port}"


def sort_key(addr: str) -> tuple:
	ip, port_s = addr.split(":")
	return (tuple(int(x) for x in ip.split(".")), int(port_s))


def main() -> int:
	root = Path(__file__).resolve().parents[1]
	out_path = root / "servers.txt"

	sources: dict[str, list[str]] = {}
	errors: list[str] = []

	extras = load_extras(root)
	if extras:
		sources["extras.txt"] = extras
		print(f"extras.txt: {len(extras)} addresses")

	try:
		sources["hambloch.com/servers_active.php?gameport=1"] = fetch_hambloch_gameports()
		print(
			"hambloch gameport: "
			f"{len(sources['hambloch.com/servers_active.php?gameport=1'])} addresses"
		)
	except Exception as exc:  # noqa: BLE001
		errors.append(f"hambloch: {exc}")
		print(f"hambloch FAILED: {exc}", file=sys.stderr)

	for host in GAMESPY_MASTERS:
		label = f"gamespy://{host}:28900"
		try:
			addrs = fetch_gamespy_master(host)
			sources[label] = addrs
			print(f"{label}: {len(addrs)} addresses")
		except Exception as exc:  # noqa: BLE001
			errors.append(f"{label}: {exc}")
			print(f"{label} FAILED: {exc}", file=sys.stderr)

	for host in Q2_MASTERS:
		label = f"q2udp://{host}:27900"
		try:
			addrs = fetch_q2_master(host)
			sources[label] = addrs
			print(f"{label}: {len(addrs)} addresses")
		except Exception as exc:  # noqa: BLE001
			errors.append(f"{label}: {exc}")
			print(f"{label} FAILED: {exc}", file=sys.stderr)

	merged: dict[str, str] = {}
	for label, addrs in sources.items():
		for raw in addrs:
			norm = normalize(raw)
			if norm and norm not in merged:
				merged[norm] = label

	if len(merged) < 5:
		print(
			f"ERROR: only {len(merged)} addresses after merge; refusing to write",
			file=sys.stderr,
		)
		for e in errors:
			print(f"  {e}", file=sys.stderr)
		return 1

	now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	lines = [
		"# Merged Kingpin server address list (game / connect ports)",
		f"# Last fetch (UTC): {now}",
		"# Sources:",
	]
	for label, addrs in sources.items():
		lines.append(f"#   - {label}: {len(addrs)}")
	if errors:
		lines.append("# Failures (non-fatal if other sources succeeded):")
		for e in errors:
			lines.append(f"#   - {e}")
	lines.append("#")
	lines.append(
		"# Format: ip:gameport  (UDP status usually on gameport-10; launcher probes both)"
	)
	lines.append(
		"# Hambloch source: servers_active.php?gameport=1"
	)
	lines.append("#")

	for addr in sorted(merged.keys(), key=sort_key):
		lines.append(addr)

	out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
	print(f"Wrote {len(merged)} unique addresses -> {out_path}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
