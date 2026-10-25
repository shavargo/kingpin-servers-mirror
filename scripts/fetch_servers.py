#!/usr/bin/env python3
"""Build a merged Kingpin address list from Hambloch + community masters.

List entries are **game (connect) ports** only — what `+connect` uses.
UDP status normally answers on query port = game − 10 (Kingpin convention).

Master hostnames are the real DNS names from
https://wiki.kingpin.info/index.php/Ports (Details column), not the
masterN.kingpin.info aliases.

Two master protocols:
  - Quake II UDP ``query`` on 27900 (Kingpin-native master software)
  - GameSpy v0 TCP list on 28900 (secure/validate; lists query ports)
"""

from __future__ import annotations

import re
import socket
import struct
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Public Hambloch endpoint (game / connect ports).
HAMBLOCH_GAMEPORT_URL = (
	"https://hambloch.com/kingpin/servers_active.php?gameport=1"
)

# Quake II–style masters (UDP 27900, "query" → packed server list).
# These run Kingpin-native master software and answer UDP query.
Q2_MASTERS = [
	"master.hambloch.com",
	"master.shavargo.com",
]

# GameSpy v0 masters (TCP 28900). Do not answer Q2 UDP query on 27900.
# Cipher from 333networks Masterserver-Qt5 data/SupportedGames.json.
GAMESPY_MASTERS = [
	"master.errorist.eu",
	"master.333networks.com",
	"master.frag-net.com",
]
GAMESPY_GAMENAME = "kingpin"
GAMESPY_CIPHER = "QFWxY2"

ADDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
GAMESPY_IP_RE = re.compile(
	rb"\\ip\\(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"
)


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


def _gs_charshift(reg: int) -> int:
	if reg < 26:
		return reg + 65
	if reg < 52:
		return reg + 71
	if reg < 62:
		return reg - 4
	if reg == 62:
		return 43
	if reg == 63:
		return 47
	return 0


def gamespy_validate(cipher: str, secure: str, enctype: int = 0) -> str:
	"""GameSpy secure/validate (gsmsalg / enctype 0), from GSMSALG / 333networks."""
	cip = [ord(c) for c in cipher]
	sec = [ord(c) for c in secure]
	if not (0 < len(sec) <= 8 and 0 < len(cip) <= 8):
		return ""
	enc = list(range(256))
	j = 0
	for i in range(256):
		j = (j + enc[i] + cip[i % len(cip)]) % 256
		enc[j], enc[i] = enc[i], enc[j]
	tmp: list[int] = []
	j = 0
	k = 0
	for i in range(len(sec)):
		j = (j + sec[i] + 1) % 256
		left = enc[j]
		k = (k + left) % 256
		right = enc[k]
		enc[k] = left
		enc[j] = right
		tmp.append(sec[i] ^ enc[(left + right) & 0xFF])
	while len(tmp) % 3:
		tmp.append(0)
	if enctype == 2:
		for i in range(len(tmp)):
			tmp[i] ^= cip[i % len(cip)]
	val: list[int] = []
	for i in range(0, len(tmp), 3):
		left, mid, right = tmp[i], tmp[i + 1] % 256, tmp[i + 2] % 256
		val.append(_gs_charshift(left >> 2))
		val.append(_gs_charshift(((left & 3) << 4) | (mid >> 4)))
		val.append(_gs_charshift(((mid & 15) << 2) | (right >> 6)))
		val.append(_gs_charshift(right & 63))
	return "".join(chr(c) for c in val)


def _recv_tcp(sock: socket.socket, first: float, more: float) -> bytes:
	chunks: list[bytes] = []
	sock.settimeout(first)
	try:
		while True:
			data = sock.recv(65535)
			if not data:
				break
			chunks.append(data)
			sock.settimeout(more)
	except socket.timeout:
		pass
	return b"".join(chunks)


def _fetch_gamespy_master_once(
	host: str,
	port: int,
	timeout: float,
) -> list[str]:
	"""One TCP GameSpy v0 list attempt; returns **game** ports (query + 10)."""
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	try:
		sock.connect((host, port))
		challenge = _recv_tcp(sock, 4.0, 0.5)
		if not challenge:
			# Some masters (e.g. frag-net) wait for a first byte before secure.
			sock.sendall(b"\n")
			challenge = _recv_tcp(sock, 4.0, 0.5)
		if b"\\secure\\" not in challenge:
			raise RuntimeError(f"no secure challenge: {challenge[:80]!r}")
		secure = (
			challenge.split(b"\\secure\\", 1)[1]
			.split(b"\\", 1)[0]
			.decode("ascii", "replace")
		)
		validate = gamespy_validate(GAMESPY_CIPHER, secure, enctype=0)
		if not validate:
			raise RuntimeError(f"empty validate for secure={secure!r}")
		req = (
			f"\\list\\\\gamename\\{GAMESPY_GAMENAME}"
			f"\\validate\\{validate}\\enctype\\0\\final\\"
		).encode("ascii")
		sock.sendall(req)
		body = _recv_tcp(sock, 6.0, 1.5)
		if not body:
			raise RuntimeError("empty list response")
		addrs: list[str] = []
		for ip, port_s in GAMESPY_IP_RE.findall(body):
			query_port = int(port_s)
			game_port = query_port + 10
			if game_port > 65535:
				continue
			addrs.append(f"{ip.decode('ascii')}:{game_port}")
		if not addrs:
			raise RuntimeError(f"no \\ip\\ entries in {len(body)}-byte response")
		return list(dict.fromkeys(addrs))
	finally:
		sock.close()


def fetch_gamespy_master(
	host: str,
	port: int = 28900,
	timeout: float = 8.0,
	attempts: int = 2,
) -> list[str]:
	"""TCP GameSpy v0 list with a short retry (some masters are flaky)."""
	last_exc: Exception | None = None
	for i in range(attempts):
		try:
			return _fetch_gamespy_master_once(host, port, timeout)
		except Exception as exc:  # noqa: BLE001
			last_exc = exc
			if i + 1 < attempts:
				continue
	assert last_exc is not None
	raise last_exc


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
				"kingpin-servers-mirror/1.4 "
				"(+https://github.com/shavargo/kingpin-servers-mirror)"
			)
		},
	)
	with urllib.request.urlopen(req, timeout=60) as resp:
		text = resp.read().decode("utf-8", "replace")
	return parse_addr_file(text)


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

	try:
		sources["hambloch.com/servers_active.php?gameport=1"] = fetch_hambloch_gameports()
		print(
			"hambloch gameport: "
			f"{len(sources['hambloch.com/servers_active.php?gameport=1'])} addresses"
		)
	except Exception as exc:  # noqa: BLE001
		errors.append(f"hambloch: {exc}")
		print(f"hambloch FAILED: {exc}", file=sys.stderr)

	for host in Q2_MASTERS:
		label = f"q2udp://{host}:27900"
		try:
			addrs = fetch_q2_master(host)
			sources[label] = addrs
			print(f"{label}: {len(addrs)} addresses")
		except Exception as exc:  # noqa: BLE001
			errors.append(f"{label}: {exc}")
			print(f"{label} FAILED: {exc}", file=sys.stderr)

	for host in GAMESPY_MASTERS:
		label = f"gamespy://{host}:28900"
		try:
			addrs = fetch_gamespy_master(host)
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
	lines.append("#")

	for addr in sorted(merged.keys(), key=sort_key):
		lines.append(addr)

	out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
	print(f"Wrote {len(merged)} unique addresses -> {out_path}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
