#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║         CHIA XCH BALANCE CHECKER v2  —  by Claude / Anthropic       ║
║  ✔ Proxy rotation (HTTP/SOCKS5) — anti rate-limit                   ║
║  ✔ Import address.txt / mnemonic.txt (bulk, ribuan baris)           ║
║  ✔ Cek XCH + semua CAT token + valuasi USD                          ║
║  ✔ Export: balance.txt & no_balance.txt                              ║
╚══════════════════════════════════════════════════════════════════════╝

QUICK START:
  pip install -r requirements.txt

  # Cek dari file address
  python chia_balance_checker.py --address-file address.txt

  # Cek dari file mnemonic
  python chia_balance_checker.py --mnemonic-file mnemonic.txt

  # Dengan proxy list
  python chia_balance_checker.py --address-file address.txt --proxy-file proxies.txt

  # Kombinasi semua + multi-thread
  python chia_balance_checker.py \\
      --address-file address.txt \\
      --mnemonic-file mnemonic.txt \\
      --proxy-file proxies.txt \\
      --count 30 \\
      --threads 5

FORMAT FILE:
  address.txt  → satu address xch1... per baris
  mnemonic.txt → satu mnemonic phrase (12/24 kata) per baris
  proxies.txt  → satu proxy per baris:
                   http://ip:port
                   http://user:pass@ip:port
                   socks5://ip:port
                   socks5://user:pass@ip:port
                   ip:port          (dianggap HTTP)
"""

import argparse
import sys
import os
import time
import hashlib
import hmac as hmaclib
import threading
import queue
import itertools
from typing import Optional, List, Dict, Tuple
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────
MISSING = []

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    MISSING.append("requests")

try:
    from mnemonic import Mnemonic
except ImportError:
    MISSING.append("mnemonic")

BLS_LIB = None
try:
    import chia_bls
    from chia_bls import PrivateKey
    BLS_LIB = "chia_bls"
except ImportError:
    try:
        from blspy import PrivateKey
        BLS_LIB = "blspy"
    except ImportError:
        MISSING.append("chia-bls  (atau: pip install blspy)")

try:
    from bech32 import bech32_encode, convertbits
except ImportError:
    MISSING.append("bech32")

if MISSING:
    print("\n❌  Dependencies kurang — install dulu:")
    for m in MISSING:
        print(f"    pip install {m}")
    print("\n  Install semua:\n  pip install requests mnemonic chia-bls bech32\n")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
#  KONSTANTA
# ─────────────────────────────────────────────────────────
SPACESCAN_API   = "https://api.spacescan.io"
DEFAULT_COUNT   = 20
DEFAULT_THREADS = 3
DELAY_NO_PROXY  = 1.2    # detik tantar request tanpa proxy
DELAY_PROXY     = 0.35   # detik antar request dengan proxy
MAX_RETRIES     = 4
TIMEOUT         = 18
HRP             = "xch"
BLS_MOD         = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# ─────────────────────────────────────────────────────────
#  PRINT LOCK
# ─────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

# ─────────────────────────────────────────────────────────
#  PROXY MANAGER  (round-robin + blacklist)
# ─────────────────────────────────────────────────────────

class ProxyManager:
    """
    Rotasi proxy secara round-robin.
    Proxy yang gagal >=5 kali di-skip otomatis.
    Format: http://ip:port | http://user:pass@ip:port
            socks5://ip:port | ip:port (→ http)
    """

    def __init__(self, proxy_lines: List[str]):
        self._list   = []
        self._stats  = defaultdict(lambda: {"ok": 0, "fail": 0})
        self._lock   = threading.Lock()
        self._cycle  = None

        for raw in proxy_lines:
            p = raw.strip()
            if not p or p.startswith("#"):
                continue
            if "://" not in p:
                p = "http://" + p
            self._list.append(p)

        if self._list:
            self._cycle = itertools.cycle(self._list)
            print(f"  🔀 {len(self._list)} proxy dimuat")
        else:
            print("  ⚠  Tidak ada proxy valid — lanjut tanpa proxy")

    def __bool__(self):
        return bool(self._list)

    def get(self) -> Optional[Dict]:
        if not self._list:
            return None
        with self._lock:
            for _ in range(len(self._list) * 2):
                url = next(self._cycle)
                if self._stats[url]["fail"] < 5:
                    return {"http": url, "https": url}
        return None   # semua proxy sudah blacklist

    def ok(self, proxy: Optional[Dict]):
        if proxy:
            with self._lock:
                self._stats[list(proxy.values())[0]]["ok"] += 1

    def fail(self, proxy: Optional[Dict]):
        if proxy:
            with self._lock:
                self._stats[list(proxy.values())[0]]["fail"] += 1

    def summary(self) -> str:
        lines = []
        for url, s in sorted(self._stats.items(), key=lambda x: -x[1]["ok"]):
            lines.append(f"  {url[:48]:48s}  ✓{s['ok']:>4}  ✗{s['fail']:>3}")
        return "\n".join(lines) or "  (tidak ada data)"


# ─────────────────────────────────────────────────────────
#  HTTP SESSION  (per-request, ganti proxy tiap kali)
# ─────────────────────────────────────────────────────────

def _make_session(proxy: Optional[Dict]) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "Mozilla/5.0 (compatible; ChiaChecker/2.0)"
    s.headers["Accept"]     = "application/json"
    if proxy:
        s.proxies.update(proxy)
    return s


def api_get(
    url: str,
    proxy_mgr: Optional[ProxyManager],
    delay: float,
) -> Optional[dict]:
    """GET ke Spacescan API dengan retry + rotasi proxy."""
    for attempt in range(MAX_RETRIES):
        proxy   = proxy_mgr.get() if proxy_mgr else None
        session = _make_session(proxy)
        try:
            resp = session.get(url, timeout=TIMEOUT)

            if resp.status_code == 200:
                if proxy_mgr:
                    proxy_mgr.ok(proxy)
                time.sleep(delay)
                try:
                    return resp.json()
                except Exception:
                    return None

            elif resp.status_code == 429:
                wait = (2 ** attempt) * (1.0 if proxy_mgr else 4.0)
                safe_print(f"\n  ⏳ Rate limit (429) — tunggu {wait:.0f}s "
                           f"{'[rotasi proxy]' if proxy_mgr else ''}")
                if proxy_mgr:
                    proxy_mgr.fail(proxy)
                time.sleep(wait)

            elif resp.status_code in (403, 407):
                if proxy_mgr:
                    proxy_mgr.fail(proxy)
                time.sleep(0.5)

            else:
                time.sleep(delay)
                return None

        except requests.exceptions.ProxyError:
            if proxy_mgr:
                proxy_mgr.fail(proxy)
            time.sleep(0.5)

        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout):
            if proxy_mgr:
                proxy_mgr.fail(proxy)
            time.sleep(0.5)

        except Exception:
            time.sleep(1)

    return None


# ─────────────────────────────────────────────────────────
#  SPACESCAN WRAPPERS
# ─────────────────────────────────────────────────────────

def get_xch_balance(addr: str, pm, delay: float) -> float:
    d = api_get(f"{SPACESCAN_API}/address/xch-balance/{addr}", pm, delay)
    if d and d.get("status") == "success":
        return float(d.get("balance", d.get("xch-balance", 0)) or 0)
    return 0.0


def get_cat_balances(addr: str, pm, delay: float) -> list:
    d = api_get(f"{SPACESCAN_API}/address/cat-balance/{addr}", pm, delay)
    if d and d.get("status") == "success":
        cats = d.get("cats", d.get("cat", []))
        if isinstance(cats, list):
            return [c for c in cats
                    if float(c.get("balance", c.get("amount", 0)) or 0) > 0]
    return []


def get_xch_price_usd(pm, delay: float) -> float:
    d = api_get(f"{SPACESCAN_API}/price/xch?currency=USD", pm, delay)
    if d:
        price = (d.get("data") or {}).get("price") or d.get("price") or 0
        return float(price)
    return 0.0


# ─────────────────────────────────────────────────────────
#  BLS12-381 KEY DERIVATION  (EIP-2333 / Chia standard)
# ─────────────────────────────────────────────────────────

def _hkdf_expand_sha512(prk: bytes, info: bytes, length: int) -> bytes:
    T, okm, i = b"", b"", 1
    while len(okm) < length:
        T = hmaclib.new(prk, T + info + bytes([i]), hashlib.sha512).digest()
        okm += T
        i += 1
    return okm[:length]


def _ikm_to_lamport_sk(ikm: bytes, salt: bytes) -> list:
    prk = hmaclib.new(salt, ikm, hashlib.sha512).digest()
    okm = _hkdf_expand_sha512(prk, b"", 255 * 32)
    return [okm[i*32:(i+1)*32] for i in range(255)]


def _parent_sk_to_lamport_pk(parent_sk: bytes) -> bytes:
    salt = b'\x00' * 4
    l0   = _ikm_to_lamport_sk(parent_sk, salt)
    l1   = _ikm_to_lamport_sk(bytes(b ^ 0xFF for b in parent_sk), salt)
    combined = b"".join(hashlib.sha256(c).digest() for c in l0 + l1)
    return hashlib.sha256(combined).digest()


def _bls_keygen(ikm: bytes) -> int:
    salt = hashlib.sha256(b"BLS-SIG-KEYGEN-SALT-").digest()
    while True:
        prk = hmaclib.new(salt, ikm + b'\x00', hashlib.sha512).digest()
        okm = _hkdf_expand_sha512(prk, b'\x00\x30', 48)
        sk  = int.from_bytes(okm, 'big') % BLS_MOD
        if sk:
            return sk
        salt = hashlib.sha256(salt).digest()


def _derive_child(parent_sk: bytes, index: int) -> bytes:
    lpk = _parent_sk_to_lamport_pk(parent_sk)
    ikm = lpk + index.to_bytes(4, 'big')
    return _bls_keygen(ikm).to_bytes(32, 'big')


def mnemonic_to_seed(phrase: str) -> bytes:
    m = Mnemonic("english")
    if not m.check(phrase):
        raise ValueError("mnemonic tidak valid / kata salah")
    return m.to_seed(phrase, passphrase="")


def derive_wallet_sk(seed: bytes, index: int) -> bytes:
    """Path: m/12381/8444/2/index  (Chia standard wallet path)"""
    sk = _bls_keygen(seed).to_bytes(32, 'big')
    for i in [12381, 8444, 2, index]:
        sk = _derive_child(sk, i)
    return sk


def sk_to_address(sk_bytes: bytes) -> str:
    pk_bytes    = bytes(PrivateKey.from_bytes(sk_bytes).get_g1())  # 48 bytes G1
    inner       = hashlib.sha256(b'\x01' + pk_bytes).digest()
    puzzle_hash = hashlib.sha256(b'\x02' + inner).digest()
    converted   = convertbits(puzzle_hash, 8, 5)
    return bech32_encode(HRP, [0] + converted)


def derive_addresses_from_mnemonic(phrase: str, count: int) -> List[Tuple[str, int]]:
    seed   = mnemonic_to_seed(phrase)
    result = []
    for i in range(count):
        sk   = derive_wallet_sk(seed, i)
        addr = sk_to_address(sk)
        result.append((addr, i))
    return result


# ─────────────────────────────────────────────────────────
#  FILE LOADER  (robust: UTF-8, BOM, CRLF, blank/comment)
# ─────────────────────────────────────────────────────────

def load_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        print(f"❌  File tidak ditemukan: {path}")
        sys.exit(1)
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return [
            ln.strip()
            for ln in f
            if ln.strip() and not ln.strip().startswith("#")
        ]


def load_proxies(path: str) -> List[str]:
    if not os.path.exists(path):
        print(f"⚠  Proxy file tidak ditemukan: {path}")
        return []
    return load_lines(path)


# ─────────────────────────────────────────────────────────
#  WORKER THREAD
# ─────────────────────────────────────────────────────────

def worker(
    task_q: queue.Queue,
    result_q: queue.Queue,
    proxy_mgr: Optional[ProxyManager],
    xch_price: float,
    delay: float,
    counter: dict,
    counter_lock: threading.Lock,
):
    while True:
        try:
            addr, meta = task_q.get(timeout=3)
        except queue.Empty:
            break

        xch  = get_xch_balance(addr, proxy_mgr, delay)
        cats = get_cat_balances(addr, proxy_mgr, delay)

        usd = xch * xch_price
        for cat in cats:
            p   = float(cat.get("price_usd", cat.get("price_USD", 0)) or 0)
            bal = float(cat.get("balance",   cat.get("amount", 0))    or 0)
            usd += bal * p

        has_balance = xch > 0 or bool(cats)
        result = {
            "address":     addr,
            "xch":         xch,
            "cats":        cats,
            "usd":         usd,
            "has_balance": has_balance,
            "meta":        meta,
        }
        result_q.put(result)

        with counter_lock:
            counter["done"] += 1
            if has_balance:
                counter["found"] += 1
            done  = counter["done"]
            total = counter["total"]
            found = counter["found"]

        # Print baris progres
        pct  = done / max(total, 1) * 100
        info = (f"💰 {xch:.6f} XCH" + (f" +{len(cats)}🪙" if cats else "")
                if has_balance else "—")
        safe_print(
            f"  [{done:>5}/{total}  {pct:5.1f}%  💰{found}]  "
            f"{addr[:12]}..{addr[-6:]}  {info}"
        )

        task_q.task_done()


# ─────────────────────────────────────────────────────────
#  OUTPUT WRITER
# ─────────────────────────────────────────────────────────

def fmt_xch(v) -> str:
    s = f"{float(v or 0):.8f}".rstrip('0').rstrip('.')
    return s or "0"

def fmt_usd(v) -> str:
    return f"${float(v or 0):,.4f}"


def write_balance_file(path: str, results: list, xch_price: float):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w", encoding="utf-8") as f:
        f.write("═" * 64 + "\n")
        f.write("  CHIA XCH BALANCE CHECKER v2 — WALLET DENGAN SALDO\n")
        f.write(f"  Waktu    : {now}\n")
        f.write(f"  Wallet   : {len(results)} wallet ada saldo\n")
        f.write(f"  XCH/USD  : ${xch_price:.4f}\n")
        f.write("═" * 64 + "\n\n")

        total_xch = sum(r["xch"] for r in results)
        total_usd = sum(r["usd"] for r in results)
        f.write(f"GRAND TOTAL : {fmt_xch(total_xch)} XCH  ≈  ${total_usd:,.2f} USD\n\n")

        # Ringkasan semua token CAT
        token_totals: Dict[str, dict] = {}
        for r in results:
            for cat in r["cats"]:
                sym  = cat.get("symbol", cat.get("asset_symbol", "???"))
                name = cat.get("name", cat.get("asset_name", sym))
                bal  = float(cat.get("balance", cat.get("amount", 0)) or 0)
                p    = float(cat.get("price_usd", cat.get("price_USD", 0)) or 0)
                if sym not in token_totals:
                    token_totals[sym] = {"name": name, "sym": sym, "bal": 0.0, "usd": 0.0}
                token_totals[sym]["bal"] += bal
                token_totals[sym]["usd"] += bal * p

        if token_totals:
            f.write("TOKEN CAT GABUNGAN (SEMUA WALLET):\n")
            for info in sorted(token_totals.values(), key=lambda x: -x["usd"]):
                f.write(f"  ├─ {info['name']:30s}  "
                        f"{info['bal']:>18.6f} {info['sym']:<8}  "
                        f"≈  {fmt_usd(info['usd'])}\n")
            f.write("\n")

        # Detail per wallet
        for i, r in enumerate(results, 1):
            addr = r["address"]
            meta = r.get("meta") or {}
            origin = ""
            if meta.get("mnemonic_idx") is not None:
                origin = (f"  [mnemonic #{meta['mnemonic_idx']+1}"
                          f", derive idx {meta['derive_idx']}]")

            f.write("─" * 64 + "\n")
            f.write(f"[{i}/{len(results)}] {addr}{origin}\n")
            f.write(f"  Explorer : https://www.spacescan.io/address/{addr}\n")
            f.write(f"  XCH      : {fmt_xch(r['xch'])} XCH"
                    f"  ≈  ${r['xch']*xch_price:,.4f} USD\n")

            if r["cats"]:
                f.write(f"  TOKENS ({len(r['cats'])}):\n")
                for cat in r["cats"]:
                    sym  = cat.get("symbol", cat.get("asset_symbol", "?"))
                    name = cat.get("name",   cat.get("asset_name", sym))
                    bal  = float(cat.get("balance", cat.get("amount", 0)) or 0)
                    p    = float(cat.get("price_usd", cat.get("price_USD", 0)) or 0)
                    f.write(f"    ├─ {name} ({sym}): "
                            f"{bal:.6f}  ≈  ${bal*p:,.6f} USD\n")
            else:
                f.write("  TOKENS   : —\n")
            f.write("\n")


def write_no_balance_file(path: str, results: list):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w", encoding="utf-8") as f:
        f.write("═" * 64 + "\n")
        f.write("  CHIA XCH BALANCE CHECKER v2 — WALLET KOSONG\n")
        f.write(f"  Waktu  : {now}\n")
        f.write(f"  Total  : {len(results)} wallet kosong\n")
        f.write("═" * 64 + "\n\n")
        for r in results:
            addr = r["address"]
            meta = r.get("meta") or {}
            note = ""
            if meta.get("mnemonic_idx") is not None:
                note = f"  # mnemonic #{meta['mnemonic_idx']+1}, idx {meta['derive_idx']}"
            f.write(f"{addr}{note}\n")


# ─────────────────────────────────────────────────────────
#  CLI ARGS
# ─────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Chia XCH Balance Checker v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    inp = p.add_argument_group("INPUT  (bisa dikombinasikan)")
    inp.add_argument("--address-file",  "-A", metavar="FILE",
                     help="File berisi address xch1... (satu per baris)")
    inp.add_argument("--mnemonic-file", "-M", metavar="FILE",
                     help="File berisi mnemonic phrase (satu per baris)")
    inp.add_argument("--input-file",    "-I", metavar="FILE",
                     help="File campur address+mnemonic — auto-detect per baris")
    inp.add_argument("--address",       "-a", nargs="+", metavar="ADDR",
                     help="Address xch1... langsung di CLI")
    inp.add_argument("--mnemonic",      "-m", nargs="+", metavar="WORD",
                     help='Mnemonic phrase langsung (dalam tanda kutip)')
    inp.add_argument("--count",         "-c", type=int, default=DEFAULT_COUNT,
                     help=f"Jumlah address per mnemonic (default: {DEFAULT_COUNT})")

    prx = p.add_argument_group("PROXY")
    prx.add_argument("--proxy-file",    "-P", metavar="FILE",
                     help="File berisi proxy list (satu per baris)")
    prx.add_argument("--proxy",         nargs="+", metavar="PROXY",
                     help="Proxy langsung: http://ip:port atau socks5://ip:port")
    prx.add_argument("--delay",         type=float, default=None,
                     help="Override delay antar request (detik)")

    out = p.add_argument_group("OUTPUT")
    out.add_argument("--output-dir",    "-o", default=".", metavar="DIR",
                     help="Direktori output (default: folder saat ini)")
    out.add_argument("--threads",       "-t", type=int, default=DEFAULT_THREADS,
                     help=f"Jumlah thread concurrent (default: {DEFAULT_THREADS})")
    out.add_argument("--quiet",         "-q", action="store_true")
    return p.parse_args()


# ─────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║   CHIA XCH BALANCE CHECKER v2                           ║
║   Proxy Rotation + Bulk Import  |  Spacescan.io API     ║
╚══════════════════════════════════════════════════════════╝""")


def main():
    args = parse_args()
    if not args.quiet:
        banner()

    # ── Proxy ───────────────────────────────────────────
    proxy_lines = []
    if args.proxy_file:
        proxy_lines += load_proxies(args.proxy_file)
    if args.proxy:
        proxy_lines += args.proxy
    proxy_mgr = ProxyManager(proxy_lines) if proxy_lines else None

    delay = args.delay
    if delay is None:
        delay = DELAY_PROXY if proxy_mgr else DELAY_NO_PROXY

    # ── Kumpulkan tasks: (address, meta) ────────────────
    tasks: List[Tuple[str, dict]] = []
    seen:  set = set()

    def add_addr(addr: str, meta: dict = None):
        addr = addr.strip()
        if addr and addr.startswith("xch1") and len(addr) > 50 and addr not in seen:
            seen.add(addr)
            tasks.append((addr, meta or {}))

    def add_mnemonic(phrase: str, m_idx: int):
        phrase = " ".join(phrase.strip().split())  # normalize whitespace
        if not phrase:
            return
        try:
            pairs = derive_addresses_from_mnemonic(phrase, args.count)
            for addr, d_idx in pairs:
                add_addr(addr, {"mnemonic_idx": m_idx, "derive_idx": d_idx})
            safe_print(f"  ✓ Mnemonic #{m_idx+1}: {len(pairs)} address diturunkan")
        except Exception as e:
            safe_print(f"  ✗ Mnemonic #{m_idx+1} gagal: {e}")

    # -- Inline address
    if args.address:
        for a in args.address:
            add_addr(a)

    # -- Inline mnemonic
    if args.mnemonic:
        phrase = " ".join(args.mnemonic)
        add_mnemonic(phrase, 0)

    # -- --address-file
    if args.address_file:
        lines = load_lines(args.address_file)
        print(f"\n📂 address-file: {args.address_file}  ({len(lines)} baris)")
        before = len(tasks)
        for ln in lines:
            add_addr(ln)
        print(f"   → {len(tasks)-before} address unik ditambahkan")

    # -- --mnemonic-file
    if args.mnemonic_file:
        lines = load_lines(args.mnemonic_file)
        print(f"\n📂 mnemonic-file: {args.mnemonic_file}  ({len(lines)} baris)")
        print("   Menurunkan address...\n")
        for i, phrase in enumerate(lines):
            add_mnemonic(phrase, i)

    # -- --input-file  (auto-detect per baris)
    if args.input_file:
        lines = load_lines(args.input_file)
        print(f"\n📂 input-file: {args.input_file}  ({len(lines)} baris, auto-detect)")
        m_idx = 0
        for ln in lines:
            if ln.startswith("xch1") and len(ln.split()) == 1:
                add_addr(ln)
            elif len(ln.split()) >= 10:
                add_mnemonic(ln, m_idx)
                m_idx += 1
            else:
                safe_print(f"   ⚠  Skip (tidak dikenal): {ln[:50]}")

    if not tasks:
        print("\n❌  Tidak ada address/mnemonic valid. Gunakan --help.\n")
        sys.exit(1)

    print(f"\n{'─'*52}")
    print(f"  📋 Total address unik : {len(tasks)}")
    print(f"  🔀 Proxy aktif        : {len(proxy_lines)}")
    print(f"  ⚙  Thread             : {args.threads}")
    print(f"  ⏱  Delay              : {delay:.2f}s / request")
    print(f"{'─'*52}\n")

    # ── Harga XCH ───────────────────────────────────────
    print("💱 Ambil harga XCH/USD...")
    xch_price = get_xch_price_usd(proxy_mgr, delay)
    print(f"   1 XCH = ${xch_price:.4f} USD\n")

    # ── Multi-thread processing ──────────────────────────
    print(f"🔍 Mulai cek {len(tasks)} address...\n")

    task_q   = queue.Queue()
    result_q = queue.Queue()
    counter      = {"done": 0, "found": 0, "total": len(tasks)}
    counter_lock = threading.Lock()

    for item in tasks:
        task_q.put(item)

    n_threads = min(args.threads, len(tasks))
    threads   = []
    for _ in range(n_threads):
        t = threading.Thread(
            target=worker,
            args=(task_q, result_q, proxy_mgr, xch_price,
                  delay, counter, counter_lock),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # ── Kumpulkan & sortir ───────────────────────────────
    all_results = []
    while not result_q.empty():
        all_results.append(result_q.get())

    all_results.sort(key=lambda r: (-int(r["has_balance"]), -r["xch"]))
    with_balance = [r for r in all_results if r["has_balance"]]
    no_balance   = [r for r in all_results if not r["has_balance"]]

    # ── Simpan file ──────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    bal_path = os.path.join(args.output_dir, "balance.txt")
    nob_path = os.path.join(args.output_dir, "no_balance.txt")

    write_balance_file(bal_path, with_balance, xch_price)
    write_no_balance_file(nob_path, no_balance)

    # ── Proxy stats ──────────────────────────────────────
    if proxy_mgr and not args.quiet:
        print(f"\n{'─'*52}")
        print("  PROXY STATS:")
        print(proxy_mgr.summary())

    # ── Ringkasan akhir ──────────────────────────────────
    total_xch = sum(r["xch"] for r in with_balance)
    total_usd = sum(r["usd"] for r in with_balance)

    print(f"""
{'═'*52}
  SELESAI!
{'═'*52}
  ✅ Wallet ada saldo   : {len(with_balance):>6}
  ⬜ Wallet kosong      : {len(no_balance):>6}
  ─────────────────────────────────────────────
  💰 Total XCH          : {fmt_xch(total_xch)} XCH
  💵 Estimasi USD       : ${total_usd:,.2f}
  ─────────────────────────────────────────────
  📄 balance.txt     → {bal_path}
  📄 no_balance.txt  → {nob_path}
{'═'*52}
""")


if __name__ == "__main__":
    main()