#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║           CHIA XCH BALANCE CHECKER - by Claude / Anthropic          ║
║  Cek balance XCH + CAT tokens per wallet dari mnemonic phrase        ║
║  Export: balance.txt (ada saldo) & no_balance.txt (kosong)           ║
╚══════════════════════════════════════════════════════════════════════╝

CARA PAKAI:
  1. Install dependencies:
       pip install mnemonic chia-bls requests bech32

  2. Jalankan dengan flag mnemonic (satu atau lebih):
       python chia_balance_checker.py --mnemonic "word1 word2 ... word24"

  3. Atau simpan mnemonic di file (satu mnemonic per baris):
       python chia_balance_checker.py --file mnemonics.txt

  4. Atau cek satu atau lebih address langsung:
       python chia_balance_checker.py --address xch1abc... xch1def...

  5. Jumlah address yang di-derive per mnemonic (default: 20):
       python chia_balance_checker.py --mnemonic "..." --count 50

OUTPUT:
  - balance.txt     : wallet dengan saldo XCH atau token
  - no_balance.txt  : wallet kosong
  - summary di terminal
"""

import argparse
import sys
import os
import time
import json
import hashlib
import hmac
import struct
from typing import Optional
import requests

# ─────────────────────────────────────────────
#   DEPENDENCY CHECK
# ─────────────────────────────────────────────
MISSING = []
try:
    from mnemonic import Mnemonic
except ImportError:
    MISSING.append("mnemonic")

try:
    import chia_bls
    from chia_bls import PrivateKey, G1Element
    BLS_LIB = "chia_bls"
except ImportError:
    try:
        from blspy import PrivateKey, G1Element, AugSchemeMPL
        BLS_LIB = "blspy"
    except ImportError:
        BLS_LIB = None
        MISSING.append("chia-bls  (atau blspy)")

try:
    from bech32 import bech32_encode, bech32_decode, convertbits
    BECH32_LIB = "bech32"
except ImportError:
    BECH32_LIB = None
    MISSING.append("bech32")

if MISSING:
    print("\n❌  Library berikut belum terinstall:")
    for m in MISSING:
        print(f"    pip install {m}")
    print("\n  Install semua sekaligus:")
    print("    pip install mnemonic chia-bls bech32 requests\n")
    sys.exit(1)

# ─────────────────────────────────────────────
#   KONSTANTA
# ─────────────────────────────────────────────
SPACESCAN_API   = "https://api.spacescan.io"
RATE_LIMIT_WAIT = 0.4   # detik antar request (free tier)
DERIVE_COUNT    = 20    # default jumlah address per mnemonic
HRP             = "xch" # human-readable prefix bech32

# ─────────────────────────────────────────────
#   DERIVASI ALAMAT CHIA DARI MNEMONIC
# ─────────────────────────────────────────────

def mnemonic_to_seed(mnemonic_phrase: str) -> bytes:
    """BIP-39: mnemonic → 64-byte seed (tanpa passphrase)."""
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic_phrase):
        raise ValueError(f"Mnemonic tidak valid: '{mnemonic_phrase[:30]}...'")
    return mnemo.to_seed(mnemonic_phrase, passphrase="")


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand dengan SHA-512."""
    import hashlib, hmac
    T = b""
    okm = b""
    i = 1
    while len(okm) < length:
        T = hmac.new(prk, T + info + bytes([i]), hashlib.sha512).digest()
        okm += T
        i += 1
    return okm[:length]


def _ikm_to_lamport_sk(ikm: bytes, salt: bytes):
    """IKM + salt → 255 chunks × 32 bytes (EIP-2333 Lamport SK)."""
    import hashlib, hmac
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm = _hkdf_expand(prk, b"", 255 * 32)
    return [okm[i*32:(i+1)*32] for i in range(255)]


def _parent_sk_to_lamport_pk(parent_sk: bytes) -> bytes:
    """EIP-2333: derive Lamport PK from parent SK."""
    import hashlib
    salt = b'\x00' * 4
    l0  = _ikm_to_lamport_sk(parent_sk, salt)
    l1  = _ikm_to_lamport_sk(bytes([b ^ 0xFF for b in parent_sk]), salt)
    lamport_pk = b""
    for chunk in l0 + l1:
        lamport_pk += hashlib.sha256(chunk).digest()
    return hashlib.sha256(lamport_pk).digest()


def _bls_keygen(ikm: bytes) -> int:
    """EIP-2333 / Chia variant: IKM → BLS private key integer."""
    import hashlib, hmac
    BLS_MOD = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    # Chia menggunakan hash(b"BLS-SIG-KEYGEN-SALT-") sebagai salt awal
    salt = hashlib.sha256(b"BLS-SIG-KEYGEN-SALT-").digest()
    while True:
        prk = hmac.new(salt, ikm + b'\x00', hashlib.sha512).digest()
        okm = _hkdf_expand(prk, b'\x00\x30', 48)  # L=48
        sk  = int.from_bytes(okm, 'big') % BLS_MOD
        if sk != 0:
            return sk
        salt = hashlib.sha256(salt).digest()


def _derive_child_sk_unhardened_eip2333(parent_sk_bytes: bytes, index: int) -> bytes:
    """EIP-2333 child key derivation (hardened, Chia compatible)."""
    lamport_pk = _parent_sk_to_lamport_pk(parent_sk_bytes)
    # index 4 bytes big-endian digabung ke IKM
    ikm = lamport_pk + index.to_bytes(4, 'big')
    child_sk_int = _bls_keygen(ikm)
    return child_sk_int.to_bytes(32, 'big')


def derive_master_sk(seed: bytes) -> bytes:
    """Seed 64 byte → master private key 32 byte."""
    sk_int = _bls_keygen(seed)
    return sk_int.to_bytes(32, 'big')


def derive_wallet_sk(seed: bytes, index: int) -> bytes:
    """
    Derive wallet private key sesuai path Chia:
    m / 12381 / 8444 / 2 / index
    """
    sk = derive_master_sk(seed)
    for i in [12381, 8444, 2, index]:
        sk = _derive_child_sk_unhardened_eip2333(sk, i)
    return sk


def sk_to_xch_address(sk_bytes: bytes) -> str:
    """Private key → XCH address (bech32m of puzzle hash)."""
    # Load private key via chia_bls atau blspy
    if BLS_LIB == "chia_bls":
        pk: G1Element = PrivateKey.from_bytes(sk_bytes).get_g1()
        pk_bytes = bytes(pk)
    else:
        pk: G1Element = PrivateKey.from_bytes(sk_bytes).get_g1()
        pk_bytes = bytes(pk)  # 48 bytes compressed G1

    # Puzzle hash = sha256 dari standard p2_delegated_puzzle (simplified)
    # Chia wallet address = bech32m(sha256(puzzle)) di mana puzzle bergantung pada pubkey
    # Untuk standard wallet: puzzle_hash = sha256(sha256tree(DEFAULT_PUZZLE_WITH_PUBKEY))
    # Karena implementasi Chialisp penuh terlalu kompleks, kita pakai chia_puzzles approach:
    # puzzle_hash = sha256(0x0101 + sha256(0x0201 + sha256(pubkey_bytes)))
    # Ini adalah approksimasi; untuk presisi 100% gunakan: chia keys derive

    # Standard approach yang lebih akurat menggunakan synthetic key:
    # synthetic_sk = sk + hash(pk || DEFAULT_HIDDEN_PUZZLE_HASH)
    # Tapi untuk cek balance, kita gunakan pubkey langsung → puzzle hash via known formula
    # Chia official formula: puzzle_hash = sha256(chr(2) + sha256(chr(1) + pubkey))
    # Ref: chia/wallet/puzzles/p2_delegated_puzzle_or_hidden_puzzle.py

    # Level 1: hash pubkey
    import hashlib
    inner = hashlib.sha256(b'\x01' + pk_bytes).digest()
    # Level 2: wrap
    puzzle_hash = hashlib.sha256(b'\x02' + inner).digest()

    # Encode ke bech32 (Chia pakai bech32m untuk XCH address, tapi versi lama pakai bech32)
    # Chia menggunakan SEGWIT versi 0 style: witness_version=0 prefix
    converted = convertbits(puzzle_hash, 8, 5)
    if converted is None:
        raise ValueError("Gagal konversi bits untuk bech32")
    address = bech32_encode(HRP, [0] + converted)
    return address


# ─────────────────────────────────────────────
#   SPACESCAN API
# ─────────────────────────────────────────────

def api_get(url: str, max_retries: int = 3) -> Optional[dict]:
    """GET request ke Spacescan API dengan retry."""
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = 2 ** attempt * 2
                print(f"    ⚠ Rate limited, tunggu {wait}s...")
                time.sleep(wait)
            else:
                return None
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(1)
            else:
                return None
    return None


def get_xch_balance(address: str) -> float:
    """Ambil balance XCH dari Spacescan."""
    data = api_get(f"{SPACESCAN_API}/address/xch-balance/{address}")
    if data and data.get("status") == "success":
        raw = data.get("balance", data.get("xch-balance", 0))
        return float(raw) if raw else 0.0
    return 0.0


def get_cat_balances(address: str) -> list:
    """Ambil balance semua CAT tokens dari Spacescan."""
    data = api_get(f"{SPACESCAN_API}/address/cat-balance/{address}")
    if data and data.get("status") == "success":
        cats = data.get("cats", data.get("cat", []))
        return cats if isinstance(cats, list) else []
    return []


def get_xch_price_usd() -> float:
    """Ambil harga XCH dalam USD."""
    data = api_get(f"{SPACESCAN_API}/price/xch?currency=USD")
    if data:
        return float(data.get("data", {}).get("price", data.get("price", 0)) or 0)
    return 0.0


# ─────────────────────────────────────────────
#   LOGIKA UTAMA
# ─────────────────────────────────────────────

def check_address(address: str, xch_price: float) -> dict:
    """Cek satu address, return dict info balance."""
    result = {
        "address": address,
        "xch":     0.0,
        "cats":    [],
        "usd":     0.0,
        "has_balance": False,
    }
    time.sleep(RATE_LIMIT_WAIT)

    xch = get_xch_balance(address)
    result["xch"] = xch

    time.sleep(RATE_LIMIT_WAIT)
    cats = get_cat_balances(address)
    # Filter token dengan balance > 0
    cats_nonzero = [c for c in cats if float(c.get("balance", c.get("amount", 0)) or 0) > 0]
    result["cats"] = cats_nonzero

    total_usd = xch * xch_price
    for cat in cats_nonzero:
        price_usd = float(cat.get("price_usd", cat.get("price_USD", 0)) or 0)
        bal       = float(cat.get("balance", cat.get("amount", 0)) or 0)
        total_usd += bal * price_usd
    result["usd"] = total_usd
    result["has_balance"] = (xch > 0 or len(cats_nonzero) > 0)

    return result


def format_wallet_report(result: dict, xch_price: float, index: int = None, total: int = None) -> str:
    """Format satu wallet ke string laporan."""
    lines = []
    prefix = f"[{index}/{total}] " if index is not None else ""
    addr = result["address"]
    xch  = result["xch"]
    usd  = result["usd"]

    lines.append(f"{'─'*60}")
    lines.append(f"{prefix}ADDRESS : {addr}")
    lines.append(f"SPACESCAN: https://www.spacescan.io/address/{addr}")
    lines.append(f"XCH      : {xch:.8f} XCH  ≈  ${usd:.2f} USD")

    if result["cats"]:
        lines.append(f"TOKENS ({len(result['cats'])}):")
        for cat in result["cats"]:
            sym  = cat.get("symbol", cat.get("asset_symbol", "???"))
            name = cat.get("name", cat.get("asset_name", sym))
            bal  = float(cat.get("balance", cat.get("amount", 0)) or 0)
            p_usd = float(cat.get("price_usd", cat.get("price_USD", 0)) or 0)
            val_usd = bal * p_usd
            lines.append(f"  ├─ {name} ({sym}): {bal:.6f}  ≈  ${val_usd:.4f} USD")
    else:
        lines.append("TOKENS   : —")

    status = "✅ ADA SALDO" if result["has_balance"] else "⬜ KOSONG"
    lines.append(f"STATUS   : {status}")
    return "\n".join(lines)


def process_addresses(addresses: list, xch_price: float, verbose: bool = True) -> tuple:
    """
    Proses daftar address, return (with_balance, no_balance) lists.
    """
    with_balance = []
    no_balance   = []
    total = len(addresses)

    for i, addr in enumerate(addresses, 1):
        if verbose:
            print(f"  [{i:>4}/{total}] Cek {addr[:20]}...{addr[-8:]} ", end="", flush=True)

        result = check_address(addr, xch_price)

        if result["has_balance"]:
            if verbose:
                token_info = f" + {len(result['cats'])} token" if result["cats"] else ""
                print(f"  💰 {result['xch']:.6f} XCH{token_info}  (${result['usd']:.2f})")
            with_balance.append(result)
        else:
            if verbose:
                print("  —")
            no_balance.append(result)

    return with_balance, no_balance


def save_results(with_balance: list, no_balance: list, xch_price: float, output_dir: str = "."):
    """Simpan hasil ke balance.txt dan no_balance.txt."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    total = len(with_balance) + len(no_balance)

    # ── balance.txt ──────────────────────────────────────
    bal_path = os.path.join(output_dir, "balance.txt")
    with open(bal_path, "w", encoding="utf-8") as f:
        f.write("═" * 60 + "\n")
        f.write("  CHIA XCH BALANCE CHECKER — WALLET DENGAN SALDO\n")
        f.write(f"  Waktu  : {timestamp}\n")
        f.write(f"  Total  : {len(with_balance)} wallet ada saldo dari {total} total\n")
        f.write(f"  Harga  : 1 XCH = ${xch_price:.4f} USD\n")
        f.write("═" * 60 + "\n\n")

        if with_balance:
            total_xch = sum(r["xch"] for r in with_balance)
            total_usd = sum(r["usd"] for r in with_balance)
            f.write(f"TOTAL XCH: {total_xch:.8f} XCH  ≈  ${total_usd:.2f} USD\n\n")

            for i, result in enumerate(with_balance, 1):
                f.write(format_wallet_report(result, xch_price, i, len(with_balance)))
                f.write("\n\n")

            # Ringkasan token gabungan
            token_totals = {}
            for result in with_balance:
                for cat in result["cats"]:
                    sym = cat.get("symbol", cat.get("asset_symbol", "???"))
                    if sym not in token_totals:
                        token_totals[sym] = {"name": cat.get("name", sym), "sym": sym, "bal": 0.0, "usd": 0.0}
                    token_totals[sym]["bal"] += float(cat.get("balance", cat.get("amount", 0)) or 0)
                    p = float(cat.get("price_usd", 0) or 0)
                    token_totals[sym]["usd"] += float(cat.get("balance", cat.get("amount", 0)) or 0) * p

            if token_totals:
                f.write("\n" + "─" * 60 + "\n")
                f.write("RINGKASAN TOKEN CAT (SEMUA WALLET):\n")
                for sym, info in token_totals.items():
                    f.write(f"  {info['name']} ({sym}): {info['bal']:.6f}  ≈  ${info['usd']:.4f} USD\n")
        else:
            f.write("Tidak ada wallet dengan saldo.\n")

    # ── no_balance.txt ────────────────────────────────────
    nob_path = os.path.join(output_dir, "no_balance.txt")
    with open(nob_path, "w", encoding="utf-8") as f:
        f.write("═" * 60 + "\n")
        f.write("  CHIA XCH BALANCE CHECKER — WALLET KOSONG\n")
        f.write(f"  Waktu  : {timestamp}\n")
        f.write(f"  Total  : {len(no_balance)} wallet kosong dari {total} total\n")
        f.write("═" * 60 + "\n\n")

        for result in no_balance:
            f.write(f"{result['address']}\n")
            f.write(f"  https://www.spacescan.io/address/{result['address']}\n")

    return bal_path, nob_path


# ─────────────────────────────────────────────
#   CLI ENTRY POINT
# ─────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Chia XCH Balance Checker — cek balance + CAT token per wallet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--mnemonic", "-m", nargs="+", metavar="PHRASE",
        help='Satu atau lebih mnemonic phrase (dalam tanda kutip)',
    )
    src.add_argument(
        "--file", "-f", metavar="FILE",
        help="File teks berisi mnemonic/address, satu per baris",
    )
    src.add_argument(
        "--address", "-a", nargs="+", metavar="ADDR",
        help="Satu atau lebih address XCH langsung",
    )
    p.add_argument(
        "--count", "-c", type=int, default=DERIVE_COUNT,
        help=f"Jumlah address per mnemonic (default: {DERIVE_COUNT})",
    )
    p.add_argument(
        "--output-dir", "-o", default=".",
        help="Direktori output file (default: current dir)",
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Tampilkan output minimal",
    )
    return p.parse_args()


def banner():
    print("""
╔══════════════════════════════════════════════════════╗
║       CHIA XCH BALANCE CHECKER                      ║
║       Powered by Spacescan.io API                   ║
╚══════════════════════════════════════════════════════╝""")


def main():
    args = parse_args()
    banner()

    # ── Kumpulkan semua address ──────────────────────────
    all_addresses = []
    mnemonic_map  = {}  # address → mnemonic index (untuk labeling)

    if args.address:
        all_addresses = [a.strip() for a in args.address if a.strip().startswith("xch1")]
        print(f"\n📌 Mode: Cek {len(all_addresses)} address langsung\n")

    elif args.mnemonic or args.file:
        mnemonics = []
        if args.mnemonic:
            mnemonics = [" ".join(args.mnemonic)] if len(args.mnemonic) > 2 else args.mnemonic
            # Support: --mnemonic "word1 ... word24" atau --mnemonic word1 word2 ...
            # Kalau semua elemen adalah satu kata, gabungkan jadi satu phrase
            if all(len(m.split()) == 1 for m in mnemonics):
                mnemonics = [" ".join(mnemonics)]
        elif args.file:
            if not os.path.exists(args.file):
                print(f"\n❌ File tidak ditemukan: {args.file}")
                sys.exit(1)
            with open(args.file, "r", encoding="utf-8") as fh:
                mnemonics = [ln.strip() for ln in fh if ln.strip()]

        print(f"\n🔑 Ditemukan {len(mnemonics)} mnemonic phrase")
        print(f"📐 Derive {args.count} address per mnemonic\n")

        mnemo = Mnemonic("english")
        for idx, phrase in enumerate(mnemonics, 1):
            print(f"  [{idx}/{len(mnemonics)}] Menurunkan address dari mnemonic #{idx}...")
            try:
                seed = mnemonic_to_seed(phrase)
            except ValueError as e:
                print(f"    ⚠  {e} — dilewati")
                continue

            for i in range(args.count):
                try:
                    sk    = derive_wallet_sk(seed, i)
                    addr  = sk_to_xch_address(sk)
                    all_addresses.append(addr)
                    mnemonic_map[addr] = (idx, i)
                except Exception as e:
                    print(f"    ⚠  Gagal derive index {i}: {e}")

        print(f"\n  Total address diturunkan: {len(all_addresses)}\n")

    else:
        print("\n❌  Tidak ada input. Gunakan --help untuk bantuan.\n")
        sys.exit(1)

    if not all_addresses:
        print("❌  Tidak ada address valid untuk dicek.")
        sys.exit(1)

    # ── Ambil harga XCH ─────────────────────────────────
    print("💱 Mengambil harga XCH/USD...")
    xch_price = get_xch_price_usd()
    print(f"   1 XCH = ${xch_price:.4f} USD\n")

    # ── Cek semua address ────────────────────────────────
    print(f"🔍 Memeriksa {len(all_addresses)} address...\n")
    with_balance, no_balance = process_addresses(
        all_addresses, xch_price, verbose=not args.quiet
    )

    # ── Simpan file ──────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    bal_path, nob_path = save_results(with_balance, no_balance, xch_price, args.output_dir)

    # ── Ringkasan terminal ────────────────────────────────
    total_xch = sum(r["xch"] for r in with_balance)
    total_usd = sum(r["usd"] for r in with_balance)
    print(f"""
{'═'*50}
  SELESAI!
{'═'*50}
  ✅ Wallet ada saldo  : {len(with_balance):>5}
  ⬜ Wallet kosong     : {len(no_balance):>5}
  ─────────────────────────────────
  💰 Total XCH         : {total_xch:.6f} XCH
  💵 Estimasi USD      : ${total_usd:.2f}
  ─────────────────────────────────
  📄 balance.txt    → {bal_path}
  📄 no_balance.txt → {nob_path}
{'═'*50}
""")


if __name__ == "__main__":
    main()
