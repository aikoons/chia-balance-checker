# 🌿 Chia XCH Balance Checker v2

Cek balance XCH + semua CAT token dari **address.txt** atau **mnemonic.txt**,
dengan **proxy rotation** untuk menghindari rate-limit Spacescan API.

---

## 📦 Install

```bash
pip install -r requirements.txt
```

Atau manual:
```bash
pip install requests mnemonic chia-bls bech32
```

> **Windows:** Jika `chia-bls` gagal → `pip install blspy` (fallback otomatis).
> **SOCKS5:** Tambah `pip install requests[socks]`

---

## 🚀 Cara Pakai

### Cek dari file address (paling umum)
```bash
python chia_balance_checker.py --address-file address.txt
```

### Cek dari file mnemonic
```bash
python chia_balance_checker.py --mnemonic-file mnemonic.txt
```

### Dengan proxy (anti rate-limit) + lebih banyak thread
```bash
python chia_balance_checker.py \
    --address-file address.txt \
    --proxy-file proxies.txt \
    --threads 5
```

### Input file campur address + mnemonic (auto-detect per baris)
```bash
python chia_balance_checker.py --input-file semua.txt --proxy-file proxies.txt
```

### Derive lebih banyak address per mnemonic
```bash
python chia_balance_checker.py --mnemonic-file mnemonic.txt --count 50
```

### Kombinasi semua input sekaligus
```bash
python chia_balance_checker.py \
    --address-file address.txt \
    --mnemonic-file mnemonic.txt \
    --address xch1abc... xch1def... \
    --proxy-file proxies.txt \
    --threads 8 \
    --count 30 \
    --output-dir ./hasil
```

---

## 📄 Format File

**address.txt** — satu address per baris:
```
xch1ztyl7vjt4mgh5vp492537n6uyls40afxg5vll82jtnqz9f8jlpmqegfrpg
xch1abc123...
xch1def456...
```

**mnemonic.txt** — satu mnemonic per baris (12 atau 24 kata):
```
word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
apple banana cherry delta echo foxtrot golf hotel india juliet kilo lima ...
```

**proxies.txt** — satu proxy per baris:
```
http://123.45.67.89:8080
http://user:pass@proxy.example.com:3128
socks5://10.0.0.1:1080
socks5://alice:secret@proxy2.example.com:1080
45.67.89.12:3128
```

**semua.txt** (auto-detect per baris — campur address & mnemonic):
```
xch1ztyl7vjt4mgh5vp492537n6uyls40afxg5vll82jtnqz9f8jlpmqegfrpg
word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
xch1abc123...
apple banana cherry delta echo foxtrot golf hotel india juliet kilo lima ...
```

---

## 🔀 Proxy Rotation

Script secara otomatis:
- **Rotasi proxy** round-robin untuk setiap request
- **Blacklist** proxy yang gagal ≥5 kali
- **Retry** dengan backoff eksponensial jika kena rate-limit (429)
- Tampilkan **statistik** tiap proxy (✓ sukses / ✗ gagal) di akhir run

Proxy gratis (kualitas bervariasi):
- https://www.proxyscrape.com/free-proxy-list
- https://www.proxy-list.download
- https://spys.one/en/

> Untuk hasil terbaik, gunakan proxy premium/private. Proxy gratis sering lambat/mati.

---

## ⚙️ Semua Flag

| Flag | Shortcut | Fungsi |
|------|----------|--------|
| `--address-file FILE` | `-A` | Import file address |
| `--mnemonic-file FILE` | `-M` | Import file mnemonic |
| `--input-file FILE` | `-I` | Import file campur (auto-detect) |
| `--address ADDR...` | `-a` | Address langsung di CLI |
| `--mnemonic WORD...` | `-m` | Mnemonic langsung di CLI |
| `--count N` | `-c` | Jumlah address per mnemonic (default: 20) |
| `--proxy-file FILE` | `-P` | File daftar proxy |
| `--proxy PROXY...` | | Proxy langsung di CLI |
| `--delay DETIK` | | Override delay antar request |
| `--threads N` | `-t` | Jumlah thread (default: 3) |
| `--output-dir DIR` | `-o` | Folder output (default: `.`) |
| `--quiet` | `-q` | Minimal output |

---

## 📁 Output

| File | Isi |
|------|-----|
| `balance.txt` | Detail tiap wallet yang ada saldo: XCH + token + valuasi USD |
| `no_balance.txt` | Daftar semua address kosong |

Contoh `balance.txt`:
```
════════════════════════════════════════════════════════════════
  CHIA XCH BALANCE CHECKER v2 — WALLET DENGAN SALDO
  Waktu    : 2025-01-15 10:30:00
  Wallet   : 3 wallet ada saldo
  XCH/USD  : $32.5000
════════════════════════════════════════════════════════════════

GRAND TOTAL : 12.34567800 XCH  ≈  $401.23 USD

TOKEN CAT GABUNGAN (SEMUA WALLET):
  ├─ Marmot                           500.000000 MRMT      ≈  $12.5000

────────────────────────────────────────────────────────────────
[1/3] xch1ztyl7vjt4mgh5vp492537n6uyls40afxg5vll82jtnqz9f8jlpmqegfrpg  [mnemonic #1, derive idx 0]
  Explorer : https://www.spacescan.io/address/xch1ztyl7...
  XCH      : 10.12345600 XCH  ≈  $329.0000 USD
  TOKENS (1):
    ├─ Marmot (MRMT): 500.000000  ≈  $12.500000 USD
```

---

## ⚠️ Keamanan

- Derivasi key BLS12-381 berjalan **100% lokal** — mnemonic tidak pernah keluar dari komputermu
- Hanya request ke `api.spacescan.io` untuk balance (data publik blockchain)
- Jangan jalankan di komputer yang tidak dipercaya
- Jangan share file `balance.txt` yang berisi address dengan saldo besar

---

## 🛠 Troubleshooting

**`chia-bls` gagal install:**
```bash
pip install blspy  # fallback, otomatis terdeteksi
```

**Error SOCKS5:**
```bash
pip install requests[socks]
```

**Masih rate-limited walaupun pakai proxy:**
- Tambah `--delay 2.0`
- Kurangi `--threads` ke 1–2
- Gunakan proxy premium, bukan proxy gratis

**Address tidak cocok dengan wallet Chia:**
- Pastikan mnemonic 12 atau 24 kata BIP-39 bahasa Inggris
- Coba naikkan `--count` (default 20 mungkin belum cukup)
- Beberapa wallet pakai index tinggi (coba `--count 100`)