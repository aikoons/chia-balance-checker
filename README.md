# 🌿 Chia XCH Balance Checker

Cek balance XCH + semua CAT token per wallet dari mnemonic phrase atau address langsung.
Export otomatis ke `balance.txt` dan `no_balance.txt`.

---

## 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

Atau manual:
```bash
pip install mnemonic chia-bls bech32 requests
```

> **Windows:** Jika `chia-bls` gagal, coba: `pip install blspy` (fallback otomatis).

---

## 🚀 Cara Pakai

### 1. Cek dari Mnemonic Phrase (24 kata)

```bash
python chia_balance_checker.py --mnemonic "word1 word2 word3 ... word24"
```

Script akan otomatis menurunkan 20 address pertama dari mnemonic dan cek balance-nya.

### 2. Jumlah Address yang Di-derive (default: 20)

```bash
python chia_balance_checker.py --mnemonic "word1 ... word24" --count 50
```

> Rekomendasi: mulai dari 20–50. Kalau saldo tidak ketemu, coba naikkan ke 100.

### 3. Banyak Mnemonic dari File

Buat file `mnemonics.txt`, isi satu mnemonic per baris:

```
word1 word2 word3 ... word24
apple banana cherry ... lastword
...
```

Lalu jalankan:
```bash
python chia_balance_checker.py --file mnemonics.txt --count 30
```

### 4. Cek Address Langsung (tanpa mnemonic)

```bash
python chia_balance_checker.py --address xch1abc... xch1def...
```

### 5. Output ke Folder Tertentu

```bash
python chia_balance_checker.py --mnemonic "..." --output-dir ./hasil
```

---

## 📁 Output

| File | Isi |
|------|-----|
| `balance.txt` | Semua wallet yang ada saldo XCH atau token, beserta detail dan valuasi USD |
| `no_balance.txt` | Daftar address yang kosong |

### Contoh `balance.txt`:

```
════════════════════════════════════════════════════════════
  CHIA XCH BALANCE CHECKER — WALLET DENGAN SALDO
  Waktu  : 2025-01-15 10:30:00
  Total  : 3 wallet ada saldo dari 40 total
  Harga  : 1 XCH = $32.50 USD
════════════════════════════════════════════════════════════

TOTAL XCH: 12.34567800 XCH  ≈  $401.23 USD

────────────────────────────────────────────────────────────
[1/3] ADDRESS : xch1ztyl7vjt4mgh5vp492537n6uyls40afxg5vll82jtnqz9f8jlpmqegfrpg
SPACESCAN: https://www.spacescan.io/address/xch1ztyl7...
XCH      : 10.12345600 XCH  ≈  $329.01 USD
TOKENS (2):
  ├─ Marmot (MRMT): 500.000000  ≈  $12.5000 USD
  ├─ ShibaInu (SHIB): 1000.00  ≈  $0.0010 USD
STATUS   : ✅ ADA SALDO
```

---

## ⚠️ Keamanan

- **Script berjalan 100% offline untuk derivasi key.** Mnemonic phrase tidak pernah dikirim ke server manapun.
- Request hanya ke `api.spacescan.io` untuk mengambil data balance (public blockchain data).
- **Jangan bagikan mnemonic phrase ke siapapun atau memasukkannya di komputer yang tidak aman.**
- Simpan file `balance.txt` di tempat yang aman.

---

## 🛠 Troubleshooting

**Error: `chia-bls` gagal install**
```bash
pip install blspy
# Script akan otomatis deteksi dan menggunakan blspy
```

**Error: Rate limited oleh API**
Script sudah handle otomatis dengan delay dan retry. Jika masih error, tambah delay di kode:
```python
RATE_LIMIT_WAIT = 1.0  # naikkan dari 0.4 ke 1.0
```

**Address yang diturunkan tidak match dengan wallet Chia**
Chia menggunakan BLS12-381 dengan path `m/12381/8444/2/index`. Pastikan mnemonic 24 kata.
Coba naikkan `--count` karena wallet mungkin menggunakan index yang lebih tinggi.

---

## 📊 API yang Digunakan

- `GET https://api.spacescan.io/address/xch-balance/{address}` — Balance XCH
- `GET https://api.spacescan.io/address/cat-balance/{address}` — Balance CAT tokens  
- `GET https://api.spacescan.io/price/xch?currency=USD` — Harga XCH
