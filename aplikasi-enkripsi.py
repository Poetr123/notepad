#!/usr/bin/env python3
"""
Aplikasi Notepad Terenkripsi

Fitur:
- Enkripsi / Dekrip text
- Buat / List / Buka / Edit / Hapus note
- Hapus note tanpa password, hanya konfirmasi judul
- Audit log (tanpa timestamp)
- Autentikasi catatan menggunakan password_cipher_hex (bukan plaintext)
"""

# ======================================================================
# CONFIG
# ======================================================================

DB_FILE = "notes_db.pmv"
DB_HEADER = "NOTES0"
AUDIT_FILE = "audit_log.txt"

ITERATIONS = 1500
VERIFIER_MAGIC = "__VERIFIER__"

# ======================================================================
# UTILS
# ======================================================================

def _to_bytes(s):
    if isinstance(s, bytes):
        return s
    return str(s).encode("utf-8")

def _from_bytes(b):
    try:
        return b.decode("utf-8")
    except Exception:
        return str(b)

def _escape(s):
    if s is None:
        s = ""
    s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace("\t", "\\t")
    s = s.replace("\n", "\\n")
    return s

def _unescape(s):
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\\\\", "\\")
    s = s.replace("\\t", "\t")
    s = s.replace("\\n", "\n")
    return s

# ======================================================================
# SALT & KEYSTREAM
# ======================================================================

def _make_salt(password, hint=""):
    s = str(password)
    total = 0
    for c in s:
        total += ord(c)
    hint_len = 0
    try:
        hint_len = len(str(hint))
    except:
        pass
    return "SALT" + str((total ^ (hint_len * 1234567)) & 0xffffffff)

def derive_key_stream(key, salt, length, iterations=ITERATIONS):
    seed = 0

    k = str(key)
    for i, ch in enumerate(k):
        seed = (seed * 1315423911) ^ (ord(ch) + i)

    s = str(salt)
    for i, ch in enumerate(s):
        seed = (seed * 2654435761) ^ (ord(ch) + i)

    state = seed & 0xffffffff
    a = 1664525
    c = 1013904223
    mod = 2**32

    for _ in range(iterations):
        state = (a * state + c) % mod

    out = bytearray()
    while len(out) < length:
        state = (a * state + c) % mod
        x = ((state >> 16) ^ state) & 0xffffffff
        out.append((x >> 0) & 0xff)
        if len(out) < length:
            out.append((x >> 8) & 0xff)
        if len(out) < length:
            out.append((x >> 16) & 0xff)
        if len(out) < length:
            out.append((x >> 24) & 0xff)

    return bytes(out[:length])

def xor_bytes(data, ks):
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ ks[i % len(ks)]
    return bytes(out)

# ======================================================================
# ENCRYPT / DECRYPT
# ======================================================================

def encrypt_text_with_password(plaintext, password, salt=None, iterations=ITERATIONS):
    if salt is None:
        salt = _make_salt(password, plaintext)
    pb = _to_bytes(plaintext)
    ks = derive_key_stream(password, salt, len(pb), iterations)
    cipher = xor_bytes(pb, ks)
    return cipher.hex(), salt, iterations

def decrypt_text_with_password(cipher_hex, password, salt, iterations):
    try:
        cb = bytes.fromhex(cipher_hex)
    except:
        return None
    ks = derive_key_stream(password, salt, len(cb), iterations)
    plain = xor_bytes(cb, ks)
    try:
        return plain.decode("utf-8")
    except:
        return _from_bytes(plain)

# ======================================================================
# DB
# ======================================================================

def load_db():
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except:
        return []

    if not lines or lines[0].strip() != DB_HEADER:
        return []

    entries = []
    for ln in lines[1:]:
        if not ln:
            continue
        cols = ln.split("\t")
        if len(cols) < 7:
            continue
        try:
            nid = int(cols[0])
        except:
            continue
        entries.append({
            "id": nid,
            "title": _unescape(cols[1]),
            "cipher_hex": cols[2],
            "salt": cols[3],
            "iterations": int(cols[4]),
            "verifier_hex": cols[5],
            "pass_cipher_hex": cols[6],
        })
    return entries

def save_db(entries):
    out = [DB_HEADER]
    for e in entries:
        row = (
            str(e["id"]) + "\t" +
            _escape(e["title"]) + "\t" +
            e["cipher_hex"] + "\t" +
            e["salt"] + "\t" +
            str(e["iterations"]) + "\t" +
            e["verifier_hex"] + "\t" +
            e["pass_cipher_hex"]
        )
        out.append(row)
    with open(DB_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

def _next_id(entries):
    mx = 0
    for e in entries:
        if e["id"] > mx:
            mx = e["id"]
    return mx + 1

# ======================================================================
# AUDIT LOG (TANPA TIMESTAMP)
# ======================================================================

def _append_audit(action, nid, title):
    row = action + "\t" + str(nid) + "\t" + _escape(title)
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(row + "\n")
    except:
        pass

def op_view_audit():
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except:
        print("Audit log kosong.")
        return
    if not lines:
        print("Audit log kosong.")
        return

    print("--- AUDIT LOG ---")
    for ln in lines:
        cols = ln.split("\t")
        if len(cols) < 3:
            print(ln)
            continue
        action, nid, title = cols[0], cols[1], _unescape(cols[2])
        print(action, "| ID:", nid, "|", title)
    print("--- END ---")

# ======================================================================
# VERIFIER
# ======================================================================

def _make_verifier(pass_cipher_hex, salt, it):
    v, _, _ = encrypt_text_with_password(VERIFIER_MAGIC, pass_cipher_hex, salt, it)
    return v

def _check_pass_cipher(pass_cipher_hex, salt, it, verifier_hex):
    plain = decrypt_text_with_password(verifier_hex, pass_cipher_hex, salt, it)
    return plain == VERIFIER_MAGIC

# ======================================================================
# OPERATIONS
# ======================================================================

def op_encrypt_text():
    print("== Enkripsi Text ==")
    text = input("Text: ")
    pw_plain = input("Password plaintext: ").strip()

    pass_cipher_hex, _, _ = encrypt_text_with_password(pw_plain, pw_plain)
    cipher_hex, salt, it = encrypt_text_with_password(text, pass_cipher_hex)
    verifier = _make_verifier(pass_cipher_hex, salt, it)

    print("\n--- OUTPUT ---")
    print("password_cipher_hex:", pass_cipher_hex)
    print("ciphertext_hex:", cipher_hex)
    print("salt:", salt)
    print("iterations:", it)
    print("verifier_hex:", verifier)

def op_decrypt_text():
    print("== Dekrip Text ==")
    ch = input("Ciphertext HEX: ").strip()
    salt = input("Salt: ").strip()
    try:
        it = int(input("Iterations: ").strip())
    except:
        it = ITERATIONS
    pch = input("password_cipher_hex: ").strip()
    verifier = input("verifier_hex: ").strip()

    if not _check_pass_cipher(pch, salt, it, verifier):
        print("Password cipher salah.")
        return

    plain = decrypt_text_with_password(ch, pch, salt, it)
    print("\n--- PLAINTEXT ---")
    print(plain)

def op_create_note():
    print("== Buat Catatan ==")
    title = input("Judul: ").strip()
    body = input("Isi catatan: ")
    pw_plain = input("Password plaintext: ").strip()

    pass_cipher_hex, _, _ = encrypt_text_with_password(pw_plain, pw_plain)
    ch, salt, it = encrypt_text_with_password(body, pass_cipher_hex)
    verifier = _make_verifier(pass_cipher_hex, salt, it)

    entries = load_db()
    nid = _next_id(entries)

    entries.append({
        "id": nid,
        "title": title,
        "cipher_hex": ch,
        "salt": salt,
        "iterations": it,
        "verifier_hex": verifier,
        "pass_cipher_hex": pass_cipher_hex
    })

    save_db(entries)

    print("\nCatatan dibuat.")
    print("ID:", nid)
    print("password_cipher_hex:", pass_cipher_hex)
    print("ciphertext_hex:", ch)
    print("salt:", salt)
    print("iterations:", it)
    print("verifier_hex:", verifier)

def op_list_notes():
    entries = load_db()
    if not entries:
        print("Belum ada catatan.")
        return
    print("Daftar catatan:")
    for e in entries:
        print("ID:", e["id"], "|", e["title"])

def op_open_note():
    entries = load_db()
    if not entries:
        print("Belum ada catatan.")
        return

    try:
        nid = int(input("ID catatan: ").strip())
    except:
        print("ID invalid.")
        return

    for e in entries:
        if e["id"] == nid:
            pch = input("password_cipher_hex: ").strip()
            if pch != e["pass_cipher_hex"]:
                print("Password cipher salah.")
                return

            if not _check_pass_cipher(pch, e["salt"], e["iterations"], e["verifier_hex"]):
                print("Verifikasi gagal.")
                return

            plain = decrypt_text_with_password(e["cipher_hex"], pch, e["salt"], e["iterations"])
            print("\n--- ISI CATATAN ---")
            print(plain)
            print("--- END ---")
            return

    print("Catatan tidak ditemukan.")

def op_edit_note():
    entries = load_db()
    if not entries:
        print("Belum ada catatan.")
        return

    try:
        nid = int(input("ID catatan: ").strip())
    except:
        print("ID invalid.")
        return

    for i, e in enumerate(entries):
        if e["id"] == nid:
            pch = input("password_cipher_hex: ").strip()
            if pch != e["pass_cipher_hex"]:
                print("Password cipher salah.")
                return

            if not _check_pass_cipher(pch, e["salt"], e["iterations"], e["verifier_hex"]):
                print("Verifikasi gagal.")
                return

            new_title = input("Judul baru (kosong = tidak ubah): ").strip()
            new_body = input("Isi baru (kosong = tidak ubah): ")

            if new_title:
                e["title"] = new_title

            if new_body:
                ch, salt, it = encrypt_text_with_password(new_body, pch)
                e["cipher_hex"] = ch
                e["salt"] = salt
                e["iterations"] = it
                e["verifier_hex"] = _make_verifier(pch, salt, it)

            entries[i] = e
            save_db(entries)
            print("Catatan diperbarui.")
            return

    print("Catatan tidak ditemukan.")

def op_delete_note():
    entries = load_db()
    if not entries:
        print("Belum ada catatan.")
        return

    try:
        nid = int(input("ID catatan untuk dihapus: ").strip())
    except:
        print("ID invalid.")
        return

    for i, e in enumerate(entries):
        if e["id"] == nid:
            confirm = input("Ketik judul catatan persis: ").strip()
            if confirm != e["title"]:
                print("Judul tidak cocok. Batal.")
                return

            _append_audit("DELETE", e["id"], e["title"])
            entries.pop(i)
            save_db(entries)
            print("Catatan dihapus. Tercatat di audit log.")
            return

    print("Catatan tidak ditemukan.")

# ======================================================================
# MAIN MENU
# ======================================================================

def main():
    while True:
        print("\n=== MENU UTAMA ===")
        print("1 = Enkripsi text")
        print("2 = Dekrip text")
        print("3 = Buat catatan")
        print("4 = Daftar catatan")
        print("5 = Buka catatan")
        print("6 = Edit catatan")
        print("7 = Hapus catatan")
        print("8 = Lihat audit log")
        print("9 = Keluar")

        c = input("Pilih nomor: ").strip()

        if c == "1":
            op_encrypt_text()
        elif c == "2":
            op_decrypt_text()
        elif c == "3":
            op_create_note()
        elif c == "4":
            op_list_notes()
        elif c == "5":
            op_open_note()
        elif c == "6":
            op_edit_note()
        elif c == "7":
            op_delete_note()
        elif c == "8":
            op_view_audit()
        elif c == "9":
            print("Bye.")
            return
        else:
            print("Pilihan tidak dikenali.")

if __name__ == "__main__":
    main()
