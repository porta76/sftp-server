"""WPA2 handshake cracker - tests password strength against captured handshake.

For testing YOUR OWN network security only.

Handshake source: plain.pcapng, frames 2027-2032
  Network: Kent2
  AP MAC:  90:9a:4a:f8:04:e3
  Client:  dc:a6:32:b0:34:cd (hacklab-pi4)
  Key Descriptor Version: 2 (AES Cipher, HMAC-SHA1 MIC)
"""

import hashlib
import hmac
import struct
import sys
import os
from datetime import datetime

# ─── Handshake data from plain.pcapng (frames 2027-2032) ───

SSID = "Kent2"
AP_MAC = bytes.fromhex("909a4af804e3")
STA_MAC = bytes.fromhex("dca632b034cd")

# ANonce from Message 1 (frame 2027)
ANONCE = bytes.fromhex(
    "5a61b367e840023f2e8e714caf89855ace75cab060f7b5eef9fb4399f26c2b54"
)

# SNonce from Message 2 (frame 2028)
SNONCE = bytes.fromhex(
    "5f6475a64fb6d7e0cd22a06c73c168314407a4e9f821000f836d8575320df8f7"
)

# MIC from Message 2 (16 bytes)
MIC_M2 = bytes.fromhex("e796e7ec0c1813092c1f5689f6781188")

# Full EAPOL-Key frame from Message 2 with MIC zeroed.
# Key Descriptor Version 2, 2-byte Key Length field.
EAPOL_M2_DATA = bytes.fromhex(
    "01030075"          # EAPOL: version=1, type=3 (Key), length=117
    "02"                # Key Descriptor Type = 2 (RSN)
    "010a"              # Key Information = 0x010a
    "0000"              # Key Length = 0 (2 bytes)
    "0000000000000001"  # Replay Counter = 1 (8 bytes)
    "5f6475a64fb6d7e0cd22a06c73c168314407a4e9f821000f836d8575320df8f7"  # SNonce
    "00000000000000000000000000000000"  # Key IV
    "0000000000000000"  # Key RSC
    "0000000000000000"  # Key ID
    "00000000000000000000000000000000"  # MIC (zeroed)
    "0016"              # Key Data Length = 22
    "30140100000fac040100000fac040100000fac028000"  # Key Data (RSN IE)
)


def pbkdf2_password_to_pmk(password: str, ssid: str) -> bytes:
    """Derive the PMK (Pairwise Master Key) from password and SSID."""
    return hashlib.pbkdf2_hmac(
        "sha1", password.encode("utf-8"), ssid.encode("utf-8"), 4096, 32
    )


def prf_512(key: bytes, label: str, data: bytes) -> bytes:
    """WPA2 PRF - generates 512 bits (64 bytes) of PTK."""
    result = b""
    for i in range(4):
        b = struct.pack("B", i)
        result += hmac.new(
            key, label.encode("ascii") + b"\x00" + data + b, hashlib.sha1
        ).digest()
    return result[:64]


def derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce):
    """Derive the PTK from PMK and handshake parameters."""
    mac_pair = min(ap_mac, sta_mac) + max(ap_mac, sta_mac)
    nonce_pair = min(anonce, snonce) + max(anonce, snonce)
    return prf_512(pmk, "Pairwise key expansion", mac_pair + nonce_pair)


def compute_mic(ptk, eapol_data):
    """Compute MIC using KCK (first 16 bytes of PTK).
    Key Descriptor Version 2 = HMAC-SHA1 truncated to 16 bytes.
    """
    kck = ptk[:16]
    return hmac.new(kck, eapol_data, hashlib.sha1).digest()[:16]


def try_password(password):
    """Try a password. Returns (matched, pmk, ptk)."""
    pmk = pbkdf2_password_to_pmk(password, SSID)
    ptk = derive_ptk(pmk, AP_MAC, STA_MAC, ANONCE, SNONCE)
    computed_mic = compute_mic(ptk, EAPOL_M2_DATA)
    return computed_mic == MIC_M2, pmk, ptk


def generate_wordlist():
    """Common weak WiFi passwords."""
    return [
        "password", "Password", "PASSWORD",
        "12345678", "123456789", "1234567890",
        "password1", "password123",
        "admin", "admin123",
        "qwerty", "qwerty123",
        "abc12345", "abcd1234",
        "kent", "Kent", "kent2", "Kent2", "kent123",
        "telia", "Telia",
        "sommar", "vinter", "hejhej123",
        "Hemligt123", "hemligt",
        "enlitenapa", "enlitenapa1", "Enitenapa",
        "11111111", "00000000", "aaaaaaaa",
        "test1234", "testtest",
        "anders", "anders123",
        "kalle", "kalle123",
        "home1234", "wifi1234",
        "welcome", "welcome1",
        "letmein", "letmein123",
        "monkey", "monkey123",
        "dragon", "dragon123",
        "master", "master123",
        "login", "login123",
        "princess", "princess1",
        "solo", "solo123",
        "passw0rd", "P@ssw0rd",
        "trustno1",
    ]


def main():
    print("=" * 60)
    print("  WPA2 Handshake Cracker - Password Strength Tester")
    print("=" * 60)
    print()
    print(f"SSID:       {SSID}")
    print(f"AP MAC:     {AP_MAC.hex(':')}")
    print(f"Client MAC: {STA_MAC.hex(':')}")
    print(f"ANonce:     {ANONCE.hex()}")
    print(f"SNonce:     {SNONCE.hex()}")
    print(f"MIC (M2):   {MIC_M2.hex()}")
    print(f"EAPOL len:  {len(EAPOL_M2_DATA)} bytes")
    print()

    # Mode 1: Test a single password
    if len(sys.argv) == 2 and sys.argv[1] != "--wordlist":
        password = sys.argv[1]
        print(f"Testing single password: '{password}'")
        start = datetime.now()
        found, pmk, ptk = try_password(password)
        elapsed = (datetime.now() - start).total_seconds()
        if found:
            print(f"  ✅ PASSWORD FOUND: '{password}'")
            print(f"     PMK: {pmk.hex()}")
            print(f"     PTK: {ptk.hex()}")
        else:
            print(f"  ❌ Password '{password}' does NOT match.")
        print(f"  Time: {elapsed:.3f}s")
        return

    # Mode 2: Custom wordlist
    if len(sys.argv) == 3 and sys.argv[1] == "--wordlist":
        wordlist_file = sys.argv[2]
        if not os.path.exists(wordlist_file):
            print(f"Error: Wordlist '{wordlist_file}' not found.")
            return
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        # Mode 3: Built-in wordlist
        passwords = generate_wordlist()

    print(f"Testing {len(passwords)} passwords...")
    print()

    start = datetime.now()
    tested = 0
    found = False

    for password in passwords:
        tested += 1
        if tested % 10 == 0:
            elapsed = (datetime.now() - start).total_seconds()
            rate = tested / elapsed if elapsed > 0 else 0
            print(f"  ...tested {tested}/{len(passwords)} ({rate:.1f} pwd/s)")

        matched, pmk, ptk = try_password(password)
        if matched:
            print(f"  ✅ PASSWORD FOUND: '{password}'")
            print(f"     PMK: {pmk.hex()}")
            print(f"     PTK: {ptk.hex()}")
            found = True
            break

    elapsed = (datetime.now() - start).total_seconds()
    print()
    print(f"Tested {tested} passwords in {elapsed:.2f}s ({tested/elapsed:.1f} pwd/s)")

    if found:
        print("⚠️  Your WiFi password is WEAK — it was found in the wordlist!")
    else:
        print("✅ Your WiFi password was NOT found in the wordlist.")


if __name__ == "__main__":
    main()