#!/usr/bin/env python3
"""
Ninebot Max G3 - BLE Connect & Get Serial Number
=================================================

Portiert aus der echten App-Logik (index-DtXiOxd1.js, Klassen `Fo`/`Io`
im Original). Die dort verwendete Verschlüsselung ("nbc") ist das
öffentlich dokumentierte NinebotCrypto-Protokoll (majsi/scooterhacking).

pip install bleak pycryptodome
python max_g3_sn.py                       # scannt
python max_g3_sn.py C1:6B:5E:D4:2D:D8      # verbindet + pairt + zeigt SN
"""

import asyncio
import struct
import sys

from Crypto.Cipher import AES
from bleak import BleakClient, BleakScanner
import hashlib

UART_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
UART_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
UART_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

# Adressen (aus dem "Y" enum im Bundle)
ADDR_MOTOR = 1
ADDR_MCU = 2
ADDR_BLE = 4
ADDR_BMS = 7
ADDR_VCU = 22       # 0x16
ADDR_ESC = 32
ADDR_BLE_LEGACY = 33
ADDR_BMS_LEGACY = 34
ADDR_EXTBMS = 35
ADDR_HOST = 62       # 0x3E - das ist "wir" (die App/dieses Skript)

JO = bytes([151, 207, 184, 2, 132, 65, 67, 222, 86, 0, 43, 59, 52, 120, 10, 93])


# ---------------------------------------------------------------------------
# Krypto-Primitiven (1:1 aus Mo/No/Po im Bundle)
# ---------------------------------------------------------------------------
def aes_ecb_block(key: bytes, block: bytes) -> bytes:
    """entspricht Mo(): AES-CBC mit Zero-IV auf genau 1 Block == AES-ECB."""
    assert len(key) == 16 and len(block) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def sha1_key(a: bytes, b: bytes) -> bytes:
    """entspricht Po(): sha1(a||b)[:16], a und b je 16 Byte."""
    assert len(a) == 16 and len(b) == 16
    return hashlib.sha1(a + b).digest()[:16]


def u32be(n: int) -> bytes:
    return struct.pack(">I", n & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# NBC - Port der Klasse `Fo`
# ---------------------------------------------------------------------------
class Nbc:
    def __init__(self, name: str):
        n = name.encode("utf-8")[:16]
        self.name_data = n + b"\x00" * (16 - len(n))
        self.ble_data = bytes(16)
        self.app_data = bytes(16)
        self.sha1 = sha1_key(self.name_data, JO)
        self.msg_it = 0
        self.peer_addr = 0
        self.initial_key_tail = bytes(14)
        self.initial_key_received = False
        self.recalc_received = False
        self.paired_received = False

    def set_app_data(self, data: bytes):
        assert len(data) == 16
        self.app_data = data

    def crypto_first(self, data: bytes) -> bytes:
        keystream = aes_ecb_block(self.sha1, JO)
        out = bytearray(len(data))
        for off in range(0, len(data), 16):
            chunk_len = min(16, len(data) - off)
            for i in range(chunk_len):
                out[off + i] = data[off + i] ^ keystream[i]
        return bytes(out)

    def crypto_next(self, data: bytes, counter: int) -> bytes:
        out = bytearray(len(data))
        block_idx = 0
        for off in range(0, len(data), 16):
            block_idx += 1
            nonce = bytearray(16)
            nonce[0] = 1
            nonce[1:5] = u32be(counter)
            nonce[5:13] = self.ble_data[0:8]
            nonce[15] = block_idx & 0xFF
            keystream = aes_ecb_block(self.sha1, bytes(nonce))
            chunk_len = min(16, len(data) - off)
            for i in range(chunk_len):
                out[off + i] = data[off + i] ^ keystream[i]
        return bytes(out)

    def compute_mac(self, packet: bytes, counter: int) -> bytes:
        n = len(packet) - 3
        r = bytearray(16)
        r[0] = 89
        r[1:5] = u32be(counter)
        r[5:13] = self.ble_data[0:8]
        r[15] = n & 0xFF
        mac_state = aes_ecb_block(self.sha1, bytes(r))

        a = bytearray(16)
        a[0:3] = packet[0:3]
        mac_state = aes_ecb_block(self.sha1, xor16(bytes(a), mac_state))

        off = 0
        while off < n:
            chunk = min(16, n - off)
            a = bytearray(16)
            a[0:chunk] = packet[3 + off:3 + off + chunk]
            mac_state = aes_ecb_block(self.sha1, xor16(bytes(a), mac_state))
            off += 16

        o = bytearray(16)
        o[0] = 1
        o[1:5] = u32be(counter)
        o[5:13] = self.ble_data[0:8]
        s = aes_ecb_block(self.sha1, bytes(o))
        return bytes(x ^ y for x, y in zip(s[0:4], mac_state[0:4]))

    def decrypt(self, frame: bytes):
        if len(frame) < 9 or frame[0] != 0x5A or frame[1] != 0xA5:
            return None

        t = self.msg_it
        n = ((frame[-2] << 8) | frame[-1]) & 0xFFFF
        if (t & 0x8000) and not (frame[-2] >> 7):
            t += 0x10000
        counter = (t & 0xFFFF0000) | n

        i = len(frame) - 9
        enc_payload = frame[3:3 + i]
        header = frame[0:3]
        out = bytearray(3 + i)
        out[0:3] = header

        if counter == 0:
            dec = self.crypto_first(enc_payload)
            out[3:3 + len(dec)] = dec
            if len(out) >= 23 and out[2] >= 22 and out[4] == 62 and out[5] == 91 and out[6] == 1:
                self.ble_data = bytes(out[7:23])
                self.peer_addr = out[3]
                if len(out) >= 37:
                    self.initial_key_tail = bytes(out[23:37])
                if any(b != 0 for b in self.app_data):
                    self.sha1 = sha1_key(self.app_data, self.ble_data)
                else:
                    self.sha1 = sha1_key(self.name_data, self.ble_data)
                self.initial_key_received = True
            return bytes(out)

        dec = self.crypto_next(enc_payload, counter)
        out[3:3 + len(dec)] = dec
        if len(out) >= 23 and out[2] == 16 and out[3] == 62 and out[5] == 92 and out[6] == 0:
            self.app_data = bytes(out[7:23])
        if len(out) >= 7 and out[2] == 0 and out[4] == 62 and out[5] == 92 and out[6] == 1:
            self.sha1 = sha1_key(self.app_data, self.ble_data)
            self.recalc_received = True
        if len(out) >= 7 and out[2] == 0 and out[4] == 62 and out[5] == 93 and out[6] == 1:
            self.paired_received = True
        self.msg_it = counter
        return bytes(out)

    def encrypt(self, packet: bytes) -> bytes:
        if packet[0] != 0x5A or packet[1] != 0xA5:
            raise ValueError("frame must start with 5A A5")
        header = packet[0:3]
        body = packet[3:]

        if self.msg_it == 0:
            checksum = 0
            for b in body:
                checksum = (checksum + b) & 0xFFFF
            checksum ^= 0xFFFF
            checksum &= 0xFFFF
            enc = self.crypto_first(body)
            out = bytearray(3 + len(enc) + 6)
            out[0:3] = header
            out[3:3 + len(enc)] = enc
            out[3 + len(enc) + 2] = checksum & 0xFF
            out[3 + len(enc) + 3] = (checksum >> 8) & 0xFF
            return bytes(out)

        self.msg_it += 1
        mac = self.compute_mac(packet, self.msg_it)
        enc = self.crypto_next(body, self.msg_it)
        out = bytearray(3 + len(enc) + 6)
        out[0:3] = header
        out[3:3 + len(enc)] = enc
        out[3 + len(enc):3 + len(enc) + 4] = mac
        out[3 + len(enc) + 4] = (self.msg_it >> 8) & 0xFF
        out[3 + len(enc) + 5] = self.msg_it & 0xFF
        if len(packet) >= 23 and packet[2] == 16 and packet[3] == 62 and packet[5] == 92 and packet[6] == 0:
            self.app_data = packet[7:23]
        return bytes(out)


# ---------------------------------------------------------------------------
# Klartext-Innenpaket:  5A A5 len src dst cmd arg data...   (kein Checksum!)
# entspricht xa()/Sa()
# ---------------------------------------------------------------------------
def build_inner(src: int, dst: int, cmd: int, arg: int, data: bytes = b"") -> bytes:
    if len(data) > 255:
        raise ValueError("data too long")
    return bytes([0x5A, 0xA5, len(data), src, dst, cmd, arg]) + data


def parse_inner(frame: bytes):
    if len(frame) < 7 or frame[0] != 0x5A or frame[1] != 0xA5:
        return None
    length = frame[2]
    if len(frame) < 7 + length:
        return None
    return {
        "src": frame[3], "dst": frame[4], "cmd": frame[5], "arg": frame[6],
        "data": frame[7:7 + length],
    }


# ---------------------------------------------------------------------------
# Reassembler für eingehende Notify-Fragmente. Entspricht Ao(): sucht 5A A5,
# Gesamtlänge = 3 + len_byte + 10 (4 Header-Felder + 6 Byte Trailer)
# ---------------------------------------------------------------------------
class FrameAssembler:
    def __init__(self, on_frame):
        self.buf = bytearray()
        self.on_frame = on_frame

    def feed(self, chunk: bytes):
        self.buf += chunk
        while len(self.buf) >= 3:
            idx = -1
            for i in range(len(self.buf) - 1):
                if self.buf[i] == 0x5A and self.buf[i + 1] == 0xA5:
                    idx = i
                    break
            if idx < 0:
                self.buf = self.buf[-1:]
                break
            if idx > 0:
                self.buf = self.buf[idx:]
            if len(self.buf) < 3:
                break
            total = 3 + self.buf[2] + 10
            if len(self.buf) < total:
                break
            frame = bytes(self.buf[:total])
            self.buf = self.buf[total:]
            self.on_frame(frame)


# ---------------------------------------------------------------------------
# Session: Pairing-Ablauf + Request/Response, entspricht Klasse `Io`
# ---------------------------------------------------------------------------
class NinebotSession:
    def __init__(self, client: BleakClient, ble_name: str):
        self.client = client
        self.ble_name = ble_name
        self.nbc = Nbc(ble_name)
        self.pending = []  # list of dict(target, expected_cmd(set|None), fut)
        self.assembler = FrameAssembler(self._handle_incoming)

    async def start(self):
        await self.client.start_notify(UART_RX, self._on_notify)

    def _on_notify(self, _sender, data: bytearray):
        self.assembler.feed(bytes(data))

    def _handle_incoming(self, raw_frame: bytes):
        decoded = self.nbc.decrypt(raw_frame)
        if decoded is None:
            return
        pkt = parse_inner(decoded)
        if not pkt:
            return
        print(f"[rx pt] src=0x{pkt['src']:x} dst=0x{pkt['dst']:x} "
              f"cmd=0x{pkt['cmd']:x} arg=0x{pkt['arg']:x} data={pkt['data'].hex()}")
        if pkt["src"] == self.nbc.peer_addr and pkt["cmd"] in (0x5B, 0x5C, 0x5D):
            return
        for entry in self.pending:
            if entry["target"] == pkt["src"] and (
                entry["expected_cmd"] is None or pkt["cmd"] in entry["expected_cmd"]
            ):
                self.pending.remove(entry)
                if not entry["fut"].done():
                    entry["fut"].set_result(pkt)
                return

    async def _write(self, frame: bytes):
        await self.client.write_gatt_char(UART_TX, frame, response=False)

    async def request(self, dst: int, cmd: int, arg: int, data: bytes = b"",
                       expected_cmd=None, timeout: float = 10.0):
        pkt = build_inner(ADDR_HOST, dst, cmd, arg, data)
        print(f"[tx pt] src=0x{ADDR_HOST:x} dst=0x{dst:x} cmd=0x{cmd:x} "
              f"arg=0x{arg:x} data={data.hex()}")
        frame = self.nbc.encrypt(pkt)
        fut = asyncio.get_event_loop().create_future()
        entry = {"target": dst, "expected_cmd": set(expected_cmd) if expected_cmd else None, "fut": fut}
        self.pending.append(entry)
        await self._write(frame)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            if entry in self.pending:
                self.pending.remove(entry)

    # --- Pairing-Ablauf ---
    def _pairing_dst(self) -> int:
        return ADDR_BLE if self.ble_name.startswith("1CG") else ADDR_BLE_LEGACY

    async def send_request_initial_key(self):
        dst = self._pairing_dst()
        pkt = bytes([0x5A, 0xA5, 0x00, ADDR_HOST, dst, 0x5B, 0x00])
        print(f"[tx pt] src=0x{ADDR_HOST:x} dst=0x{dst:x} cmd=0x5b arg=0x0 data=")
        frame = self.nbc.encrypt(pkt)
        await self._write(frame)

    async def wait_for_initial_key(self, timeout=10.0):
        start = asyncio.get_event_loop().time()
        while not self.nbc.initial_key_received:
            if asyncio.get_event_loop().time() - start > timeout:
                raise TimeoutError("INITIAL_KEY nicht erhalten (0x5B) - "
                                    "Scooter hat nicht geantwortet")
            await asyncio.sleep(0.1)

    async def send_save_app_key(self, app_data: bytes):
        dst = self.nbc.peer_addr or ADDR_BLE_LEGACY
        pkt = bytes([0x5A, 0xA5, 16, ADDR_HOST, dst, 0x5C, 0x00]) + app_data
        print(f"[tx pt] src=0x{ADDR_HOST:x} dst=0x{dst:x} cmd=0x5c arg=0x0 data={app_data.hex()}")
        frame = self.nbc.encrypt(pkt)
        await self._write(frame)

    async def wait_for_recalc_key(self, app_data: bytes, timeout=60.0):
        start = asyncio.get_event_loop().time()
        last_send = asyncio.get_event_loop().time()
        while not self.nbc.recalc_received:
            now = asyncio.get_event_loop().time()
            if now - start > timeout:
                raise TimeoutError("RECALC_KEY nicht erhalten - Power-Button "
                                    "wurde nicht innerhalb 60s gedrückt")
            if now - last_send > 0.5:
                await self.send_save_app_key(app_data)
                last_send = now
            await asyncio.sleep(0.05)

    async def send_confirm_ready(self):
        dst = self.nbc.peer_addr or ADDR_BLE_LEGACY
        pkt = (bytes([0x5A, 0xA5, 14, ADDR_HOST, dst, 0x5D, 0x00])
               + self.nbc.initial_key_tail)
        frame = self.nbc.encrypt(pkt)
        await self._write(frame)

    async def wait_for_confirm_ready(self, timeout=10.0):
        start = asyncio.get_event_loop().time()
        last_send = 0.0
        while not self.nbc.paired_received:
            now = asyncio.get_event_loop().time()
            if now - start > timeout:
                raise TimeoutError("Pairing nicht bestätigt (0x5D)")
            if now - last_send > 0.5:
                await self.send_confirm_ready()
                last_send = now
            await asyncio.sleep(0.05)

    async def pair(self) -> str:
        print("[*] Sende REQUEST_INITIAL_KEY (0x5B) ...")
        await self.send_request_initial_key()
        await self.wait_for_initial_key()

        sn = self.nbc.initial_key_tail.decode(errors="replace")
        print(f"[*] Seriennummer aus Pairing-Antwort: {sn}")

        app_data = bytes(range(16))  # muss während der Session konstant bleiben
        self.nbc.set_app_data(app_data)

        print("[*] Sende SAVE_APP_KEY (0x5C) - bitte jetzt Power-Button drücken ...")
        for _ in range(4):
            await self.send_save_app_key(app_data)
        await self.wait_for_recalc_key(app_data)
        print("[*] Power-Button erkannt, bestätige Pairing (0x5D) ...")
        await self.wait_for_confirm_ready()
        print("[+] Gepairt!")
        return sn

    async def read_register(self, dst: int, reg: int, length: int, timeout=10.0) -> bytes:
        data = bytes([reg & 0xFF, (reg >> 8) & 0xFF])
        pkt = await self.request(dst, 1, reg, data, expected_cmd=None, timeout=timeout)
        if pkt["arg"] != reg:
            raise ValueError(f"readRegister arg mismatch: reg=0x{reg:x} got 0x{pkt['arg']:x}")
        if len(pkt["data"]) != length:
            raise ValueError(f"readRegister length mismatch: expected {length} got {len(pkt['data'])}")
        return pkt["data"]


async def scan():
    print("Scanne nach BLE-Geräten (5s) ...")
    for d in await BleakScanner.discover(timeout=5.0):
        print(f"  {d.address}  {d.name}")


GAP_DEVICE_NAME_CHAR = "00002a00-0000-1000-8000-00805f9b34fb"


async def run(address: str, forced_name: str = None):
    ble_name = forced_name
    if not ble_name:
        # WICHTIG: zuerst scannen (VOR dem Connect), da viele Geräte nach dem
        # Verbinden keine Advertisements mit Namen mehr senden.
        print(f"[*] Suche {address} im Advertisement-Scan (5s) ...")
        for adv_dev in await BleakScanner.discover(timeout=5.0):
            if adv_dev.address.lower() == address.lower():
                ble_name = adv_dev.name
                break

    async with BleakClient(address) as client:
        if not ble_name:
            # Fallback: Namen über die GAP-Standard-Characteristic lesen
            try:
                raw = await client.read_gatt_char(GAP_DEVICE_NAME_CHAR)
                ble_name = raw.decode(errors="replace")
            except Exception:
                pass
        if not ble_name:
            raise RuntimeError(
                "Konnte den BLE-Namen des Geräts nicht ermitteln (wird für die "
                "Schlüsselableitung gebraucht). Gib den Namen manuell als 2. "
                "Argument an: py max_g3_sn.py <MAC> <BLE-NAME>")
        print(f"[*] Verbunden mit {address} (Name: {ble_name})")

        session = NinebotSession(client, ble_name)
        await session.start()
        sn = await session.pair()

        # Bonus: SN zusätzlich live vom VCU-Register auslesen (arg 0x10, 14 Byte)
        try:
            reg_data = await session.read_register(ADDR_VCU, 0x10, 14)
            print(f"[*] SN via Register-Read bestätigt: {reg_data.decode(errors='replace')}")
        except Exception as e:
            print(f"[!] Register-Read fehlgeschlagen (nicht kritisch): {e}")

        print(f"\nSeriennummer: {sn}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        asyncio.run(scan())
    elif len(sys.argv) >= 3:
        asyncio.run(run(sys.argv[1], sys.argv[2]))
    else:
        asyncio.run(run(sys.argv[1]))