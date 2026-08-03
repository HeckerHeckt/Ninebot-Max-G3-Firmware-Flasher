#!/usr/bin/env python3
"""
Ninebot Max G3 - IAP Firmware Flasher v2 (MCU / VCU)
=====================================================

Neuimplementierung, portiert 1:1 aus der echten N-SAK-Webapp
(index-CsU5yUDb.js, Funktionen `xs()` / `ys` / `ws()` / `Ts()` / `Es()`).
Ersetzt die Annahmen aus iap_flash.py durch bestätigtes Verhalten der
echten App:

  - BEGIN-Payload (cmd 0x07): für MCU/VCU (nicht BLE/"hd"-Modus) ist es
    IMMER nur ein reines 4-Byte-LE-Längenfeld (`ws()` mit n=false).
    Kein Flag-Bit, keine MD5-Anhängung, kein 0x7FFF-Limit.
  - WR-Payload (cmd 0x08): 128-Byte-Chunks, letzter Chunk nullgepaddet
    (`Ts()`). arg = page & 0xFF (Seitenindex wraps auf 1 Byte).
  - "CRC" (cmd 0x09) ist KEIN CRC32, sondern eine simple 32-Bit-
    Ringsumme über ALLE Firmware-Bytes, anschließend bitweise NOT,
    Little-Endian gesendet (`~sum & 0xFFFFFFFF`).
  - ACK-Auswertung: das arg-Feld der ACK-Antwort ist der Status-Code:
        0   = OK
        7   = vom Bootloader abgelehnt (z.B. gesperrter Compat-Build -
              ggf. zuerst auf ältere Compat-FW zurückrollen)
        255 = vom Gerät abgebrochen
        *   = sonstiger Fehler
  - Timing/Konfiguration pro Ziel-Partition (aus `ys`):
        mcu: pageSize=128 startTimeout=9000ms pageTimeout=6000ms
             interPageDelay=15ms postWait=8000ms
        vcu: pageSize=128 startTimeout=5000ms pageTimeout=2000ms
             interPageDelay=0ms  postWait=8000ms
  - RESET (cmd 0x0A): 4x fire-and-forget, je 100ms Pause dazwischen
    (nicht 50ms wie in der ersten Version).

Sicherheits-Vorkehrungen (unverändert aus v1):
  - Standardmäßig DRY-RUN: alle Frames werden gebaut und geloggt, aber
    NICHT gesendet, außer --live wird angegeben.
  - Nach dem letzten WR-Chunk wird die Checksumme gesendet und auf ACK
    gewartet. CMD_RESET wird nur gesendet, wenn zusätzlich
    --confirm-reset angegeben ist (+ interaktive Bestätigung).
  - Bei jedem Fehler/Timeout/abgelehnten ACK bricht der Flash sofort ab.

Firmware-Paket-Format (aus ru()/$l/Pl() im Bundle):
  ZIP mit info.json + FIRM.bin ODER FIRM.bin.enc (+ optional params.txt).
  WICHTIG: Pl() im JS gibt bei verschluesselten Paketen die binEnc-Bytes
  UNVERAENDERT zurueck und die App sendet genau die an das Geraet - es
  gibt KEINE Host-seitige Entschluesselung. Der Bootloader entschluesselt
  FIRM.bin.enc selbst. extract_firmware() hier macht dasselbe: bevorzugt
  FIRM.bin.enc roh uebernehmen, sonst FIRM.bin, und optional gegen die
  md5.enc/md5.bin-Werte aus info.json verifizieren (KEIN pycryptodome
  noetig).

pip install bleak
python iap_flash_v2.py C1:6B:5E:D4:2D:D8 1CGCF2602C1892 firmware.zip --partition mcu
"""

import asyncio
import struct
import sys
import zipfile
from pathlib import Path

from bleak import BleakClient

from ninebot_ble import ADDR_HOST, ADDR_MCU, ADDR_VCU, NinebotSession

# ---------------------------------------------------------------------------
# IAP Kommandos
# ---------------------------------------------------------------------------
CMD_IAP_BEGIN = 0x07
CMD_IAP_WR = 0x08
CMD_IAP_CS = 0x09
CMD_IAP_RESET = 0x0A
CMD_IAP_ACK = 0x0B

# ---------------------------------------------------------------------------
# Partitions-Konfiguration - 1:1 aus `ys` im Bundle (nur mcu/vcu, non-hd)
# ---------------------------------------------------------------------------
PARTITIONS = {
    "mcu": dict(
        dst=ADDR_MCU, page_size=128,
        start_timeout=9.0, page_timeout=6.0,
        inter_page_delay=0.015, post_wait=8.0,
    ),
    "vcu": dict(
        dst=ADDR_VCU, page_size=128,
        start_timeout=5.0, page_timeout=2.0,
        inter_page_delay=0.0, post_wait=8.0,
    ),
}

START_EXPECTED = {0x07, CMD_IAP_ACK}
PAGE_EXPECTED = {0x08, CMD_IAP_ACK}
CS_EXPECTED = {0x09, CMD_IAP_ACK}


# ---------------------------------------------------------------------------
# Payload-Aufbau - entspricht ws() / Ts() / der Checksummen-Schleife in xs()
# ---------------------------------------------------------------------------
def build_begin_payload(fw_size: int) -> bytes:
    """entspricht ws(fwLength, md5, hd=false): reines 4-Byte-LE-Längenfeld."""
    return struct.pack("<I", fw_size)


def build_page_payload(fw_bytes: bytes, page: int, page_size: int) -> bytes:
    """entspricht Ts(): Chunk extrahieren, letzter Chunk nullgepaddet."""
    off = page * page_size
    chunk = fw_bytes[off:off + page_size]
    if len(chunk) < page_size:
        chunk = chunk + b"\x00" * (page_size - len(chunk))
    return chunk


def build_checksum_payload(fw_bytes: bytes) -> bytes:
    """entspricht der Summen-Schleife am Ende von xs():
    g = g+e|0 (32-Bit wrap) ueber ALLE Bytes, dann ~g>>>0, LE gesendet."""
    s = 0
    for b in fw_bytes:
        s = (s + b) & 0xFFFFFFFF
    inv = (~s) & 0xFFFFFFFF
    return struct.pack("<I", inv)


# ---------------------------------------------------------------------------
# ACK-Auswertung - entspricht Es(name, arg)
# ---------------------------------------------------------------------------
def check_ack(step_name: str, arg: int):
    if arg == 0:
        return
    if arg == 7:
        raise RuntimeError(
            f"{step_name} von Bootloader ABGELEHNT (ACK=7) - laufende FW ist "
            "vermutlich ein gesperrter Compat-Build. Ggf. zuerst auf eine "
            "aeltere Compat-Version (z.B. 1.5.13) zurueckrollen."
        )
    if arg == 255:
        raise RuntimeError(f"{step_name} vom Geraet ABGEBROCHEN (ACK=255)")
    raise RuntimeError(f"{step_name} fehlgeschlagen (ACK=0x{arg:x})")


# ---------------------------------------------------------------------------
# Firmware aus ZIP extrahieren
# ---------------------------------------------------------------------------
def extract_firmware(zip_path: str) -> bytes:
    """entspricht ru()/Pl() aus dem Bundle: Paket-Layout ist
    info.json + (FIRM.bin | FIRM.bin.enc) [+ params.txt]. Die App
    entschluesselt .enc NIE selbst (Pl() liefert binEnc unveraendert) -
    die rohen Bytes werden 1:1 an das Geraet gesendet, das sie im
    Bootloader entschluesselt. Also: .enc bevorzugt roh uebernehmen,
    .bin nur als Fallback fuer unverschluesselte Pakete."""
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())

        info = {}
        if "info.json" in names:
            import json
            info = json.loads(zf.read("info.json").decode("utf-8"))
            fw = info.get("firmware", {})
            print(f"[*] info.json: displayName={fw.get('displayName')!r} "
                  f"model={fw.get('model')!r} type={fw.get('type')!r} "
                  f"encryption={fw.get('encryption')!r}")

        # bevorzugt binEnc (roh, unentschluesselt an Geraet senden),
        # sonst plain bin - genau wie Pl(e) im JS.
        if "FIRM.bin.enc" in names:
            name = "FIRM.bin.enc"
            print("[*] FIRM.bin.enc gefunden - wird UNVERAENDERT (verschluesselt) "
                  "an das Geraet gesendet, wie die echte App es tut (Pl()).")
        elif "FIRM.bin" in names:
            name = "FIRM.bin"
            print("[*] FIRM.bin (unverschluesselt) gefunden.")
        else:
            # Fallback fuer abweichende Paketnamen
            candidates = [n for n in names if n.lower().endswith((".bin", ".enc", ".fw"))]
            if len(candidates) != 1:
                raise RuntimeError(
                    f"Erwarte info.json + FIRM.bin[.enc] im ZIP, gefunden: {sorted(names)}"
                )
            name = candidates[0]
            print(f"[*] Firmware-Datei im ZIP (Fallback): {name}")

        data = zf.read(name)

        # optionale MD5-Verifikation gegen info.json, wie ru() es tut
        expected_md5 = None
        fw_info = info.get("firmware", {}) if info else {}
        md5_block = fw_info.get("md5", {}) if fw_info else {}
        if name == "FIRM.bin.enc":
            expected_md5 = md5_block.get("enc")
        elif name == "FIRM.bin":
            expected_md5 = md5_block.get("bin")
        if expected_md5:
            import hashlib
            actual = hashlib.md5(data).hexdigest()
            if actual.lower() != str(expected_md5).lower():
                raise RuntimeError(
                    f"MD5-Mismatch fuer {name}: erwartet {expected_md5}, "
                    f"berechnet {actual} - Paket beschaedigt/manipuliert."
                )
            print(f"[+] MD5 von {name} bestaetigt ({actual}).")

        return data


def print_progress(done: int, total: int, prefix: str = "Flashing"):
    pct = (done / total) * 100 if total else 100
    bar_len = 30
    filled = int(bar_len * done // total) if total else bar_len
    bar = "#" * filled + "-" * (bar_len - filled)
    print(f"\r[{bar}] {pct:5.1f}%  ({done}/{total} bytes)  {prefix}", end="", flush=True)
    if done >= total:
        print()


# ---------------------------------------------------------------------------
# IAP-Ablauf - entspricht xs()
# ---------------------------------------------------------------------------
class IapFlasher:
    def __init__(self, session: NinebotSession, partition: str, live: bool):
        if partition not in PARTITIONS:
            raise ValueError(f"Unbekannte Partition '{partition}', erlaubt: {list(PARTITIONS)}")
        self.session = session
        self.partition = partition
        self.cfg = PARTITIONS[partition]
        self.target = self.cfg["dst"]
        self.live = live

    async def _request(self, cmd: int, arg: int, data: bytes, expected_cmd, timeout: float):
        if not self.live:
            print(f"\n[dry-run] wuerde senden: dst=0x{self.target:x} cmd=0x{cmd:x} "
                  f"arg=0x{arg:x} len={len(data)} data={data[:16].hex()}"
                  f"{'...' if len(data) > 16 else ''}")
            return {"cmd": CMD_IAP_ACK, "arg": 0, "data": b""}
        return await self.session.request(
            self.target, cmd, arg, data, expected_cmd=expected_cmd, timeout=timeout,
        )

    async def begin(self, fw_size: int):
        print(f"[*] IAP_BEGIN ({self.partition}): Firmware-Groesse={fw_size} Bytes, "
              f"Ziel=0x{self.target:x}")
        payload = build_begin_payload(fw_size)
        ack = await self._request(CMD_IAP_BEGIN, 0x00, payload, START_EXPECTED,
                                   self.cfg["start_timeout"])
        check_ack("start_update", ack["arg"])
        print(f"[+] IAP_BEGIN bestaetigt (ack arg={ack['arg']})")

    async def write_pages(self, fw_bytes: bytes):
        page_size = self.cfg["page_size"]
        total = len(fw_bytes)
        total_pages = -(-total // page_size)  # ceil
        done = 0
        for page in range(total_pages):
            payload = build_page_payload(fw_bytes, page, page_size)
            ack = await self._request(
                CMD_IAP_WR, page & 0xFF, payload, PAGE_EXPECTED, self.cfg["page_timeout"],
            )
            check_ack("update_page", ack["arg"])
            done += min(page_size, total - done)
            print_progress(done, total)
            if self.cfg["inter_page_delay"] > 0:
                await asyncio.sleep(self.cfg["inter_page_delay"])
        print(f"[+] Alle {total_pages} Seiten uebertragen ({total} Bytes)")

    async def verify_checksum(self, fw_bytes: bytes):
        payload = build_checksum_payload(fw_bytes)
        print(f"[*] IAP_CS: checksum(LE)=0x{payload.hex()}")
        ack = await self._request(CMD_IAP_CS, 0x00, payload, CS_EXPECTED, 10.0)
        check_ack("update_checksum", ack["arg"])
        print(f"[+] Checksumme bestaetigt vom Geraet (ack arg={ack['arg']})")

    async def reset(self):
        print("[*] IAP_RESET: Geraet uebernimmt neue Firmware und startet neu ...")
        if not self.live:
            print("[dry-run] wuerde IAP_RESET senden (4x) - uebersprungen")
            return
        from ninebot_ble import build_inner
        for i in range(4):
            pkt = build_inner(ADDR_HOST, self.target, CMD_IAP_RESET, 0x00, b"")
            frame = self.session.nbc.encrypt(pkt)
            await self.session._write(frame)
            print(f"[+] RESET #{i + 1}/4 gesendet.")
            await asyncio.sleep(0.1)  # 100ms, bestaetigt aus xs()
        print("[+] Alle RESET-Frames gesendet. Geraet sollte jetzt neu starten.")


async def run(address: str, ble_name: str, zip_path: str, partition: str,
               live: bool, confirm_reset: bool):
    fw_bytes = extract_firmware(zip_path)
    print(f"[*] Firmware geladen: {len(fw_bytes)} Bytes")

    async with BleakClient(address) as client:
        session = NinebotSession(client, ble_name)
        await session.start()
        print("[*] Pairing/Auth ...")
        await session.pair()
        print("[+] Authentifiziert, starte IAP-Ablauf ...")

        if not live:
            print("\n" + "=" * 60)
            print("DRY-RUN MODUS - es wird NICHTS an den Scooter gesendet.")
            print("Zum echten Flashen: --live anhaengen.")
            print("=" * 60 + "\n")

        flasher = IapFlasher(session, partition, live)
        await flasher.begin(len(fw_bytes))
        await flasher.write_pages(fw_bytes)
        await flasher.verify_checksum(fw_bytes)

        if not live:
            print("\n[*] Dry-run abgeschlossen, kein RESET gesendet.")
            return

        if not confirm_reset:
            print("\n[!] Checksumme ok. RESET wird NICHT gesendet ohne --confirm-reset.")
            print("    Firmware liegt jetzt im Uebertragungspuffer des Geraets,")
            print("    ist aber noch nicht aktiv. Erneut mit --confirm-reset")
            print("    starten, um den Reset/Uebernahme auszuloesen.")
            return

        answer = input("\nWirklich RESET senden und neue Firmware aktivieren? [ja/nein]: ")
        if answer.strip().lower() not in ("ja", "j", "yes", "y"):
            print("[*] Abgebrochen, kein RESET gesendet.")
            return

        await flasher.reset()

        post_wait = PARTITIONS[partition]["post_wait"]
        print(f"[*] Warte {post_wait:.0f}s (postWait), bis Geraet neu gebootet ist ...")
        await asyncio.sleep(post_wait)
        print("[+] Fertig.")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        print("\nUsage: python iap_flash_v2.py <MAC> <BLE-NAME> <firmware.zip> "
              "[--partition mcu|vcu] [--live] [--confirm-reset]")
        sys.exit(1)

    address = sys.argv[1]
    ble_name = sys.argv[2]
    zip_path = sys.argv[3]
    rest = sys.argv[4:]

    partition = "mcu"
    if "--partition" in rest:
        idx = rest.index("--partition")
        partition = rest[idx + 1]

    live = "--live" in rest
    confirm_reset = "--confirm-reset" in rest

    if confirm_reset and not live:
        print("[!] --confirm-reset ohne --live ergibt keinen Sinn, ignoriere.")
        confirm_reset = False

    asyncio.run(run(address, ble_name, zip_path, partition, live, confirm_reset))


if __name__ == "__main__":
    main()