#!/usr/bin/env python3
import asyncio
from bleak import BleakScanner, BleakClient
from ninebot_ble import NinebotSession

def u16_le(b: bytes) -> int:
    return b[0] | (b[1] << 8)

def to_version_str(val: int) -> str:
    n = val & 0xFFFFFFFF
    parts = []
    while n > 0 or len(parts) < 3:
        parts.insert(0, n & 0xF)
        n >>= 4
    return ".".join(str(x) for x in parts)

async def read_reg(session, dst, reg, length=2):
    # cmd=0x01 (READ), arg=reg, data=[lenLo,lenHi]
    data = bytes((length & 0xFF, (length >> 8) & 0xFF))
    resp = await session.request(dst, 0x01, reg, data)
    return bytes(resp["data"])

async def read_versions(address, name):
    print(f"[*] Verbinde mit {name} ({address}) ...")
    client = BleakClient(address)
    await client.connect()

    session = NinebotSession(client, name)
    await session.start()

    print("[*] Pairing... Bitte Power-Button drücken!")
    await session.pair()
    print("[+] Pairing erfolgreich!\n")

    versions = {}

    # BLE-Version: dst=0x04, reg=0x01
    ble_raw = await read_reg(session, 0x04, 0x01)
    versions["BLE"] = to_version_str(u16_le(ble_raw)) if len(ble_raw) >= 2 else ""

    # VCU-Version: dst=0x16, reg=0x17
    vcu_raw = await read_reg(session, 0x16, 0x17)
    versions["VCU"] = to_version_str(u16_le(vcu_raw)) if len(vcu_raw) >= 2 else ""

    # MCU-Version: erst direkt über MCU (dst=0x02, reg=0x19)
    mcu_raw = await read_reg(session, 0x02, 0x19)
    if len(mcu_raw) < 2:
        # Fallback: über VCU (dst=0x16, reg=0x18)
        mcu_raw = await read_reg(session, 0x16, 0x18)
    versions["MCU"] = to_version_str(u16_le(mcu_raw)) if len(mcu_raw) >= 2 else ""

    # BMS-Version: über VCU (dst=0x16, reg=0x19)
    bms_raw = await read_reg(session, 0x16, 0x19)
    versions["BMS"] = to_version_str(u16_le(bms_raw)) if len(bms_raw) >= 2 else ""

    print("[+] Firmware-Versionen:")
    for k, v in versions.items():
        print(f"{k}: {v}")

    await client.disconnect()

async def main():
    print("[*] Scanne BLE-Geräte...")
    devices = await BleakScanner.discover(timeout=4.0)

    for d in devices:
        name = d.name or ""
        if name.startswith("1C"):
            print(f"[+] Gefunden: {name} ({d.address})")
            await read_versions(d.address, name)
            return

    print("[!] Kein Ninebot-Gerät gefunden.")

if __name__ == "__main__":
    asyncio.run(main())
