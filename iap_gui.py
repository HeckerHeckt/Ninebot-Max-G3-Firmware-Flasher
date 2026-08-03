#!/usr/bin/env python3
import sys
import asyncio
import zipfile
import hashlib

from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QListWidget, QFileDialog, QProgressBar, QTextEdit,
    QCheckBox, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from bleak import BleakScanner, BleakClient
from iap_flash_v2 import IapFlasher, extract_firmware
from ninebot_ble import NinebotSession


# ------------------------------------------------------------
# Version decode + Register read (G3/G2/GT/P-Series)
# ------------------------------------------------------------
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
    data = bytes((length & 0xFF, (length >> 8) & 0xFF))
    resp = await session.request(dst, 0x01, reg, data)
    return bytes(resp["data"])

async def fetch_versions(session):
    versions = {}

    # BLE-Version: dst=0x04, reg=0x01
    ble_raw = await read_reg(session, 0x04, 0x01)
    versions["ble"] = to_version_str(u16_le(ble_raw)) if len(ble_raw) >= 2 else "?"

    # VCU-Version: dst=0x16, reg=0x17
    vcu_raw = await read_reg(session, 0x16, 0x17)
    versions["vcu"] = to_version_str(u16_le(vcu_raw)) if len(vcu_raw) >= 2 else "?"

    # MCU-Version: erst direkt über MCU (dst=0x02, reg=0x19)
    mcu_raw = await read_reg(session, 0x02, 0x19)
    if len(mcu_raw) < 2:
        mcu_raw = await read_reg(session, 0x16, 0x18)
    versions["mcu"] = to_version_str(u16_le(mcu_raw)) if len(mcu_raw) >= 2 else "?"

    # BMS-Version: über VCU (dst=0x16, reg=0x19)
    bms_raw = await read_reg(session, 0x16, 0x19)
    versions["bms"] = to_version_str(u16_le(bms_raw)) if len(bms_raw) >= 2 else "?"

    return versions


# ------------------------------------------------------------
# Worker-Thread für Flash
# ------------------------------------------------------------
class FlashWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    versions = pyqtSignal(dict)

    def __init__(self, address, ble_name, zip_path, partition, safe_mode):
        super().__init__()
        self.address = address
        self.ble_name = ble_name
        self.zip_path = zip_path
        self.partition = partition
        self.safe_mode = safe_mode

    async def _run_async(self):
        self.log.emit("[*] Lade Firmware...")
        fw_bytes = extract_firmware(self.zip_path)
        self.log.emit(f"[*] Firmware: {len(fw_bytes)} Bytes")

        async with BleakClient(self.address) as client:
            session = NinebotSession(client, self.ble_name)
            await session.start()

            # Versionen holen (NEU)
            self.log.emit("[*] Lese Firmware-Versionen...")
            try:
                vers = await fetch_versions(session)
                self.versions.emit(vers)
                self.log.emit(f"[+] FW: BLE {vers['ble']} | VCU {vers['vcu']} | MCU {vers['mcu']} | BMS {vers['bms']}")
            except Exception as e:
                self.log.emit(f"[!] Versions-Fehler: {e}")

            self.log.emit("[*] Pairing...")
            await session.pair()
            self.log.emit("[+] Authentifiziert.")

            flasher = IapFlasher(session, self.partition, live=True)

            self.log.emit("[*] Sende BEGIN...")
            await flasher.begin(len(fw_bytes))

            page_size = flasher.cfg["page_size"]
            total = len(fw_bytes)
            total_pages = -(-total // page_size)
            done = 0

            for page in range(total_pages):
                payload = fw_bytes[page * page_size : page * page_size + page_size]
                await flasher._request(
                    0x08, page & 0xFF, payload, {0x08, 0x0B}, flasher.cfg["page_timeout"]
                )
                done += min(page_size, total - done)
                pct = int((done / total) * 100)
                self.progress.emit(pct)
                self.log.emit(f"[{pct}%] Page {page+1}/{total_pages}")

            self.log.emit("[*] Sende Checksumme...")
            await flasher.verify_checksum(fw_bytes)

            if self.safe_mode:
                self.log.emit("[!] Safe-Mode aktiv: RESET wird NICHT gesendet.")
            else:
                self.log.emit("[*] Sende RESET...")
                await flasher.reset()

            self.log.emit("[+] Flash abgeschlossen.")
            self.finished.emit()

    def run(self):
        asyncio.run(self._run_async())


# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------
class FlashGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ScooterHacking – Ninebot Max G3 Flasher")
        self.resize(800, 600)

        # Dark Theme StyleSheet (SH-Style)
        self.setStyleSheet("""
            QWidget {
                background-color: #0d0f12;
                color: #e8e8e8;
                font-family: Segoe UI, Arial;
            }
            QFrame#MainPanel {
                background-color: #15181d;
                border-radius: 16px;
                border: 1px solid #22252b;
            }
            QLabel#TitleLabel {
                font-size: 26px;
                font-weight: 600;
                color: #e8e8e8;
            }
            QLabel#SubLabel {
                font-size: 13px;
                color: #9aa0a6;
            }
            QListWidget {
                background-color: #101318;
                border-radius: 8px;
                border: 1px solid #22252b;
            }
            QTextEdit {
                background-color: #101318;
                border-radius: 8px;
                border: 1px solid #22252b;
                color: #e8e8e8;
            }
        """)

        outer = QVBoxLayout()
        outer.setContentsMargins(40, 40, 40, 40)

        panel = QFrame()
        panel.setObjectName("MainPanel")
        panel_layout = QVBoxLayout()
        panel_layout.setContentsMargins(30, 30, 30, 30)
        panel_layout.setSpacing(20)

        # Header
        title = QLabel("Ready to Flash")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Select your scooter and a firmware package to get started.")
        subtitle.setObjectName("SubLabel")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        panel_layout.addWidget(title)
        panel_layout.addWidget(subtitle)

        # BLE list
        mid_row = QHBoxLayout()
        mid_row.setSpacing(20)

        left_col = QVBoxLayout()
        left_label = QLabel("Scooters")
        left_label.setObjectName("SubLabel")
        left_col.addWidget(left_label)

        self.ble_list = QListWidget()
        self.ble_list.setMinimumHeight(150)
        left_col.addWidget(self.ble_list)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self.scan_ble)
        left_col.addWidget(scan_btn)

        mid_row.addLayout(left_col)

        # Firmware info
        right_col = QVBoxLayout()
        right_label = QLabel("Firmware")
        right_label.setObjectName("SubLabel")
        right_col.addWidget(right_label)

        self.zip_info = QLabel("Keine Firmware ausgewählt")
        self.zip_info.setObjectName("SubLabel")
        right_col.addWidget(self.zip_info)

        btn_row = QHBoxLayout()
        self.btn_select_zip = QPushButton("Load ZIP")
        self.btn_select_zip.clicked.connect(self.select_zip)
        btn_row.addWidget(self.btn_select_zip)

        self.btn_flash = QPushButton("FLASH FIRMWARE")
        self.btn_flash.clicked.connect(self.start_flash)
        btn_row.addWidget(self.btn_flash)

        right_col.addLayout(btn_row)

        self.safe_mode = QCheckBox("Safe Mode (kein RESET)")
        right_col.addWidget(self.safe_mode)

        mid_row.addLayout(right_col)
        panel_layout.addLayout(mid_row)

        # Progress
        self.progress = QProgressBar()
        panel_layout.addWidget(self.progress)

        # Log
        log_label = QLabel("Log")
        log_label.setObjectName("SubLabel")
        panel_layout.addWidget(log_label)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        panel_layout.addWidget(self.log)

        # Version info panel
        self.version_info = QLabel("BMS: ?   BLE: ?   VCU: ?   MCU: ?")
        self.version_info.setObjectName("SubLabel")
        panel_layout.addWidget(self.version_info)

        panel.setLayout(panel_layout)
        outer.addWidget(panel)
        self.setLayout(outer)

        self.zip_path = None
        self.worker = None
        self.scan_thread = None
        self.auto_thread = None

    def log_msg(self, msg):
        self.log.append(msg)

    # ------------------------------------------------------------
    # ZIP-Auswahl + ZIP-Info
    # ------------------------------------------------------------
    def select_zip(self):
        path, _ = QFileDialog.getOpenFileName(self, "Firmware ZIP auswählen", "", "ZIP Dateien (*.zip)")
        if not path:
            return

        self.zip_path = path

        try:
            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()
                size = sum(z.getinfo(n).file_size for n in names)

            md5 = hashlib.md5(open(path, "rb").read()).hexdigest()

            self.zip_info.setText(
                f"ZIP: {path}\n"
                f"Files: {len(names)}\n"
                f"Size: {size} Bytes\n"
                f"MD5: {md5}"
            )
        except Exception as e:
            self.zip_info.setText(f"[!] Fehler beim Lesen: {e}")

        self.log_msg(f"[+] Firmware ausgewählt: {path}")

    # ------------------------------------------------------------
    # Auto-Connect + Auto-Pair + Versionen abrufen (NEU)
    # ------------------------------------------------------------
    def auto_connect(self, address, name):
        if self.auto_thread and self.auto_thread.isRunning():
            return

        self.log_msg(f"[*] Verbinde automatisch mit {name} ({address}) ...")

        class AutoThread(QThread):
            log = pyqtSignal(str)
            versions = pyqtSignal(dict)

            def run(self_inner):
                async def _run():
                    try:
                        client = BleakClient(address)
                        await client.connect()

                        session = NinebotSession(client, name)
                        await session.start()

                        self_inner.log.emit("[*] Pairing... Bitte Power-Button drücken!")
                        await session.pair()
                        self_inner.log.emit("[+] Pairing erfolgreich!")

                        # Versionen abrufen (NEU)
                        self_inner.log.emit("[*] Lese Firmware-Versionen...")
                        try:
                            vers = await fetch_versions(session)
                            self_inner.versions.emit(vers)
                            self_inner.log.emit(f"[+] FW: BLE {vers['ble']} | VCU {vers['vcu']} | MCU {vers['mcu']} | BMS {vers['bms']}")
                        except Exception as e:
                            self_inner.log.emit(f"[!] Versions-Fehler: {e}")

                        await client.disconnect()

                    except Exception as e:
                        self_inner.log.emit(f"[!] Auto-Connect Fehler: {e}")

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(_run())
                loop.close()

        def update_versions(v):
            self.version_info.setText(
                f"BMS: {v.get('bms','?')}   "
                f"BLE: {v.get('ble','?')}   "
                f"VCU: {v.get('vcu','?')}   "
                f"MCU: {v.get('mcu','?')}"
            )

        self.auto_thread = AutoThread()
        self.auto_thread.log.connect(self.log_msg)
        self.auto_thread.versions.connect(update_versions)
        self.auto_thread.start()

    # ------------------------------------------------------------
    # BLE-SCAN
    # ------------------------------------------------------------
    def scan_ble(self):
        self.log_msg("[*] Scanne BLE-Geräte...")
        self.ble_list.clear()

        class ScanThread(QThread):
            result = pyqtSignal(list)
            log = pyqtSignal(str)

            def run(self_inner):
                async def _scan():
                    try:
                        devices = await BleakScanner.discover(timeout=2.0)
                        return devices
                    except Exception as e:
                        return e

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                devices = loop.run_until_complete(_scan())
                loop.close()

                if isinstance(devices, Exception):
                    self_inner.log.emit(f"[!] Scan-Fehler: {devices}")
                    self_inner.result.emit([])
                else:
                    self_inner.result.emit(devices)

        def update_list(devices):
            self.ble_list.clear()

            for d in devices:
                name = d.name or ""

                if not name.startswith("1C"):
                    continue

                entry = f"{d.address} | {name}"
                self.ble_list.addItem(entry)

                # Auto-Connect starten
                self.auto_connect(d.address, name)

            self.log_msg("[+] Scan abgeschlossen.")

        self.scan_thread = ScanThread()
        self.scan_thread.result.connect(update_list)
        self.scan_thread.log.connect(self.log_msg)
        self.scan_thread.start()

    # ------------------------------------------------------------
    # Flash starten
    # ------------------------------------------------------------
    def start_flash(self):
        if not self.zip_path:
            self.log_msg("[!] Keine Firmware ausgewählt.")
            return

        item = self.ble_list.currentItem()
        if not item:
            self.log_msg("[!] Kein BLE-Gerät ausgewählt.")
            return

        address, ble_name = item.text().split(" | ")

        self.worker = FlashWorker(
            address=address,
            ble_name=ble_name,
            zip_path=self.zip_path,
            partition="mcu",
            safe_mode=self.safe_mode.isChecked()
        )

        self.worker.log.connect(self.log_msg)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.versions.connect(self.update_versions)

        def on_finished():
            self.log_msg("[+] Vorgang abgeschlossen.")
            self.worker.quit()
            self.worker.wait()

        self.worker.finished.connect(on_finished)
        self.worker.start()

    # ------------------------------------------------------------
    # Versionen aktualisieren
    # ------------------------------------------------------------
    def update_versions(self, v):
        try:
            self.version_info.setText(
                f"BMS: {v.get('bms','?')}   "
                f"BLE: {v.get('ble','?')}   "
                f"VCU: {v.get('vcu','?')}   "
                f"MCU: {v.get('mcu','?')}"
            )
        except:
            self.version_info.setText("BMS: ?   BLE: ?   VCU: ?   MCU: ?")

    # ------------------------------------------------------------
    # Thread sauber beenden
    # ------------------------------------------------------------
    def closeEvent(self, event):
        try:
            if self.worker and self.worker.isRunning():
                self.worker.quit()
                self.worker.wait()
            if self.scan_thread and self.scan_thread.isRunning():
                self.scan_thread.quit()
                self.scan_thread.wait()
            if self.auto_thread and self.auto_thread.isRunning():
                self.auto_thread.quit()
                self.auto_thread.wait()
        except:
            pass
        event.accept()


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = FlashGUI()
    gui.show()
    sys.exit(app.exec())
