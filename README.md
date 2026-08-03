Ninebot Max G3 Firmware Flasher
A Python-based firmware flashing tool for Ninebot Max G3, G3D scooters.
This project provides encrypted BLE communication, automatic device discovery, firmware version retrieval, and MCU firmware flashing through the IAP v2 protocol.

Features:
Automatic BLE scanning and device detection
Automatic connection and pairing
Encrypted communication using Ninebot BLE Crypto
Firmware version retrieval (BLE, VCU, MCU, BMS)
MCU firmware flashing (IAP v2)
ZIP firmware package loading


Requirements
Windows 10 or Windows 11
Python 3.10 or newer
Bluetooth Low Energy support


Required Python packages:
pip install bleak pyqt6


Project files required:
flasher.py (main GUI application)
ninebot_ble.py (BLE session + encryption)
iap_flash_v2.py (IAP v2 flashing logic)


Running the Application
Start the GUI by opening Start.bat


Usage
Power on your scooter.
Click Scan to detect nearby Ninebot BLE devices.
Select your scooter from the list.
Load a firmware ZIP file.
Click FLASH FIRMWARE.
Press the scooter’s power button when pairing is requested.
The flashing process will begin automatically.


Firmware Version Retrieval
The flasher reads firmware versions using encrypted BLE register access.
The following registers are used:

Component	Destination (Board)	Register	Length
BLE	0x04	0x01	2 bytes
VCU	0x16	0x17	2 bytes
MCU	0x02	0x19	2 bytes
MCU (fallback)	0x16	0x18	2 bytes
BMS	0x16	0x19	2 bytes


Version numbers are decoded using a nibble-based format (e.g., 1.5.7).

Example output:

BLE: 0.4.0
VCU: 1.6.2
MCU: 1.5.0
BMS: 4.1.6.8
Flashing Process
The tool uses the Ninebot IAP v2 protocol:

Sends encrypted IAP commands
Transfers firmware in pages
Verifies checksum
Optionally sends reset (unless Safe Mode is enabled)


Project Structure

flasher.py          GUI + FlashWorker + version retrieval
ninebot_ble.py      BLE session, encryption, pairing
iap_flash_v2.py     IAP v2 flashing implementation
firmware.zip        Example firmware package
Notes
Flashing firmware carries risk; proceed carefully.

Ensure the scooter battery is sufficiently charged.

Do not interrupt Bluetooth communication during flashing.

Only use firmware intended for your specific scooter model.

Credits to HeckerHeckt.
This project is based on community reverse engineering efforts and Ninebot BLE protocol research.
