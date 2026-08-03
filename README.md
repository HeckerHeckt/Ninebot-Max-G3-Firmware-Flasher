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


How Authentication and Encrypted BLE Communication Work
This section explains the internal flow of the flasher, the order of operations, and how each module interacts with the scooter.

The Ninebot Max G3 series uses encrypted BLE communication.
All commands must be sent through the encrypted session provided by NinebotSession.
Below is the exact sequence used by the flasher.

1. BLE Discovery
Module: BleakScanner
The application scans for BLE devices:

devices = await BleakScanner.discover(timeout=2.0)
Devices with names starting with 1C are Ninebot scooters.

3. BLE Connection
Module: BleakClient
Once a scooter is selected:

client = BleakClient(address)
await client.connect()

This establishes a raw BLE link, but not yet an authenticated Ninebot session.


3. Encrypted Session Initialization
Module: NinebotSession.start()

session = NinebotSession(client, ble_name)
await session.start()

This step:
Negotiates encryption keys
Sets up the NinebotCrypto layer
Enables encrypted command and response frames
Activates the Ninebot protocol handler
From this point on, all communication is encrypted.

4. Pairing / Authentication
Module: NinebotSession.pair()

await session.pair()

Pairing performs:
Request initial key (cmd 0x5B)
Receive serial number
Send app key (cmd 0x5C)
Wait for power-button confirmation
Confirm pairing (cmd 0x5D)
After pairing, the scooter accepts encrypted commands.


5. Firmware Version Retrieval
Module: fetch_versions()  
Registers accessed through encrypted session.request()

Each firmware module exposes a version register:

Component	Destination (Board)	Register	Length
BLE	0x04	0x01	2 bytes
VCU	0x16	0x17	2 bytes
MCU	0x02	0x19	2 bytes
MCU (fallback)	0x16	0x18	2 bytes
BMS	0x16	0x19	2 bytes


Example:

resp = await session.request(0x04, 0x01, 0x01, b"\x02\x00")
Version numbers are decoded using a nibble-based format.


6. Firmware Flashing (MCU)
Module: IapFlasher
The flashing process:
begin()
Page-by-page transfer
Checksum verification
Optional reset
All commands are encrypted and sent through NinebotSession.

7. Disconnect
Module: BleakClient.disconnect()

After flashing or version retrieval:
await client.disconnect()


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
