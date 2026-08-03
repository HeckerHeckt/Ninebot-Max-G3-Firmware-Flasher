@echo off
pip install pycryptodome bleak PyQt6
start "" /b pythonw.exe iap_gui.py
stop
