# CrackWpaWpa2
This repository contains Python code for validating Wi-Fi passwords using the Message Integrity Code (MIC) from EAPoL (Extensible Authentication Protocol over LAN) messages. The code is designed to check if a given Wi-Fi password matches the MIC value present in EAPoL message #2, which is exchanged during the WPA/WPA2 handshake process. The script iterates through a range of 8-digit numeric passwords, calculates the PMK (Pairwise Master Key) using PBKDF2-HMAC-SHA1, and validates the MIC. If a matching password is found, it is printed to the console.

Please note that the code should only be used for educational and ethical purposes, and its usage should comply with applicable laws and regulations.

