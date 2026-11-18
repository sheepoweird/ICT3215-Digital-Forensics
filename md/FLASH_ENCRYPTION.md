# ESP32 storage and boot protection status

**The supplied Arduino firmware does not provision NVS encryption, flash
encryption or Secure Boot. Vault v2 does not change this.** Firmware build success
does not establish protection against physical token theft.

## What remains exposed

The master secret and pairing credential are stored through Arduino Preferences
in NVS. With the current development configuration, a physical flash read can
expose them. Possession of the master secret bypasses token-side key approval.
Vault recovery codes are an independent route to recovery.

## Correction to the previous guide

Enabling flash encryption alone does **not** encrypt an ordinary NVS partition.
NVS uses a separate encryption mechanism and key partition. Adding a preprocessor
flag to an Arduino application does not configure its prebuilt bootloader or
provision that storage scheme. The earlier recipe claiming otherwise has been
removed. See Espressif's [flash-encryption restrictions](https://docs.espressif.com/projects/esp-idf/en/v4.4.7/esp32/security/flash-encryption.html)
and [NVS encryption configuration](https://docs.espressif.com/projects/esp-idf/en/v4.4.7/esp32/api-reference/storage/nvs_flash.html#nvs-encryption).

## Work needed for a hardened device

Build and validate a compatible bootloader, partition table and application with
the intended security configuration. Provision encrypted NVS and its protected
keys, use Secure Boot to control firmware authenticity, and select UART/JTAG
restrictions appropriate to the exact chip revision and update process. The
current source uses Arduino APIs; moving to an ESP-IDF build requires integration
work and has not been validated as an unchanged-source port.

Test provisioning, retained credentials, existing-file decryption, updates and
interrupted power on a spare board before modifying the only token holding real
data. eFuse changes can be irreversible. This repository currently provides no
verified provisioning command sequence; no fuses were changed for vault v2.
