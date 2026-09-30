import asyncio
import time
import json
import os
import platform
import hashlib
import serial
from bleak import BleakClient

CONFIG_FILE = "token_config.json"
CHARACTERISTIC_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"

def get_host_id() -> str:
    """Derives a stable, unique 8-character ID for this specific PC."""
    raw_id = platform.node() + platform.system()
    return hashlib.sha256(raw_id.encode()).hexdigest()[:8].upper()

def pair_token_usb(com_port: str = "COM3") -> tuple[bool, str]:
    """Phase 1: Robustly binds the token over USB, waiting for the boot sequence."""
    host_id = get_host_id()
    try:
        with serial.Serial(com_port, 115200, timeout=2.0) as ser:
            # 1. Opening the port forces the ESP32 to reboot. 
            # The white LED turns on for a 3-second grace period. We MUST wait for it to finish.
            time.sleep(3.5)
            
            # 2. Clear out all the boot messages (e.g. "Token Booting")
            ser.reset_input_buffer()
            
            # 3. Now that the ESP32 is ready, send the command
            command = f"PAIR_DEVICE:{host_id}\n".encode("utf-8")
            ser.write(command)
            ser.flush()

            # 4. Read the response
            for _ in range(5):
                line = ser.readline().decode("utf-8", errors="ignore").strip()
                
                if "PAIRING_SUCCESS" in line and "BLE_MAC=" in line:
                    # Parse the MAC address out of the string
                    mac_address = line.split("BLE_MAC=")[1].split(":UUID=")[0].strip()
                    
                    # Parse UUID if it was sent dynamically by C++, otherwise use default
                    char_uuid = line.split("UUID=")[1].strip() if "UUID=" in line else CHARACTERISTIC_UUID
                    
                    config_data = {
                        "ble_mac": mac_address, 
                        "char_uuid": char_uuid,
                        "host_id": host_id
                    }
                    with open(CONFIG_FILE, "w") as f:
                        json.dump(config_data, f)
                        
                    return True, f"Bound to MAC [{mac_address}]"
                    
            return False, "Token did not reply. Verify PlatformIO monitor is closed."
    except Exception as e:
        return False, f"Port error: {e}"

async def request_key_ble(env_str: str) -> str:
    """Phase 2: Reads cached MAC/UUID and retrieves the cryptographic key over BLE."""
    if not os.path.exists(CONFIG_FILE):
        return "ERROR: NOT_PAIRED"

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
        mac_address = config.get("ble_mac")
        target_uuid = config.get("char_uuid", CHARACTERISTIC_UUID)

    if not mac_address:
        return "ERROR: NOT_PAIRED"

    received_data = []
    response_event = asyncio.Event()

    def notification_handler(sender, data: bytearray):
        received_data.append(data.decode("utf-8", errors="ignore"))
        response_event.set()

    try:
        async with BleakClient(mac_address, timeout=7.0) as client:
            await client.start_notify(target_uuid, notification_handler)
            await client.write_gatt_char(target_uuid, env_str.encode("utf-8"))
            await asyncio.wait_for(response_event.wait(), timeout=5.0)
            await client.stop_notify(target_uuid)
            return received_data[0] if received_data else "ERROR: NO_RESPONSE"
    except Exception as e:
        print(f"[BLE] Connection error: {e}")
        return ""