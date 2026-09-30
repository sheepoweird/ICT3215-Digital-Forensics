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
    """Phase 1: Robustly binds the token over USB by continuously pinging it."""
    host_id = get_host_id()

    try:
        # Configure port manually to try and prevent Windows from resetting the board
        ser = serial.Serial()
        ser.port = com_port
        ser.baudrate = 115200
        ser.timeout = 0.5
        ser.dtr = False
        ser.rts = False
        
        ser.open()
        
        try:
            command = f"PAIR_DEVICE:{host_id}\n".encode("utf-8")
            
            # The ESP32 takes ~5 seconds to fully boot (3s grace + 2s BLE init).
            # We continuously ping it for up to 10 seconds until it is ready to respond.
            start_time = time.time()
            while time.time() - start_time < 10.0:
                ser.write(command)
                ser.flush()

                # Read whatever the ESP32 sends back
                line = ser.readline().decode("utf-8", errors="ignore").strip()

                if "PAIRING_SUCCESS" in line and "BLE_MAC=" in line:
                    # Safely parse the dynamic MAC address
                    mac_part = line.split("BLE_MAC=")[1].strip()
                    mac_address = mac_part.split(":UUID=")[0].strip()
                    
                    # Safely parse the UUID (supports both hardcoded and C++ dynamic versions)
                    char_uuid = line.split("UUID=")[1].strip() if "UUID=" in line else CHARACTERISTIC_UUID

                    config_data = {
                        "ble_mac": mac_address, 
                        "char_uuid": char_uuid,
                        "host_id": host_id
                    }
                    
                    # Save it locally so Phase 2 BLE knows exactly who to talk to
                    with open(CONFIG_FILE, "w") as f:
                        json.dump(config_data, f)
                        
                    return True, f"Bound to MAC [{mac_address}]"

            return False, "Token did not reply. Verify PlatformIO monitor is closed."
        finally:
            ser.close()

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