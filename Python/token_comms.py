import asyncio
import time
import serial
from bleak import BleakClient, BleakScanner

DEVICE_NAME = "3T-Hardware-Token"
CHARACTERISTIC_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"

def pair_token_usb(com_port="COM3") -> bool:
    """
    Handles the wired USB connection with an automatic retry loop to survive boot delays.
    """
    try:
        print(f"[HOST] Connecting to {com_port}...")
        
        # --- ESP32 HARDWARE FIX: Prevent the board from being held in reset ---
        ser = serial.Serial()
        ser.port = com_port
        ser.baudrate = 115200
        ser.timeout = 1
        ser.dtr = False  # Matches PlatformIO's "forcing DTR inactive"
        ser.rts = False  # Matches PlatformIO's "forcing RTS inactive"
        ser.open()
        # ----------------------------------------------------------------------
        
        # Wait for the initial boot cycle
        time.sleep(2.5) 
        ser.reset_input_buffer()

        # Try sending the command up to 5 times
        for attempt in range(1, 6):
            print(f"[HOST] Sending PAIR_DEVICE command (Attempt {attempt})...")
            ser.write(b"PAIR_DEVICE\n")
            ser.flush()

            # Wait up to 1.5 seconds for the ESP32 to reply to this attempt
            start_time = time.time()
            while time.time() - start_time < 1.5:
                if ser.in_waiting:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        print(f"[ESP32 REPLY] {line}")
                    if "PAIRING_SUCCESS" in line:
                        ser.close()
                        print("[HOST] Wired pairing verified.")
                        return True
                        
        ser.close()
        print("[HOST] Pairing timed out after 5 attempts.")
        return False
        
    except Exception as e:
        print(f"[HOST] USB Pairing error: {e}")
        return False

async def request_key_ble(env_variables: str) -> str:
    """
    Scans for the 3T token, connects over BLE, and waits for key notification.
    """
    print(f"[BLE] Scanning for '{DEVICE_NAME}'...")
    device = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=5.0)
    
    if not device:
        raise ConnectionError(f"Could not find BLE token named '{DEVICE_NAME}'.")

    file_key = None
    key_received_event = asyncio.Event()

    def notification_handler(sender, data):
        nonlocal file_key
        file_key = data.decode('utf-8')
        print(f"[BLE] Received Key from Token: {file_key}")
        key_received_event.set()

    print(f"[BLE] Connecting to {device.address}...")
    async with BleakClient(device) as client:
        # Subscribe to notifications from the ESP32
        await client.start_notify(CHARACTERISTIC_UUID, notification_handler)

        # Send environment variables
        print(f"[BLE] Sending environment payload: {env_variables}")
        await client.write_gatt_char(CHARACTERISTIC_UUID, env_variables.encode('utf-8'))

        # Wait until notification arrives (timeout after 5 seconds)
        try:
            await asyncio.wait_for(key_received_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            print("[BLE] Timed out waiting for decryption key.")
        finally:
            await client.stop_notify(CHARACTERISTIC_UUID)

    return file_key

if __name__ == "__main__":
    print("--- 3T Hardware Token Integration Test ---")
    
    # 1. Wired Pairing Phase
    paired = pair_token_usb("COM3")
    
    # 2. Wireless Decryption Key Phase
    if paired:
        print("\n--- Starting Wireless BLE Key Exchange ---")
        test_env = "WIFI:SIT_SECURE,RAM:16GB"
        key = asyncio.run(request_key_ble(test_env))
        print(f"\nFinal Derived Key: {key}")
    else:
        print("\nAborting BLE test: Wired pairing failed.")