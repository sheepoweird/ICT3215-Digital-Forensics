import serial
import time
import asyncio
from bleak import BleakClient

# Must match the UUIDs in the ESP32 code
BLE_ADDRESS = "XX:XX:XX:XX:XX:XX" # Replace with your ESP32's MAC Address (from the boot text)
CHARACTERISTIC_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"

def pair_token_usb(com_port="COM3"):
    """
    Handles the wired USB connection to establish the initial pairing.
    Because it is physical, attackers cannot step in during this exchange[cite: 3].
    """
    try:
        print(f"Connecting to token on {com_port}...")
        ser = serial.Serial(com_port, 115200, timeout=2)
        time.sleep(2) # Wait for ESP32 to reboot upon connection
        
        ser.write(b"PAIR_DEVICE\n")
        response = ser.readline().decode('utf-8').strip()
        ser.close()
        
        if "PAIRING_SUCCESS" in response:
            print("Wired pairing successful!")
            return True
        return False
    except Exception as e:
        print(f"USB Pairing failed: {e}")
        return False

async def request_key_ble(env_variables: str) -> str:
    """
    Sends the gathered environment variables to the token via BLE
    and waits for the hardware-anchored decryption key to be returned[cite: 3].
    """
    file_key = None

    def notification_handler(sender, data):
        nonlocal file_key
        file_key = data.decode('utf-8')
        print(f"Received secure key from token: {file_key}")

    async with BleakClient(BLE_ADDRESS) as client:
        print(f"Connected to 3T Token: {client.is_connected}")
        
        # Subscribe to notifications so we can catch the ESP32's reply
        await client.start_notify(CHARACTERISTIC_UUID, notification_handler)
        
        # Send the environment factors (e.g., "WIFI:SIT_SECURE,RAM:16GB")
        await client.write_gatt_char(CHARACTERISTIC_UUID, env_variables.encode('utf-8'))
        
        # Wait a moment for the ESP32 to process and send back the key
        await asyncio.sleep(1.0) 
        await client.stop_notify(CHARACTERISTIC_UUID)
        
    return file_key