EnvStego (Project Two To Tango) - portable build
================================================

1. Unzip this folder anywhere you can write to (Desktop, Documents, a USB stick).
   Do NOT put it in C:\Program Files: the app keeps its settings and the token
   pairing next to EnvStego.exe, and nothing in the Windows registry.

2. Double-click EnvStego.exe. Nothing else needs installing.
   Windows SmartScreen may warn that the app is unrecognised: click
   "More info" then "Run anyway".

3. Token setup (Setup > Token page):
   - Plug in the token (ESP32-CAM, or ESP32-S3 on either USB-C port).
   - Pick its port, then click "Install / update firmware".
     A blank board gets the firmware; an existing token is updated and
     keeps its keys and pairing.
   - Click "Pair Token" and press the token's IO0 / BOOT button when its
     light stays on.

Keep this whole folder together: EnvStego.exe needs the _internal and
firmware folders beside it. Back up token_config.json (created when you pair)
with the folder if you move to a new copy.
