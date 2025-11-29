HSIP Free MVP (Windows) – Early Preview
=======================================

What this is
------------

This build is an early preview of HSIP for Windows.

Right now it gives you:

- An HSIP daemon running locally (the "shield")
- A tray icon that shows when the shield is ON/OFF
- An optional HTTP/HTTPS gateway you can point your browser to

This version is aimed at early technical testers, not non-technical users yet.


What HSIP does in this build
----------------------------

- Runs a local daemon on 127.0.0.1:8787 (`/status` HTTP API).
- Shows a tray icon:
  - Red square = HSIP daemon offline
  - Green square = HSIP daemon answering and protecting
- Applies basic guard logic to HSIP control traffic:
  - Rate limits abusive peers
  - Tracks blocked IPs and "tracker" hosts from a local file:
    %USERPROFILE%\.hsip\tracker_blocklist.txt

- Optional: HSIP Gateway (127.0.0.1:8080)
  - Acts as a local HTTP/HTTPS proxy
  - Blocks plain HTTP sites (e.g. http://neverssl.com)
  - Allows HTTPS through, while logging and preparing for future
    phishing / malware checks.


Installing
----------

1. Run HSIP-Setup.exe
2. Accept the default install path:
   C:\Program Files\Nyx Systems\HSIP

You will get:

- hsip-cli.exe
- hsip-tray.exe
- README-USER.txt


Starting HSIP (daemon + tray)
-----------------------------

For now, startup is manual:

1. Open a PowerShell window.
2. Run:

   cd "C:\Program Files\Nyx Systems\HSIP"
   .\hsip-cli.exe daemon

   Leave this window open (daemon is running in foreground).

3. Open a second PowerShell window and run:

   cd "C:\Program Files\Nyx Systems\HSIP"
   .\hsip-tray.exe

If everything is OK:

- You should see a small square icon in the Windows tray.
- Hovering it should show something like:

  HSIP shield: ON
  cipher=ChaCha20-Poly1305
  sessions=1
  blocked_connections=0

You can also check the raw JSON status:

   curl http://127.0.0.1:8787/status


Using the HSIP Gateway (optional)
---------------------------------

This step is OPTIONAL and intended for testers.

1. In one PowerShell window (with the daemon already running):

   cd "C:\Program Files\Nyx Systems\HSIP"
   .\hsip-gateway.exe

   You should see:

   [gateway] listening on 127.0.0.1:8080

2. To test with curl:

   curl -x http://127.0.0.1:8080 https://example.com/ -v

   You should see logs in the gateway window like:

   [gateway] CONNECT example.com:443
   [gateway] GET / HTTP/1.1

3. If you configure a browser proxy (advanced / optional):

   - HTTP proxy: 127.0.0.1, port 8080
   - Use this proxy for all protocols

   Then HTTPS traffic will flow through HSIP Gateway.
   Pure HTTP sites (like http://neverssl.com) will be blocked.


Tracker blocklist
-----------------

You can add hostnames to:

   %USERPROFILE%\.hsip\tracker_blocklist.txt

One per line, for example:

   ads.example.com
   tracker.badcorp.io

The gateway will log and block these when accessed through the proxy.


Uninstalling
------------

1. Close the daemon and tray windows (Ctrl+C in PowerShell, or close the windows).
2. Use "Add or Remove Programs" in Windows and uninstall "HSIP".
3. You can optionally delete the config folder:

   %USERPROFILE%\.hsip

After uninstall, your system goes back to normal HTTPS/TCP/IP behavior.
No network settings are modified automatically by this installer.
