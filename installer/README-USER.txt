HSIP – Hyper Secure Internet Protocol
=====================================

What this app does
------------------
HSIP gives your computer a private, cryptographic “device identity” and lets
your browser use that identity to prove who you are to websites in a safer way.

For non-technical users
-----------------------
1. Run "HSIP Tray" from the Start Menu.
2. You’ll see the HSIP icon in your system tray.
3. In Firefox, install the HSIP browser extension.
4. When you browse HSIP-aware sites, you’ll see:
   - HSIP Good  → protection is active
   - HSIP Bad   → HSIP is installed but not active
   - HSIP Danger → HSIP detected a serious risk

That’s it. You don’t have to manage keys or tokens manually.

For technical users
-------------------
The main binary is:

  hsip-cli.exe

Useful commands:

  hsip-cli.exe init         # create a new identity under %USERPROFILE%\.hsip
  hsip-cli.exe whoami       # show your PeerID and public key
  hsip-cli.exe tray         # start the local tray (status + /consent HTTP)
  hsip-cli.exe daemon       # start the status API daemon
  hsip-cli.exe hello        # generate a signed HELLO JSON
  hsip-cli.exe ping ...     # HSIP-encrypted privacy ping demo

Identity is stored under:

  %USERPROFILE%\.hsip\
