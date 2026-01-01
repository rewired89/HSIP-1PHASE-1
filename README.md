# HSIP - Hyper-Secure Internet Protocol

**Take back control of your privacy and security online.**

HSIP is a Windows application that protects you from hackers, trackers, and surveillance. Once installed, it runs silently in the background - no configuration needed.

**Status:** Ready for Windows 10/11

---

## What HSIP Protects You From

### Trackers and Advertisers
Every website you visit tries to track you. Ad networks like Google, Facebook, and dozens of data brokers follow you across the internet, building profiles about your habits, interests, and behaviors.

**With HSIP:** Trackers are blocked automatically. Your browsing stays private.

### Public WiFi Hackers
Coffee shops, airports, hotels - public WiFi is a goldmine for hackers. They can intercept your passwords, credit cards, and private messages.

**With HSIP:** All your traffic is encrypted. Hackers see only gibberish.

### Man-in-the-Middle Attacks
Sophisticated attackers can position themselves between you and websites to steal your data in real-time.

**With HSIP:** Strong encryption (ChaCha20-Poly1305) makes interception useless.

### Data Harvesting
Companies collect everything: what you search, what you buy, who you talk to, where you go. This data is sold, leaked, or hacked.

**With HSIP:** Your connection is protected at the protocol level. Less data to harvest.

---

## How It Works

1. **Install HSIP** - Run the installer, click Yes
2. **Done** - HSIP runs automatically in the background

Look for the colored square in your system tray (bottom-right):
- **Green** = Protected
- **Yellow** = Actively blocking threats
- **Red** = Offline or error

---

## Installation

### Download
Get `HSIP-Setup.exe` from the Releases page.

### Install
1. Double-click `HSIP-Setup.exe`
2. Click Yes when Windows asks for permission
3. Done - you're protected

### Uninstall
Go to Windows Settings > Apps > HSIP > Uninstall

Your internet settings are automatically restored to what they were before.

---

## Technical Details

HSIP uses proven cryptographic standards:

| Component | Technology |
|-----------|------------|
| Identity | Ed25519 signatures |
| Key Exchange | X25519 |
| Encryption | ChaCha20-Poly1305 |
| Consent | Capability tokens with expiration |

For developers and technical users, see:
- [API Reference](docs/API_REFERENCE.md)
- [Protocol Specification](docs/PROTOCOL_SPEC.md)
- [Examples](docs/EXAMPLES.md)

---

## Architecture

```
hsip-cli.exe      Background daemon with HTTP API (port 8787)
hsip-gateway.exe  HTTP/HTTPS proxy with tracker blocking (port 8080)
hsip-tray.exe     System tray icon showing protection status
```

---

## Verify Protection

Check if HSIP is running:
```
curl http://127.0.0.1:8787/status
```

Expected response:
```json
{
  "protected": true,
  "active_sessions": 1,
  "cipher": "ChaCha20-Poly1305"
}
```

---

## Security

HSIP is currently in alpha. While the cryptography is solid, the software is still maturing.

**Report vulnerabilities privately to:** nyxsystemsllc@gmail.com

---

## License

**HSIP Community License (Non-Commercial)**

- **Free** for personal use, education, research, and open-source projects
- **Commercial use requires a license** from Nyx Systems LLC

### What counts as commercial use?
- Selling software that includes HSIP
- Using HSIP in a business
- Integrating HSIP into commercial products
- Offering HSIP as part of a paid service

### Want to use HSIP commercially?
Contact: **nyxsystemsllc@gmail.com**

See [LICENSE](LICENSE) for full terms.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING](docs/CONTRIBUTING.md) for guidelines.

---

## Contact

- **Issues:** https://github.com/rewired89/HSIP/issues
- **Email:** nyxsystemsllc@gmail.com

---

Copyright (c) Nyx Systems LLC. All rights reserved.
