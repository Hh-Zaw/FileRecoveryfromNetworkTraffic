# HTTP File Recovery Script

A Bash script to **recover files transferred over HTTP** from a captured network trace (`.pcap`).  
It uses [Wireshark’s tshark](https://www.wireshark.org/docs/man-pages/tshark.html) to export HTTP objects, organizes them into directories, and produces an `audit.txt` with file metadata for forensic analysis.

---

##  Features
- Export HTTP objects from `.pcap` files.
- Organize recovered files in `RecoveredFiles/http/`.
- Generate an `audit.txt` with:
  - Filename
  - Packet/stream info (if available)
  - File size
  - MD5, SHA1, SHA256 hashes
  - File type (`file` command)
  - Notes (`OK`, `truncated`, `zero-bytes`, `error-content`)
- Lightweight and CLI-friendly, built entirely with Bash + standard Linux tools.

---

##  Requirements
- `bash`
- `tshark` (Wireshark CLI)
- `file`
- `md5sum`, `sha1sum`, `sha256sum`
- GNU coreutils (`mkdir`, `stat`, `awk`, etc.)

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y tshark file coreutils
