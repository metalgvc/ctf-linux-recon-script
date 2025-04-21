## 🛠️ linctf - CTF Linux Recon & Exploitation Toolkit

**linctf** is an all-in-one Bash script designed to assist in CTF and penetration testing scenarios on Linux systems. It helps you gather sensitive information, transfer files, scan for open ports, monitor filesystem activity, brute-force users.

> ⚠️ For educational and authorized use only.

---

### Usage

```bash
./linctf.sh <module> [params]
```

---

### Gather Information

| Module          | Description                                                              |
|-----------------|--------------------------------------------------------------------------|
| `info`          | Fast recon: users, netstat, and more                                     |
| `files`         | Search for databases, backups, config files, scripts, SUID/GUID binaries |
| `passwords`     | Search for passwords, API keys, tokens, and SSH keys (slow)              |
| `logs`          | Look for juicy info inside log files                                     |
| `searchw`       | Find writable files and directories                                      |
| `installedsoft` | List installed software and packages                                     |
| `gtfobins`      | Check installed GTFOBins https://gtfobins.github.io/                     |

---

### Ports & Network Scanners

| Module        | Description                                             |
|---------------|---------------------------------------------------------|
| `networkscan` | scan internal network(s) for avail hosts                |
| `ncscan`      | Fast TCP port scan using `nc` (preferred method)        |
| `bashscan`    | Lightweight TCP port scan using Bash built-ins          |

---

### File Transfer

| Module     | Description                                                   |
|------------|---------------------------------------------------------------|
| `sendf`    | Send a file to a remote server via HTTP[S], SMB, or FTP       |
| `download` | Download a file from HTTP[S], SMB, or FTP                     |

---

### Local Servers

| Module      | Description                |
|-------------|----------------------------|
| `httpserver`| Start a Python HTTP server |

---

### Monitoring

| Module  | Description                        |
|---------|------------------------------------|
| `fsmon` | Monitor file system changes        |

---

### Brute Force

| Module     | Description                                      |
|------------|--------------------------------------------------|
| `localuser`| Brute-force local user credentials via `su -`    |

---

### Other Tools

| Module         | Description                                    |
|----------------|------------------------------------------------|
| `rexec`        | Execute a remote script via bash or sh         |
| `sectooldetect`| Detect common security monitoring tools        |
| `obfuscate`    | Obfuscate your shell scripts                   |

---

### Help
run the script without parameters
```bash
./linctf.sh
```

---

### ⚠️ Disclaimer

This script is intended for **educational purposes** and **authorized penetration testing** only. Do **not** use this on systems without explicit permission. The author is not responsible for any misuse or damage caused.

---

### 📄 License

MIT License
