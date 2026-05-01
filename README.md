# 🕵️ WhoCord

**Turn any username or Discord ID into a full identity profile.**  
WhoCord automatically scans Discord messages across mutual guilds for tracking links, resolves them to find connected social media accounts, cross‑references **700+ sites**, runs deep email intelligence, extracts EXIF data from avatars, and generates a polished AI‑powered OSINT report — all from a simple interactive menu.

---

## ⚡ What makes WhoCord different?

Most OSINT tools stop at finding profiles. WhoCord goes further:

- **Discord‑native link resolution** – extracts and resolves Instagram, TikTok, Facebook, and Twitter tracking links shared by a target user.  
- **Full identity pipeline** – names, emails, locations, breach data, GitHub history, and even avatar metadata are pulled together into one structured intelligence snapshot.  
- **30+ integrated tools** – Sherlock, Maigret, Naminter, Blackbird, Holehe, h8mail, GitFive, GHunt, Scylla, Socialscan, and more, all controlled from a single interface.  
- **AI‑generated reports** – a LLaMA 3.3 (via Groq) summary that interprets the results for you, ready to read or share.  
- **Secure token storage** – API keys are stored in your operating system’s encrypted keyring, never in plain text.

---

## 📦 Features

### 🔍 Discord link extraction
- Searches messages across **all mutual guilds** (or a specific guild) for shared links.  
- Identifies tracking parameters (`igshid`, `fbclid`, `ttclid`, etc.) in Instagram, TikTok, Facebook, and Twitter URLs.  
- Resolves those tracking links using ShareTrace to reveal the original sharer’s profile.

### 🌐 Username discovery
- Scans **700+ websites** using Sherlock, Maigret, Naminter, Blackbird, and Social‑Analyzer.  
- Spiders discovered URLs with Sociopath and Linkook to uncover even more related accounts.  
- Filters false positives with Socialscan before scraping.  
- **Blackbird** now brings 600+ additional sites with email‑based search and avatar extraction.

### ✉️ Manual email input
- You can optionally provide an email address in manual mode; it will be searched via Blackbird’s email detection and also forwarded to the email intelligence pipeline (Holehe, h8mail, etc.).  
- No more automatic email guessing – only real, user‑supplied emails are processed, keeping results clean.

### 📄 Profile scraping
- Pulls public profile pages (GitHub, Twitter, Reddit, YouTube, etc.) with built‑in scrapers.  
- Extracts display names, bios, avatars, follower counts, blog links, and embedded emails.  
- Uses **Socid‑Extractor** to mine structured identity data from generic pages.

### ✉️ Email intelligence
- Runs each email through:  
  - **Holehe** – checks which sites the email is registered on  
  - **h8mail** – breach/compromise status  
  - **HIBP** (HaveIBeenPwned) – known data breaches  
  - **Emailrep.io** – reputation and risk score  
  - **GHunt** – Google account information (requires `ghunt login` once)  
  - **Scylla** – breach database lookup

### 🐙 GitHub deep dive
- Collects public GitHub activity, pinned repositories, and profile details.  
- Uses **GitFive** to dig up commit history, possible email addresses, and full name history.

### 📷 Avatar analysis
- Downloads avatar images and extracts **EXIF metadata** (GPS coordinates, camera model, date taken).  
- Runs **reverse image search** via SauceNAO to find where else the image appears.

### 🌍 Domain & history checks
- **WHOIS** lookups on blog domains found in profiles.  
- **Wayback Machine** snapshot availability for all discovered URLs.

### 🧠 Name analysis & identity scoring
- Predicts name origin, gender, and subregion using Nametrace.  
- Computes fuzzy similarity between discovered names.  
- Generates **confidence scores** to rank the most likely real‑world identity.

### 📝 AI report
- With a Groq API key, WhoCord sends the collected evidence to LLaMA 3.3 and gets back a structured markdown report containing:  
  - Executive summary  
  - Identity assessment  
  - Digital footprint  
  - Risk indicators  
  - Recommended next steps

---

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Siv-nick/WhoCord.git
cd WhoCord
```

If you don’t have `git`, download the ZIP from the green **<> Code** button and extract it.

### 2. Create a Python virtual environment (highly recommended)

This keeps all dependencies isolated and avoids conflicts with other Python projects.

```bash
python3 -m venv venv
```

Activate the environment:

- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```
- **Windows (Command Prompt)**:
  ```cmd
  venv\Scripts\activate
  ```
- **Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate
  ```

Your terminal prompt should now show `(venv)` at the beginning. To deactivate later, just type `deactivate`.

### 3. Install WhoCord and its Python dependencies

```bash
pip install -e .
```

This installs WhoCord **and** all required Python libraries (`requests`, `beautifulsoup4`, `keyring`, `jinja2`, `openai`, `socid-extractor`, etc.).

### 4. Install external command‑line tools

WhoCord calls several standalone OSINT programs that must be available on your system. Install them with:

```bash
pip install sherlock-project maigret holehe h8mail gitfive naminter linkook sociopath
```

### 5. Install Blackbird (email & username search on 600+ sites)

Blackbird must be cloned into the project folder and its dependencies installed:

```bash
git clone https://github.com/p1ngul1n0/blackbird
cd blackbird
pip install -r requirements.txt
cd ..
```

> **Important:** Blackbird needs a large data file (`wmn-data.json`) that is normally fetched via Git LFS. If you encounter a `FileNotFoundError` for `data/wmn-data.json`, run these commands:

```bash
cd blackbird
git lfs install
git lfs pull
cd ..
```

If Git LFS isn’t available, you can also download the file manually from the **WhatsMyName** project:  
[https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json](https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json)  
Place it directly inside `blackbird/data/`.

### 6. Optional but powerful extras

```bash
# WHOIS lookups
sudo apt install whois          # Linux
brew install whois               # macOS

# GHunt for Google account info (requires `ghunt login` after install)
pip install ghunt
ghunt login
```

When you first launch WhoCord, it will automatically check which tools are missing and tell you exactly how to install them.

### 7. Launch WhoCord

```bash
discord-osint
```

The interactive menu will appear. You’re ready to investigate!

---

## 🚀 Usage

### Interactive menu (recommended)

```
==================================================
        OSINT IDENTITY PROFILING PIPELINE
==================================================
1. Toggle investigation tools
2. Set tokens / API keys
3. Start investigation
4. Save config and exit
5. Toggle debug mode
==================================================
```

- **Option 1** – Enable or disable any of the 33 tools with a single keypress.  
- **Option 2** – Enter your API tokens. They are saved securely in your OS keyring.  
  - Discord token (required for Discord mode)  
  - GitHub token (increases API rate limits)  
  - Groq API key (enables AI report)  
  - Instagram session (optional, reserved for future Toutatis integration)  
- **Option 3** – Choose `Manual` (investigate a username) or `Discord` (investigate a Discord user ID).  
  - In **Manual mode**, you can optionally provide an email address to be searched via Blackbird and the email intelligence pipeline.  
- **Option 4** – Save current configuration to `config.json` (tool toggles and mode preferences) and exit.  
- **Option 5** – Toggle debug mode. When ON, all subprocess commands are printed live to the console, and a debug log is saved to `investigation_cache/debug_logs/`.

### Command‑line mode

You can run an investigation directly without the menu:

```bash
discord-osint --mode manual --target someusername --output html --debug
```

| Argument | Description |
|----------|-------------|
| `--mode` | `discord` or `manual` |
| `--target` | username (manual) or Discord user ID (discord) |
| `--token` | Discord user token (overrides saved one) |
| `--guild` | Discord guild ID (for single‑guild search) |
| `--output` | `json`, `markdown`, or `html` |
| `--debug` | Enable debug logging |
| `--interactive` | Force the interactive menu |

---

## 📂 Output files

All results are saved in the **`investigation_cache/`** folder inside the project directory:

- `intel_<target_id>_<timestamp>.json` – the complete intelligence snapshot (structured JSON)
- `report_<target_id>_<timestamp>.md` – AI‑generated markdown report (if Groq is enabled)
- `report_<target_id>_<timestamp>.html` – interactive HTML report (if `--output html` is used)

Additionally, raw outputs from Blackbird and Socialscan are archived in:
- `investigation_cache/blackbird_output/`
- `investigation_cache/socialscan_output/`

---

## 🧰 Tools & technologies

WhoCord orchestrates these fantastic open‑source OSINT projects:

| Tool | Purpose |
|------|---------|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across 400+ sites |
| [Maigret](https://github.com/soxoj/maigret) | Full‑spectrum username search with metadata |
| [Blackbird](https://github.com/p1ngul1n0/blackbird) | Email & username search on 600+ sites with avatar extraction |
| [Holehe](https://github.com/megadose/holehe) | Checks which sites an email is registered on |
| [h8mail](https://github.com/khast3x/h8mail) | Email breach & compromise checker |
| [GitFive](https://github.com/mxrch/gitfive) | GitHub user intelligence |
| [Naminter](https://github.com/s0md3v/naminter) | Username search with smart filtering |
| [Linkook](https://github.com/JackJu1y/Linkook) | Deep URL discovery across platforms |
| [Sociopath](https://github.com/s0md3v/sociopath) | Profile spider & identity enrichment |
| [Socid‑Extractor](https://github.com/soxoj/socid-extractor) | Extracts structured identity data from HTML |
| [Socialscan](https://github.com/iojw/socialscan) | Validates social media profile availability |
| [ShareTrace](https://github.com/s0md3v/sharetrace) | Resolves social media tracking links |
| [Scylla](https://github.com/MandConsultingGroup/Scylla) | Leak database query |
| [NameTrace](https://github.com/s0md3v/nametrace) | Name origin & gender prediction |
| [ExifRead](https://github.com/ianare/exif-py) | EXIF metadata extraction from images |
| [SauceNAO](https://saucenao.com/) | Reverse image search (via API) |
| [Groq](https://groq.com) | LLaMA 3.3 AI report generation |

---

## 🆕 Updates 1.0.1

- **Blackbird integration** – now uses Blackbird for email‑based discovery and 600+ additional username sites.
- **Email guesser removed**
- **GHunt login** – GHunt now requires a one‑time `ghunt login` (see installation step 6).

---

## 🔒 Security & privacy

- **Tokens are never stored in plain text.** They are kept in your OS keyring (Windows Credential Manager, macOS Keychain, or Linux Secret Service / KWallet).  
- The `config.json` file only contains tool toggles and preferences – no secrets.  
- All investigation data stays on your machine inside the `investigation_cache/` folder.

---

## ⚠️ Disclaimer

WhoCord is intended for **educational purposes** and **authorised security testing** only.  
Do not use it to stalk, harass, or violate anyone’s privacy.  
The author assumes no liability for misuse.

---

## 📜 License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
