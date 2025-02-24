# WebScanX

**WebScanX** is a comprehensive web scanning tool that helps you discover subdomains, detect technologies, check for important files, detect WAFs, and brute-force directories on a target domain.

## Features

- **Subdomain enumeration**: Discover subdomains associated with a target domain.
- **Web technology detection**: Identify technologies used by the target website.
- **File discovery**: Search for important files like `robots.txt`, `security.txt`, etc.
- **WAF detection**: Identify the presence of Web Application Firewalls (WAFs).
- **Directory brute-forcing**: Brute-force directories on the target website.

## Installation

### Step 1: Clone the repository

Clone the repository using the following command:

```bash
git clone https://github.com/sczxw/WebScanX.git
```

Navigate into the WebScanX directory:

```bash
cd WebScanX
```

### Step 2: Install dependencies

To use this tool, you need to install the required dependencies. You can install them using `pip` with the following command:

```bash
pip install -r requirements.txt
```

The dependencies include:

- `requests`
- `dnspython`
- `Wappalyzer`
- `wafw00f`
- `colorama`

## Usage

Once you have installed the dependencies, you can run the tool as follows:

```bash
python webscanx.py
```

Or, if you're on a Unix-like system and want to execute the script directly:

```bash
./webscanx.py
```

---

### Notes:

- Ensure that you have the necessary permissions to execute `webscanx.py` if running the script directly (`chmod +x webscanx.py`).
- Always use this tool responsibly and within the legal boundaries of penetration testing or security research.

---

