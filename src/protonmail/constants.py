"""Constants."""

PM_APP_VERSION_ACCOUNT = 'web-account@5.0.42.1'
API_VERSION = '4'
SRP_LEN_BYTES = 256
SALT_LEN_BYTES = 10

DEFAULT_HEADERS = {
    'authority': 'account.proton.me',
    'accept': 'application/vnd.protonmail.v1+json',
    'accept-language': 'en-US,en;q=0.5',
    'content-type': 'application/json',
    'origin': 'https://account.proton.me',
    'referer': 'https://account.proton.me',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                  ' Chrome/114.0.0.0 Safari/537.36',
    'x-pm-appversion': 'Other',
    'x-pm-apiversion': API_VERSION,
}

urls_api = {
    'api': 'https://api.protonmail.ch/api',
    'mail': 'https://mail.proton.me/api',
    'account': 'https://account.proton.me/api',
    'assets': 'https://account.proton.me/assets'
}

colors = {
    "green": "\x1b[32m",
    "red": "\x1b[31m",
    "yellow": "\033[93m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}
