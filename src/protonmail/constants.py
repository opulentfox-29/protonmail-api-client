"""Constants."""

PM_APP_VERSION_ACCOUNT = 'web-account@5.0.255.0'
PM_APP_VERSION_MAIL = 'web-mail@5.0.66.5'
PM_APP_VERSION_DEV = 'Other'
API_VERSION = '4'
SRP_LEN_BYTES = 256
SALT_LEN_BYTES = 10

DEFAULT_HEADERS = {
    'authority': 'account.proton.me',
    'accept': 'application/vnd.protonmail.v1+json',
    'accept-language': 'en-US,en;q=0.5',
    'content-type': 'application/json',
    'origin': 'https://account.proton.me',
    'referer': 'https://account.proton.me/mail',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'x-pm-appversion': PM_APP_VERSION_ACCOUNT,
    'x-pm-apiversion': API_VERSION,
    'x-pm-locale': 'en_US',
}

urls_api = {
    'api': 'https://api.protonmail.ch/api',
    'mail': 'https://mail.proton.me/api',
    'account': 'https://account.proton.me/api',
    'account-api': 'https://account-api.proton.me',
    'assets': 'https://account.proton.me/assets'
}

colors = {
    "green": "\x1b[32m",
    "red": "\x1b[31m",
    "yellow": "\033[93m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}
