This is not an official python ProtonMail API client. it allows you to read, send and delete messages in protonmail, as well as render a ready-made template with embedded images.

> Unfortunately, I could not find an analogue of DecryptSessionKeys from OpenPG.js, so this uses Playwright to execute js. if you have any ideas write to me

## Installation
Install requirements:
``` 
pip install protonmail-api-client
```
Install Playwright:
```
playwright install
```

# Getting Started
### Get PGP private key and passphrase
Go to the [Email encryption keys](https://account.proton.me/u/0/mail/encryption-keys#addresses) section, click on "Export private key" (NOT the Account keys), create the passphrase.
![1.png](https://raw.githubusercontent.com/opulentfox-29/protonmail-api-client/master/assets/1.png)

```py
from protonmail.client import ProtonMail

username = "YouAddress@proton.me"
password = "YourPassword123"

proton = ProtonMail()
proton.login(username, password)

private_key = 'privatekey.YourAddress@proton.me-123...89.asc'
passphrase = 'YourPassphrase'
proton.pgp_import(private_key, passphrase=passphrase)

# Get a list of all messages
messages = proton.get_messages()

# Read the latest message
message = proton.read_message(messages[0])
print(message.sender.address)  # sender address
print(message.subject)  # subject
print(message.body)
# <html><body><div>it's my image: <img src="cid:1234@proton.me">....

# Render the template, images downloading, converting to BASE64 and insert into html
proton.render(message)
# This is a ready-made html page, with all the pictures, you can save it right away
with open('message.html', 'w', encoding='utf-8') as f:
    f.write(message.body)
print(message.body)
# <html><body><div>it's my image: <img src="data:image/png;base64, iVBORw0K..">....

# Download file from message
first_file = message.attachments[0]
proton.download_files([first_file])
with open(f'{first_file.name}', 'wb') as f:
    f.write(first_file.content)

# Send message
recipients = ["to@proton.me", "to2@proton.me"]
subject = "My first message"
body = "<html><body>hello, i sent my first mail!</body></html>"  # html or just text

new_message = proton.create_message(
    recipients=recipients,
    subject=subject,
    body=body
)

sent_message = proton.send_message(new_message)

# Delete messages
proton.delete_messages([message])

# Save session, you do not have to re-enter your login, password, pgp key, passphrase
# WARNING: the file contains sensitive data, do not share it with anyone,
# otherwise someone will gain access to your mail.
proton.save_session('session.pickle')

# Load session
proton = ProtonMail()
proton.load_session('session.pickle')

# Getting a list of all sessions in which you are authorized
proton.get_all_sessions()

# Revoke all sessions except the current one
proton.revoke_all_sessions()
```
