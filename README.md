This is not an official python ProtonMail API client. it allows you to read, send and delete messages in protonmail, as well as render a ready-made template with embedded images.

> [!NOTE]
> Congratulations, no need more to execute OpenPGP.js via playwright 🎉🎉🎉

## Installation
``` 
pip install protonmail-api-client
```

## Using
```py
from protonmail import ProtonMail

username = "YouAddress@proton.me"
password = "YourPassword123"

proton = ProtonMail()
proton.login(username, password)

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
recipients = ["to@gmail.com", "to2@gmail.com"]  # You can’t send to @proton.me/@protonmail.com yet
subject = "My first message"
body = "<html><body>hello, i sent my first mail!</body></html>"  # html or just text

new_message = proton.create_message(
    recipients=recipients,
    subject=subject,
    body=body
)

sent_message = proton.send_message(new_message)

# Wait for new message
new_message = proton.wait_for_new_message(interval=1, timeout=60, rise_timeout=False, read_message=True)
if 'spam' in new_message.body:
    # Delete spam
    proton.delete_messages([new_message])

# Save session, you do not have to re-enter your login, password, pgp key, passphrase
# WARNING: the file contains sensitive data, do not share it with anyone,
# otherwise someone will gain access to your mail.
proton.save_session('session.pickle')

# Load session
proton = ProtonMail()
proton.load_session('session.pickle', auto_save=True)
# Autosave is needed to save tokens if they are updated
# (the access token is only valid for 24 hours and will be updated automatically)

# Getting a list of all sessions in which you are authorized
proton.get_all_sessions()

# Revoke all sessions except the current one
proton.revoke_all_sessions()
```

### event polling
Event polling. Polling ends in 3 cases:
1. Callback returns not `None`.
2. The callback raises the `SystemExit` exception.
3. Timeout ends.

For example, wait indefinitely until 2 messages arrive.
```python
def callback(response: dict, new_messages: list):
    messages = response.get('Messages', [])
    new_messages.extend(messages)
    if len(new_messages) >= 2:
        raise SystemExit

new_messages = []
proton.event_polling(callback, new_messages)
print(new_messages)
```
