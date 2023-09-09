"""Client for api protonmail."""

import asyncio
import pickle
import string
import time
from copy import deepcopy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from base64 import b64encode, b64decode
import random
from math import ceil
from threading import Thread
from typing import Optional, Coroutine, Union

import unicodedata
from requests import Session
from requests.models import Response
from aiohttp import ClientSession, TCPConnector
from requests_toolbelt import MultipartEncoder
from tqdm.asyncio import tqdm_asyncio

from .models import Attachment, Message, UserMail, Conversation
from .constants import DEFAULT_HEADERS, urls_api
from .utils.pysrp import User
from .logger import Logger
from .pgp import PGP


class ProtonMail:
    """
    Client for api protonmail.
    """
    def __init__(self, logging_level: Optional[int] = 2, logging_func: Optional[callable] = print):
        """
        :param logging_level: logging level 1-4 (DEBUG, INFO, WARNING, ERROR), default 2[INFO].
        :type logging_level: ``int``
        :param logging_func: logging function. default print.
        :type logging_func: ``callable``
        """
        self.logger = Logger(logging_level, logging_func)
        self.pgp = PGP()
        self.user = None
        self.account_id = ''
        self.account_email = ''
        self.account_name = ''

        self.session = Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def login(self, username: str, password: str) -> None:
        """
        Authorization in ProtonMail.

        :param username: your ProtonMail address.
        :type username: ``str``
        :param password: your password.
        :type password: ``str``
        :returns: :py:obj:`None`
        """
        data = {'Username': username}

        info = self.session.post('https://api.protonmail.ch/auth/info', json=data).json()
        client_challenge, client_proof, spr_session = self._parse_info_before_login(info, password)

        auth = self.session.post('https://api.protonmail.ch/auth', json={
            'Username': username,
            'ClientEphemeral': client_challenge,
            'ClientProof': client_proof,
            'SRPSession': spr_session,
        }).json()

        if self._login_process(auth):
            self.logger.info("login success", "green")
        else:
            self.logger.error("login failure")

        self._parse_info_after_login(auth)

    def read_message(
            self,
            message_or_id: Union[Message, str],
            mark_as_read: Optional[bool] = True
    ) -> Message:
        """
        Read message.

        :param message_or_id: Message or id of the message you want to read.
        :type message_or_id: ``str``

        :param mark_as_read: Mark message as read.
        :type mark_as_read: ``bool``
        :returns: :py:obj:`Message`
        """
        _id = message_or_id.id if isinstance(message_or_id, Message) else message_or_id
        response = self._get('mail', f'mail/v4/messages/{_id}')
        message = response.json()['Message']
        message = self._convert_dict_to_message(message)

        message.body = self.pgp.decrypt(message.body)
        self._multipart_decrypt(message)

        if mark_as_read:
            self.mark_messages_as_read([message])

        return message

    def get_messages(self, page_size: Optional[int] = 150) -> list[Message]:
        """
        Get all messages, sorted by time.

        :param page_size: number of posts per page. maximum number 150.
        :type page_size: ``int``
        :returns: :py:obj:`list[Message]`
        """
        count_page = ceil(self.get_messages_count()[5]['Total'] / page_size)
        args_list = [(page_num, page_size) for page_num in range(count_page)]
        messages_lists = self._async_helper(self._async_get_messages, args_list)
        messages_dict = self._flattening_lists(messages_lists)
        messages = [self._convert_dict_to_message(message) for message in messages_dict]

        return messages

    def get_messages_by_page(self, page: int, page_size: Optional[int] = 150) -> list[Message]:
        """Get messages by page, sorted by time."""
        args_list = [(page, page_size)]
        messages_lists = self._async_helper(self._async_get_messages, args_list)
        messages_dict = self._flattening_lists(messages_lists)
        messages = [self._convert_dict_to_message(message) for message in messages_dict]

        return messages

    def get_messages_count(self) -> list[dict]:
        """get total count of messages, count of unread messages."""
        response = self._get('mail', 'mail/v4/messages/count').json()['Counts']
        return response

    def read_conversation(self, conversation_or_id: Union[Conversation, str]) -> list[Message]:
        """
        Read conversation by conversation or ID.

        :param conversation_or_id: Conversation or id of the conversation you want to read.
        :type conversation_or_id: ``Conversation`` or ``str``
        :returns: :py:obj:`Message`
        """
        _id = (
            conversation_or_id.id
            if isinstance(conversation_or_id, Conversation)
            else conversation_or_id)
        response = self._get('mail', f'mail/v4/conversations/{_id}')
        messages = response.json()['Messages']
        messages = [self._convert_dict_to_message(message) for message in messages]
        messages[-1].body = self.pgp.decrypt(messages[-1].body)
        self._multipart_decrypt(messages[-1])

        return messages

    def get_conversations(self, page_size: Optional[int] = 150) -> list[Conversation]:
        """Get all conversations, sorted by time."""
        count_page = ceil(self.get_messages_count()[0]['Total'] / page_size)
        args_list = [(page_num, page_size) for page_num in range(count_page)]
        conversations_lists = self._async_helper(self._async_get_conversations, args_list)
        conversations_dict = self._flattening_lists(conversations_lists)
        conversations = [self._convert_dict_to_conversation(c) for c in conversations_dict]

        return conversations

    def get_conversations_by_page(
            self,
            page: int,
            page_size: Optional[int] = 150
    ) -> list[Conversation]:
        """Get conversations by page, sorted by time."""
        args_list = [(page, page_size)]
        conversations_lists = self._async_helper(self._async_get_conversations, args_list)
        conversations_dict = self._flattening_lists(conversations_lists)
        conversations = [self._convert_dict_to_conversation(c) for c in conversations_dict]

        return conversations

    def get_conversations_count(self) -> list[dict]:
        """get total count of conversations, count of unread conversations."""
        response = self._get('mail', 'mail/v4/conversations/count').json()['Counts']
        return response

    def render(self, message: Message) -> None:
        """
        Downloads pictures, decrypts, encodes in BASE64 and inserts into HTML.

        The finished template can be immediately saved to an .html file.
        :param message: the message you want to render
        :type message: ``Message``
        :returns: :py:obj:`None`
        """
        images_for_download = [
            img
            for img in message.attachments
            if img.is_inserted and not img.is_decrypted
        ]
        self.download_files(images_for_download)
        images = [img for img in message.attachments if img.is_inserted]

        for image in images:
            image_b64 = b64encode(image.content).decode()
            template_before = f'src="cid:{image.cid}"'
            template_after = f'src="data:image/png;base64, {image_b64}"'
            message.body = message.body.replace(template_before, template_after)

    def download_files(self, attachments: list[Attachment]) -> list[Attachment]:
        """
        Downloads and decrypts files from the list.

        :param attachments: list of files
        :type attachments: ``list``
        :returns: :py:obj:`list[attachment]`
        """
        args_list = [(attachment, ) for attachment in attachments]
        results = self._async_helper(self._async_download_file, args_list)
        threads = [Thread(target=self._file_decrypt, args=result) for result in results]
        [t.start() for t in threads]
        [t.join() for t in threads]

        return attachments

    def send_message(self, message: Message) -> Message:
        """
        Send the message.

        :param message: The message you want to send.
        :type message: ``Message``
        :returns: :py:obj:`Message`
        """
        draft = self.create_draft(message, decrypt_body=False)
        multipart = self._multipart_encrypt(message)

        headers = {
            "Content-Type": multipart.content_type
        }
        params = {
            'Source': 'composer',
        }
        for recipient in message.recipients:
            self.__check_email_address(recipient)

        response = self._post(
            'mail',
            f'mail/v4/messages/{draft.id}',
            headers=headers,
            params=params,
            data=multipart
        ).json()['Sent']
        sent_message = self._convert_dict_to_message(response)
        sent_message.body = self.pgp.decrypt(sent_message.body)
        self._multipart_decrypt(sent_message)

        return sent_message

    def create_draft(self, message: Message, decrypt_body: Optional[bool] = True) -> Message:
        """Create the draft."""


        pgp_body = self.pgp.encrypt(message.body)

        data = {
            'Message': {
                'ToList': [],
                'CCList': [],
                'BCCList': [],
                'Subject': message.subject,
                'Attachments': [],
                'MIMEType': 'text/html',
                'RightToLeft': 0,
                'Sender': {
                    'Name': self.account_name,
                    'Address': self.account_email,
                },
                'AddressID': self.account_id,
                'Unread': 0,
                'Body': pgp_body,
            },
        }
        for recipient in message.recipients:
            data['Message']['ToList'].append(
                {
                    'Name': recipient.name,
                    'Address': recipient.address,
                }
            )

        response = self._post(
            'mail',
            'mail/v4/messages',
            json=data
        ).json()['Message']

        draft = self._convert_dict_to_message(response)

        if decrypt_body:
            draft.body = self.pgp.decrypt(draft.body)
            self._multipart_decrypt(draft)

        return draft

    def delete_messages(self, messages_or_ids: list[Union[Message, str]]) -> None:
        """Delete messages."""
        ids = [i.id if isinstance(i, Message) else i for i in messages_or_ids]
        data = {
            "IDs": ids,
        }
        self._put('mail', 'mail/v4/messages/delete', json=data)

    def mark_messages_as_read(self, messages_or_ids: list[Union[Message, str]]) -> None:
        """
        Mark as read messages.

        :param messages_or_ids: list of messages or messages id.
        :type messages_or_ids: :py:obj:`Message`
        """
        ids = [i.id if isinstance(i, Message) else i for i in messages_or_ids]
        data = {
            'IDs': ids,
        }
        self._put('mail', 'mail/v4/messages/read', json=data)

    def wait_for_new_message(
            self,
            *args,
            interval: int = 1,
            timeout: int = 0,
            rise_timeout: bool = False,
            **kwargs
    ) -> Union[Message, None]:
        """
        Wait for a new message.

        :param interval: event check interval. default `1`
        :type interval: `int`
        :param timeout: maximum polling time in seconds. 0 = infinity. default `infinity`.
        :type timeout: `int`
        :param rise_timeout: raise exception on `timeout` completion. default `False`.
        :type rise_timeout: `bool`
        :returns :  new message.
        :rtype: `Message`
        :raises TimeoutError: at the end of the `timeout` only if the `rise_timeout` is `True`
        """
        def func(response: dict):
            messages = response.get('Messages')
            if messages:
                new_message = self._convert_dict_to_message(messages[0]['Message'])
                return new_message
            return None
        message = self.event_polling(
            func,
            *args,
            interval=interval,
            timeout=timeout,
            rise_timeout=rise_timeout,
            **kwargs,
        )
        return message

    def event_polling(
            self,
            callback: callable,
            *args: any,
            interval: int = 1,
            timeout: int = 0,
            rise_timeout: bool = False,
            **kwargs: any
    ) -> Union[any, None]:
        """
        Event polling.
        Polling ends in 3 cases:
        1. Callback returns not `None`.
        2. The callback raises the `SystemExit` exception.
        3. Timeout ends.

        :param callback: event handling function.
        :type callback: `function`
        :param args: positional arguments passed in `callback`
        :type args: `any`
        :param interval: event check interval. default `1`
        :type interval: `int`
        :param timeout: maximum polling time in seconds. zero equals infinity. default `infinity`.
        :type timeout: `int`
        :param rise_timeout: raise exception on `timeout` completion. default `False`.
        :type rise_timeout: `bool`
        :param kwargs: named arguments passed in `callback`.
        :type kwargs: `any`
        :returns :  the same as the `callback`.
        :raises TimeoutError: at the end of the `timeout` only if the `rise_timeout` is `True`
        """
        response = self._get('mail', 'core/v4/events/latest').json()
        event_id = response['EventID']
        if timeout:
            start_pooling_time = time.time()
            end_pooling_time = start_pooling_time + timeout
        else:
            end_pooling_time = float('inf')

        while time.time() <= end_pooling_time:
            response = self._get('mail', f'core/v4/events/{event_id}')
            start_time = time.time()
            response = response.json()
            event_id = response.get('EventID', event_id)
            end_time = start_time + interval
            try:
                returned = callback(response, *args, **kwargs)
                if returned is not None:
                    return returned
            except SystemExit:
                return None
            need_sleep = end_time - time.time()
            if need_sleep < 0:
                continue
            time.sleep(need_sleep)
        if rise_timeout:
            raise TimeoutError
        return None

    def pgp_import(self, private_key: str, passphrase: str) -> None:
        """
        Import private pgp key and passphrase.

        :param private_key: your private pgp key that you exported from ProtonMail settings.
                            example: ``privatekey.YourACC@proton.me-12...99.asc``
        :type private_key: ``str``, ``path``, ``file``
        :param passphrase: the passphrase you created when exporting the private key.
        :type passphrase: ``str``
        """
        self.pgp.import_pgp(private_key, passphrase)

    def get_user_info(self) -> dict:
        """User information."""
        return self._get('account', 'core/v4/users').json()

    def get_all_sessions(self) -> dict:
        """Get a list of all sessions."""
        return self._get('account', 'auth/v4/sessions').json()

    def revoke_all_sessions(self) -> dict:
        """revoke all sessions except the current one."""
        return self._delete('account', 'auth/v4/sessions').json()

    def save_session(self, path: str) -> None:
        """
        Saving the current session to a file for later loading.

        WARNING: the file contains sensitive data, do not share it with anyone,
        otherwise someone will gain access to your mail.
        """
        sliced_aes256_keys = dict(list(self.pgp.aes256_keys.items())[:100])
        pgp = {
            'public_key': self.pgp.public_key,
            'private_key': self.pgp.private_key,
            'passphrase': self.pgp.passphrase,
            'aes256_keys': sliced_aes256_keys,
        }
        account = {
            'id': self.account_id,
            'email': self.account_email,
            'name': self.account_name,
        }
        headers = dict(self.session.headers)
        cookies = self.session.cookies.get_dict()
        options = {
            'pgp': pgp,
            'account': account,
            'headers': headers,
            'cookies': cookies,
        }
        with open(path, 'wb') as file:
            pickle.dump(options, file)

    def load_session(self, path: str) -> None:
        """Loading a previously saved session."""
        with open(path, 'rb') as file:
            options = pickle.load(file)

        pgp = options['pgp']
        account = options['account']
        headers = options['headers']
        cookies = options['cookies']

        self.pgp.public_key = pgp['public_key']
        self.pgp.private_key = pgp['private_key']
        self.pgp.passphrase = pgp['passphrase']
        self.pgp.aes256_keys = pgp['aes256_keys']

        self.account_id = account['id']
        self.account_email = account['email']
        self.account_name = account['name']

        self.session.headers = headers
        for name, value in cookies.items():
            self.session.cookies.set(name, value)

    @staticmethod
    def create_mail_user(**kwargs) -> UserMail:
        """Create UserMail."""
        kwargs = deepcopy(kwargs)
        address = kwargs['address']
        if not kwargs.get('name'):
            kwargs['name'] = address
        return UserMail(**kwargs)

    @staticmethod
    def create_attachment(**kwargs) -> Attachment:
        """Create Attachment"""
        kwargs = deepcopy(kwargs)
        return Attachment(**kwargs)

    @staticmethod
    def create_message(**kwargs) -> Message:
        """Create Message."""
        kwargs = deepcopy(kwargs)
        recipients = kwargs.get('recipients', [])
        recipients = [
            {'address': recipient}
            if isinstance(recipient, str)
            else recipient
            for recipient in recipients
        ]
        kwargs['recipients'] = [
            ProtonMail.create_mail_user(**i)
            for i in recipients
        ]
        kwargs['attachments'] = [
            ProtonMail.create_attachment(**i)
            for i in kwargs.get('attachments', [])
        ]
        if kwargs.get('sender'):
            kwargs['sender'] = ProtonMail.create_mail_user(**kwargs.get('sender'))

        return Message(**kwargs)

    @staticmethod
    def create_conversation(**kwargs):
        """Create Conversation"""
        kwargs = deepcopy(kwargs)
        kwargs['recipients'] = [
            ProtonMail.create_mail_user(**i)
            for i in kwargs.get('recipients', [])
        ]
        kwargs['senders'] = [
            ProtonMail.create_mail_user(**i)
            for i in kwargs.get('senders', [])
        ]
        return Conversation(**kwargs)

    @staticmethod
    def _flattening_lists(list_of_lists: list[list[any]]) -> list[any]:
        flattened_list = [
            item
            for items_list in list_of_lists
            for item in items_list
        ]
        return flattened_list

    @staticmethod
    def _convert_dict_to_message(response: dict) -> Message:
        """
        Converts dictionary to message object.

        :param response: The dictionary from which the message will be created.
        :type response: ``dict``
        :returns: :py:obj:`Message`
        """
        sender = UserMail(
            response['Sender']['Name'],
            response['Sender']['Address'],
            response['Sender']
        )
        recipients = [
            UserMail(
                user['Name'],
                user['Address'],
                user
            ) for user in response['ToList']
        ]
        attachments_dict = response.get('Attachments', [])
        attachments = []
        for attachment in attachments_dict:
            is_inserted = attachment['Disposition'] == 'inline'
            cid = attachment['Headers'].get('content-id')
            if cid:
                cid = cid[1:-1]
            attachments.append(
                Attachment(
                    id=attachment['ID'],
                    name=attachment['Name'],
                    size=attachment['Size'],
                    type=attachment['MIMEType'],
                    is_inserted=is_inserted,
                    key_packets=attachment['KeyPackets'],
                    cid=cid,
                    extra=attachment
                )
            )

        message = Message(
            id=response['ID'],
            conversation_id=response['ConversationID'],
            subject=response['Subject'],
            unread=response['Unread'],
            sender=sender,
            recipients=recipients,
            time=response['Time'],
            size=response['Size'],
            body=response.get('Body', ''),
            type=response.get('MIMEType', ''),
            labels=response['LabelIDs'],
            attachments=attachments,
            extra=response,
        )
        return message

    @staticmethod
    def _convert_dict_to_conversation(response: dict) -> Conversation:
        """
        Converts dictionary to conversation object.

        :param response: The dictionary from which the conversation will be created.
        :type response: ``dict``
        :returns: :py:obj:`Conversation`
        """
        senders = [
            UserMail(
                user['Name'],
                user['Address'],
                user
            ) for user in response['Senders']
        ]
        recipients = [
            UserMail(
                user['Name'],
                user['Address'],
                user
            ) for user in response['Recipients']
        ]
        conversation = Conversation(
            id=response['ID'],
            subject=response['Subject'],
            senders=senders,
            recipients=recipients,
            num_messages=response['NumMessages'],
            num_unread=response['NumUnread'],
            time=response['Time'],
            size=response['Size'],
            labels=response['LabelIDs'],
            extra=response,
        )
        return conversation

    @staticmethod
    def _prepare_message(data: str) -> str:
        """Converting an unencrypted message into a multipart mime."""
        data_base64 = b64encode(data.encode())

        msg_mixed = MIMEMultipart('mixed')
        msg_alt = MIMEMultipart('alternative')
        msg_plain = MIMEText('', _subtype='plain')
        msg_related = MIMEMultipart('related')
        msg_base = MIMEText('', _subtype='html')

        msg_base.replace_header('Content-Transfer-Encoding', 'base64')
        msg_base.set_payload(data_base64, 'utf-8')

        msg_plain.replace_header('Content-Transfer-Encoding', 'quoted-printable')
        msg_plain.set_payload('hello', 'utf-8')

        msg_alt.attach(msg_plain)
        msg_related.attach(msg_base)
        msg_alt.attach(msg_related)

        msg_mixed.attach(msg_alt)
        message = msg_mixed.as_string().replace('MIME-Version: 1.0\n', '')

        return message

    def _parse_info_before_login(self, info, password: str) -> tuple[str, str, str]:
        verified = self.pgp.message(info['Modulus'])
        modulus = b64decode(verified.message)
        server_challenge = b64decode(info['ServerEphemeral'])
        salt = b64decode(info['Salt'])
        spr_session = info['SRPSession']

        self.user = User(password, modulus)
        client_challenge = b64encode(self.user.get_challenge()).decode('utf8')
        client_proof = b64encode(self.user.process_challenge(salt, server_challenge)).decode('utf8')

        return client_challenge, client_proof, spr_session

    def _login_process(self, auth: dict) -> bool:
        if auth["Code"] not in (1000, 1001):
            if auth["Code"] == 9001:
                raise NotImplementedError("CAPTCHA not implemented")
            if auth["Code"] == 2028:
                raise ConnectionRefusedError("Too many recent logins")

        self.user.verify_session(b64decode(auth['ServerProof']))

        return self.user.authenticated()

    def _parse_info_after_login(self, auth: dict) -> None:
        self.pgp.session_key = self.user.get_session_key()

        self.session.headers.update({
            'authorization': f'{auth["TokenType"]} {auth["AccessToken"]}',
            'x-pm-uid': auth['UID'],
        })

        address = self.__addresses()['Addresses'][0]

        self.account_id = address['ID']
        self.account_email = address['Email']
        self.account_name = address['DisplayName']

        keys = address['Keys'][0]
        self.pgp.public_key = keys['PublicKey']

    def __check_email_address(self, mail_address: Union[UserMail, str]) -> dict:
        """
        Checking for the existence of an email address.
        You cannot send a message to an unchecked address.

        :param mail_address: email address to check.
        :type mail_address: `UserMail` or `str`
        :returns: response from the server.
        :rtype: `dict`
        """
        address = mail_address
        if isinstance(mail_address, UserMail):
            address = mail_address.address
        params = {
            'Email': address,
        }
        response = self._get('mail', 'core/v4/keys', params=params)
        json_response = response.json()
        return json_response

    def _async_helper(self, func: callable, args_list: list[tuple]) -> list[any]:
        results = asyncio.run(
            self.__async_process(func, args_list)
        )
        return results

    async def __async_process(
            self,
            func: callable,
            args_list: list[tuple[any]]
    ) -> list[Coroutine]:
        connector = TCPConnector(limit=100)
        headers = dict(self.session.headers)
        cookies = self.session.cookies.get_dict()

        async with ClientSession(headers=headers, cookies=cookies, connector=connector) as client:
            funcs = (func(client, *args) for args in args_list)
            return await tqdm_asyncio.gather(*funcs, desc=func.__name__)

    async def _async_get_messages(
            self,
            client: ClientSession,
            page: int,
            page_size: Optional[int] = 150
    ) -> list:
        params = {
            "Page": page,
            "PageSize": page_size,
            "Limit": page_size,
            "LabelID": "5",
            "Sort": "Time",
            "Desc": "1",
        }
        response = await client.get(f"{urls_api['mail']}/mail/v4/messages", params=params)
        messages = await response.json()
        return messages['Messages']

    async def _async_get_conversations(
            self, client: ClientSession,
            page: int,
            page_size: Optional[int] = 150
    ) -> list:
        params = {
            "Page": page,
            "PageSize": page_size,
            "Limit": page_size,
            "LabelID": 0,
            "Sort": "Time",
            "Desc": "1",
            # 'Attachments': 1, # only get messages with attachments
        }
        response = await client.get(f"{urls_api['mail']}/mail/v4/conversations", params=params)
        conversations = await response.json()
        return conversations['Conversations']

    async def _async_download_file(
            self, client: ClientSession,
            image: Attachment
    ) -> tuple[Attachment, bytes]:
        _id = image.id
        response = await client.get(f"{urls_api['mail']}/mail/v4/attachments/{_id}")
        content = await response.read()
        return image, content

    def _multipart_encrypt(self, message: Message) -> MultipartEncoder:
        prepared_body = self._prepare_message(message.body)
        body_message, session_key = self.pgp.encrypt_with_session_key(prepared_body)
        body_key = b64encode(session_key)
        fields = {
            "Packages[multipart/mixed][MIMEType]": (None, 'multipart/mixed'),
            "Packages[multipart/mixed][Body]": ('blob', body_message, 'application/octet-stream'),
            "Packages[multipart/mixed][Type]": (None, '32'),
            "Packages[multipart/mixed][BodyKey][Key]": (None, body_key),
            "Packages[multipart/mixed][BodyKey][Algorithm]": (None, 'aes256'),
            "DelaySeconds": (None, '10'),
        }
        for recipient in message.recipients:
            fields[f"Packages[multipart/mixed][Addresses][{recipient.address}][Type]"] = (None, '32')
            fields[f"Packages[multipart/mixed][Addresses][{recipient.address}][Signature]"] = (None, '1')

        boundary = '------WebKitFormBoundary' + self.__random_string(16)
        multipart = MultipartEncoder(fields=fields, boundary=boundary)

        return multipart

    def __random_string(self, length: int) -> str:
        random_string = ''.join(
            random.sample(string.ascii_letters + string.digits, length)
        )
        return random_string

    def _multipart_decrypt(self, message: Message) -> None:
        """Decrypt multipart/mixed in message."""
        parser = Parser()
        multipart = parser.parsestr(message.body)
        if not multipart.is_multipart():
            return
        text = html = None
        for block in multipart.walk():
            answers = self.__multipart_decrypt_block(block)
            if answers[0] == 'text':
                text = answers[1]
            elif answers[0] == 'html':
                html = answers[1]
            elif answers[0] == 'attachment':
                message.attachments.append(Attachment(**answers[1]))
        message.body = html or text

    def __multipart_decrypt_block(self, block: any) -> tuple[str, any]:
        content_type = block.get_content_type()
        disposition = block.get_content_disposition()
        transfer = block.get('Content-Transfer-Encoding')
        payload = block.get_payload(decode=True)

        if content_type == 'image/png' or disposition == 'attachment':
            return 'attachment', self.__multipart_file_decrypt(payload, block)
        if transfer == 'quoted-printable':
            return 'text', unicodedata.normalize('NFKD', payload.decode())
        if content_type == 'text/html':
            return 'html', payload.decode()
        return 'none', 'none'

    def __multipart_file_decrypt(self, payload: any, block: any) -> dict:
        kwargs = {
            'name': block.get_filename(),
            'type': block.get_content_type(),
            'content': payload,
            'is_decrypted': True,
            'size': len(payload),
        }
        if block.get_content_disposition() == 'inline':
            kwargs['is_inserted'] = True
            kwargs['cid'] = block.get('Content-ID')[1:-1]
        return kwargs

    def _file_decrypt(self, attachment: Attachment, content: bytes) -> None:
        key_packets = attachment.key_packets

        content = self.pgp.message(content).message.ct
        key = self.pgp.decrypt_session_key(key_packets)
        packet_bytes = self.pgp.aes256_decrypt(content, key)

        attachment_bin = self.pgp.message(packet_bytes).message

        self.__update_attachment_content(attachment, attachment_bin)

    def __update_attachment_content(self, attachment, content) -> None:
        attachment.content = content
        attachment.is_decrypted = True
        attachment.size = len(content)

    def _get(self, base: str, endpoint: str, **kwargs) -> Response:
        return self.__request('get', base, endpoint, **kwargs)

    def _post(self, base: str, endpoint: str, **kwargs) -> Response:
        return self.__request('post', base, endpoint, **kwargs)

    def _put(self, base: str, endpoint: str, **kwargs) -> Response:
        return self.__request('put', base, endpoint, **kwargs)

    def _delete(self, base: str, endpoint: str, **kwargs) -> Response:
        return self.__request('delete', base, endpoint, **kwargs)

    def __request(self, method: str, base: str, endpoint: str, **kwargs) -> Response:
        methods = {
            'get': self.session.get,
            'post': self.session.post,
            'put': self.session.put,
            'delete': self.session.delete
        }
        response = methods[method](f'{urls_api[base]}/{endpoint}', **kwargs)
        return response

    def __addresses(self, params: dict = None) -> dict:
        params = params or {
            'Page': 0,
            'PageSize': 150,  # max page size
        }
        return self._get('api', 'core/v4/addresses', params=params).json()
