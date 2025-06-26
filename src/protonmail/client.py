"""Client for api protonmail."""

import asyncio
import json
import mimetypes
import pickle
import re
import string
import time
from copy import deepcopy
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.parser import Parser
from base64 import b64encode, b64decode
import random
from math import ceil
from threading import Thread
from typing import Optional, Coroutine, Union

import bcrypt

import unicodedata
from requests import Session
from requests.models import Response
from aiohttp import ClientSession, TCPConnector
from requests_toolbelt import MultipartEncoder
from tqdm.asyncio import tqdm_asyncio

from .exceptions import SendMessageError, InvalidTwoFactorCode, LoadSessionError, AddressNotFound, CantUploadAttachment, CantSetLabel, CantUnsetLabel, CantGetLabels, \
    CantSolveImageCaptcha, InvalidCaptcha
from .models import Attachment, Message, UserMail, Conversation, PgpPairKeys, Label, AccountAddress, LoginType, CaptchaConfig
from .constants import DEFAULT_HEADERS, urls_api, PM_APP_VERSION_MAIL, PM_APP_VERSION_DEV, PM_APP_VERSION_ACCOUNT
from .utils.pysrp import User
from .logger import Logger
from .pgp import PGP
from .utils.utils import bcrypt_b64_encode, delete_duplicates_cookies_and_reset_domain


class ProtonMail:
    """
    Client for api protonmail.
    """
    def __init__(self, proxy: Optional[str] = None, logging_level: Optional[int] = 2, logging_func: Optional[callable] = print):
        """
        :param proxy: proxy for all requests, template: ``http://Username:Password@host-or-ip.com:port``
        :type proxy: ``str``
        :param logging_level: logging level 1-4 (DEBUG, INFO, WARNING, ERROR), default 2[INFO].
        :type logging_level: ``int``
        :param logging_func: logging function. default print.
        :type logging_func: ``callable``
        """
        self.logger = Logger(logging_level, logging_func)
        self.proxy = proxy
        self.pgp = PGP()
        self.user = None
        self._session_path = None
        self._session_auto_save = False
        self.account_addresses: list[AccountAddress] = []

        self.session = Session()
        self.session.proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else dict()
        self.session.headers.update(DEFAULT_HEADERS)

    def login(self, username: str, password: str, getter_2fa_code: callable = lambda: input("enter 2FA code:"), login_type: LoginType = LoginType.WEB,
              captcha_config: CaptchaConfig = CaptchaConfig()) -> None:
        """
        Authorization in ProtonMail.

        :param username: your ProtonMail address.
        :type username: ``str``
        :param password: your password.
        :type password: ``str``
        :param getter_2fa_code: function to get Two-Factor Authentication(2FA) code. default: input
        :type getter_2fa_code: ``callable``
        :param login_type: Type for login, dev - simple login, fewer requests but maybe often CAPTCHA, web - more requests, CAPTCHA like in web. default: WEB
        :type login_type: ``Enum: LoginType``
        :param captcha_config: Config for CAPTCHA resolver (auto, manual or pyqt). Default: auto. More: https://github.com/opulentfox-29/protonmail-api-client?tab=readme-ov-file#solve-captcha
        :type login_type: ``CaptchaConfig``
        :returns: :py:obj:`None`
        """
        self.session.headers['x-pm-appversion'] = PM_APP_VERSION_DEV
        if login_type == LoginType.WEB:
            self.session.headers['x-pm-appversion'] = PM_APP_VERSION_ACCOUNT

            anonym_session_info = self._crate_anonym_session()

            self._get_tokens(anonym_session_info)  # Cookies for anonym user (not logged in the account yet)

        data = {'Username': username}

        info = self._post('account', 'core/v4/auth/info', json=data).json()
        client_challenge, client_proof, spr_session = self._parse_info_before_login(info, password)

        auth = self._post('account', 'core/v4/auth', json={
            'Username': username,
            'ClientEphemeral': client_challenge,
            'ClientProof': client_proof,
            'SRPSession': spr_session,
            'PersistentCookies': 1,
        }).json()

        if auth['Code'] == 9001:  # Captcha
            self._captcha_processing(auth, captcha_config)

            auth = self._post('account', 'core/v4/auth', json={
                'Username': username,
                'ClientEphemeral': client_challenge,
                'ClientProof': client_proof,
                'SRPSession': spr_session,
                'PersistentCookies': 1,
            }).json()

        if self._login_process(auth):
            self.logger.info("login success", "green")
        else:
            self.logger.error("login failure")

        if login_type == LoginType.DEV:
            self._get_tokens(auth)

        if auth["TwoFactor"]:
            if not auth["2FA"]["TOTP"]:
                raise NotImplementedError("Two-Factor Authentication(2FA) implemented only TOTP, disable FIDO2/U2F")
            domain = 'account' if login_type == LoginType.WEB else 'mail'
            response_2fa = self._post(domain, 'core/v4/auth/2fa', json={'TwoFactorCode': getter_2fa_code()})
            if response_2fa.status_code != 200:
                raise InvalidTwoFactorCode(f"Invalid Two-Factor Authentication(2FA) code: {response_2fa.json()['Error']}")

        user_private_key_password = self._get_user_private_key_password(password)
        if login_type == LoginType.WEB:
            user_pk_password_data = {'type': 'default', 'keyPassword': user_private_key_password}
            encrypted_user_pk_password_data = self.pgp.aes_gcm_encrypt(json.dumps(user_pk_password_data, separators=(',', ':')))
            b64_encrypted_user_pk_password_data = b64encode(encrypted_user_pk_password_data).decode()

            payload_for_create_fork = {
                'Payload': b64_encrypted_user_pk_password_data,
                'ChildClientID': 'web-mail',
                'Independent': 0,
            }

            response_data = self._post('account', 'auth/v4/sessions/forks', json=payload_for_create_fork).json()

            self.session.headers['x-pm-appversion'] = PM_APP_VERSION_MAIL
            fork_data = self._get('mail', f"auth/v4/sessions/forks/{response_data['Selector']}").json()

            self._get_tokens(fork_data)

        self._parse_info_after_login(password, user_private_key_password)

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

    def get_messages(self, page_size: Optional[int] = 150, label_or_id: Union[Label, str] = '5') -> list[Message]:
        """
        Get all messages, sorted by time.

        :param page_size: number of posts per page. maximum number 150.
        :param label_or_id: get messages by label. default: 5 (All Mail)
        :returns: :py:obj:`list[Message]`
        """
        label_id = label_or_id.id if isinstance(label_or_id, Label) else label_or_id
        count_page = ceil(self.get_messages_count()[5]['Total'] / page_size)
        args_list = [(page_num, page_size, label_id) for page_num in range(count_page)]
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

    def send_message(self, message: Message, is_html: bool = True, delivery_time: Optional[int] = None, account_address: Optional[AccountAddress] = None) -> Message:
        """
        Send the message.

        :param message: The message you want to send.
        :type message: ``Message``
        :param is_html: message.body is html or plain text, default: True
        :type is_html: ``bool``
        :param delivery_time: timestamp (seconds) for scheduled delivery message, default: None (send now)
        :type delivery_time: ``int``
        :param account_address: If you have more than 1 address for 1 account (premium only), you can choose which address to send messages from,
                                default: None (send from first address)
        :type account_address: ``AccountAddress``
        :returns: :py:obj:`Message`
        """
        if delivery_time and delivery_time <= datetime.now().timestamp():
            raise ValueError(f"Delivery time ({delivery_time}) is less than current, you can't send message to the past")
        recipients_info = []
        for recipient in message.recipients:
            recipient_info = self.__check_email_address(recipient)
            recipients_info.append({
                'address': recipient.address,
                'type': 1 if recipient_info['RecipientType'] == 1 else 32,
                'public_key': recipient_info['Keys'][0]['PublicKey'] if recipient_info['Keys'] else None,
            })
        for cc_recipient in message.cc:
            cc_info = self.__check_email_address(cc_recipient)
            recipients_info.append({
                'address': cc_recipient.address,
                'type': 1 if cc_info['RecipientType'] == 1 else 32,
                'public_key': cc_info['Keys'][0]['PublicKey'] if cc_info['Keys'] else None,
            })
        for bcc_recipient in message.bcc:
            bcc_info = self.__check_email_address(bcc_recipient)
            recipients_info.append({
                'address': bcc_recipient.address,
                'type': 1 if bcc_info['RecipientType'] == 1 else 32,
                'public_key': bcc_info['Keys'][0]['PublicKey'] if bcc_info['Keys'] else None,
            })
        draft = self.create_draft(message, decrypt_body=False, account_address=account_address)
        uploaded_attachments = self._upload_attachments(message.attachments, draft.id)
        multipart = self._multipart_encrypt(message, uploaded_attachments, recipients_info, is_html, delivery_time)

        headers = {
            "Content-Type": multipart.content_type
        }
        params = {
            'Source': 'composer',
        }

        response = self._post(
            'mail',
            f'mail/v4/messages/{draft.id}',
            headers=headers,
            params=params,
            data=multipart
        ).json()
        if response.get('Error'):
            raise SendMessageError(f"Can't send message: {response['Error']}")
        sent_message_dict = response['Sent']
        sent_message = self._convert_dict_to_message(sent_message_dict)
        sent_message.body = self.pgp.decrypt(sent_message.body)
        self._multipart_decrypt(sent_message)

        return sent_message

    def create_draft(self, message: Message, decrypt_body: Optional[bool] = True, account_address: Optional[AccountAddress] = None) -> Message:
        """Create the draft."""
        if not account_address:
            account_address = self.account_addresses[0]
        pgp_body = self.pgp.encrypt(message.body)

        # Sanitize external_id and in_reply_to if present
        external_id = message.external_id
        if external_id and external_id.startswith('<') and external_id.endswith('>'):
            external_id = external_id[1:-1]

        in_reply_to = message.in_reply_to
        if in_reply_to and in_reply_to.startswith('<') and in_reply_to.endswith('>'):
            in_reply_to = in_reply_to[1:-1]

        parent_id = None
        if in_reply_to:
            # Search for parent message by ExternalID
            filter_params = {
                "Page": 0,
                "PageSize": 1,
                "ExternalID": in_reply_to,
                "AddressID": account_address.id,
            }
            resp = self._get('mail', 'mail/v4/messages', params=filter_params).json()
            msgs = resp.get("Messages", [])
            if msgs:
                parent_id = msgs[0]["ID"]
            else:
                parent_id = in_reply_to

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
                    'Name': account_address.name,
                    'Address': account_address.email,
                },
                'AddressID': account_address.id,
                'Unread': 0,
                'Body': pgp_body,
                'ExternalID': external_id,
            },
        }
        if parent_id:
            data['ParentID'] = parent_id
            data['Action'] = 0 # reply
        for recipient in message.recipients:
            data['Message']['ToList'].append(
                {
                    'Name': recipient.name,
                    'Address': recipient.address,
                }
            )
        for cc_recipient in getattr(message, 'cc', []):
            data['Message']['CCList'].append(
                {
                    'Name': cc_recipient.name,
                    'Address': cc_recipient.address,
                }
            )
        for bcc_recipient in getattr(message, 'bcc', []):
            data['Message']['BCCList'].append(
                {
                    'Name': bcc_recipient.name,
                    'Address': bcc_recipient.address,
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

    def mark_messages_as_unread(self, messages_or_ids: list[Union[Message, str]]) -> None:
        """
        Mark as unread messages.

        :param messages_or_ids: list of messages or messages id.
        :type messages_or_ids: :py:obj:`Message`
        """
        ids = [i.id if isinstance(i, Message) else i for i in messages_or_ids]
        data = {
            'IDs': ids,
        }
        self._put('mail', 'mail/v4/messages/unread', json=data)

    def mark_conversations_as_read(self, conversations_or_ids: list[Union[Conversation, str]]) -> None:
        """
        Mark as read conversations.

        :param conversations_or_ids: list of conversations or conversations id.
        :type conversations_or_ids: :py:obj:`Conversation`
        """
        ids = [i.id if isinstance(i, Conversation) else i for i in conversations_or_ids]
        data = {
            'IDs': ids,
        }
        self._put('mail', 'mail/v4/conversations/read', json=data)

    def mark_conversations_as_unread(self, conversations_or_ids: list[Union[Conversation, str]]) -> None:
        """
        Mark as unread conversations.

        :param conversations_or_ids: list of conversations or conversations id.
        :type conversations_or_ids: :py:obj:`Conversation`
        """
        ids = [i.id if isinstance(i, Conversation) else i for i in conversations_or_ids]
        data = {
            'IDs': ids,
        }
        self._put('mail', 'mail/v4/conversations/unread', json=data)

    def wait_for_new_message(
            self,
            *args,
            interval: int = 1,
            timeout: int = 0,
            rise_timeout: bool = False,
            read_message: bool = False,
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
        :param read_message: read message if `True` else the message will not be read and the body will be empty.
                            default `False`.
        :type read_message: `bool`
        :returns :  new message.
        :rtype: `Message`
        :raises TimeoutError: at the end of the `timeout` only if the `rise_timeout` is `True`
        """
        def func(response: dict):
            messages = response.get('Messages', [])
            for message in messages:
                if message.get('Action') != 1:  # new message
                    continue
                new_message = self._convert_dict_to_message(message['Message'])
                if new_message.is_draft():  # skip saving draft
                    continue
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
        if read_message:
            message = self.read_message(message)

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

    def get_labels_by_type_id(self, type_id: int) -> list[Label]:
        """
        Get labels by type id

        :param type_id: type of labels (folders, labels, etc.)
                        possible types:
                            1 - User's custom labels.
                            2 - Actually, I have no idea what it is. If this returned a non-empty list for you, please let me know what it is
                            3 - User's custom folders
                            4 - ProtonMail's system labels (inbox, drafts, sent, spam, etc.)
        :returns: list of labels
        """
        params = {
            'Type': type_id,
        }
        response = self._get('mail', 'core/v4/labels', params=params).json()
        if response['Code'] not in [1000, 1001]:
            raise CantGetLabels(response['Error'])
        type_mapper = {
            1: 'user label',
            2: 'undefined',
            3: 'user folder',
            4: 'system folder',
        }
        labels = [
            Label(
                id=label['ID'],
                name=label['Name'],
                path=label['Path'],
                type=label['Type'],
                type_name=type_mapper[label['Type']],
                color=label['Color'],
                notify=label['Notify'],
                display=label['Display'],
                parent_id=label.get('ParentID'),
            )
            for label in response['Labels']
        ]

        return labels

    def get_all_labels(self) -> list[Label]:
        """Get all labels."""
        labels = []
        labels1 = self.get_user_folders()
        labels2 = self.get_labels_by_type_id(2)
        labels3 = self.get_user_labels()
        labels4 = self.get_system_labels()
        labels.extend(labels1)
        labels.extend(labels2)
        labels.extend(labels3)
        labels.extend(labels4)
        return labels

    def get_system_labels(self) -> list[Label]:
        """Get ProtonMail's system labels."""
        labels = self.get_labels_by_type_id(4)
        return labels

    def get_user_labels(self) -> list[Label]:
        """Get user's labels."""
        labels = self.get_labels_by_type_id(3)
        return labels

    def get_user_folders(self) -> list[Label]:
        """Get user's folders."""
        labels = self.get_labels_by_type_id(1)
        return labels

    def set_label_for_messages(self, label_or_id: Union[Label, str], messages_or_ids: list[Message, str]) -> None:
        """
        Set label for messages.

        :param label_or_id: label or label id
        :param messages_or_ids: list of messages or message IDs.
        """
        message_ids = [message.id if isinstance(message, Message) else message for message in messages_or_ids]
        payload = {
            'LabelID': label_or_id.id if isinstance(label_or_id, Label) else label_or_id,
            'IDs': message_ids,
        }
        response = self._put('mail', 'mail/v4/messages/label', json=payload).json()
        if response['Code'] not in [1000, 1001]:
            raise CantSetLabel(response['Error'])
        errors = []
        for resp in response['Responses']:
            if resp['Response']['Code'] in [1000, 1001]:
                continue
            errors.append({'id': resp['ID'], 'code': resp['Response']['Code'], 'error': resp['Response']['Error']})
        if errors:
            raise CantSetLabel(errors)
        return None

    def unset_label_for_messages(self, label_or_id: Union[Label, str], messages_or_ids: list[Message, str]) -> None:
        """
        Unset label for messages.

        :param label_or_id: label or label id
        :param messages_or_ids: list of messages or message IDs.
        """
        message_ids = [message.id if isinstance(message, Message) else message for message in messages_or_ids]
        payload = {
            'LabelID': label_or_id.id if isinstance(label_or_id, Label) else label_or_id,
            'IDs': message_ids,
        }
        response = self._put('mail', 'mail/v4/messages/unlabel', json=payload).json()
        if response['Code'] not in [1000, 1001]:
            raise CantUnsetLabel(response['Error'])
        errors = []
        for resp in response['Responses']:
            if resp['Response']['Code'] in [1000, 1001]:
                continue
            errors.append({'id': resp['ID'], 'code': resp['Response']['Code'], 'error': resp['Response']['Error']})
        if errors:
            raise CantSetLabel(errors)
        return None

    def pgp_import(self, private_key: str, passphrase: str) -> None:
        """
        WARNING Deprecated: all keys are automatically get while login, this method will be removed

        Import private pgp key and passphrase.

        :param private_key: your private pgp key that you exported from ProtonMail settings.
                            (by the way, your private key must be primary in order to send messages)
                            example: ``privatekey.YourACC@proton.me-12...99.asc``
        :type private_key: ``str``, ``path``, ``file``
        :param passphrase: the passphrase you created when exporting the private key.
        :type passphrase: ``str``
        """
        print("\033[31m{}".format("pgp_import is deprecated and will be removed, you no longer need to use it."))

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
            'pairs_keys': [pair.to_dict() for pair in self.pgp.pairs_keys],
            'aes256_keys': sliced_aes256_keys,
        }
        account_addresses = [{
            'id': account_address.id,
            'email': account_address.email,
            'name': account_address.name,
        } for account_address in self.account_addresses]
        headers = dict(self.session.headers)
        cookies = self.session.cookies.get_dict()
        options = {
            'pgp': pgp,
            'account_addresses': account_addresses,
            'headers': headers,
            'cookies': cookies,
        }
        with open(path, 'wb') as file:
            pickle.dump(options, file)

    def load_session(self, path: str, auto_save: bool = True) -> None:
        """
        Loading a previously saved session.

        :param path: session file path
        :type path: ``str``
        :param auto_save: when updating tokens, automatically save changes
        :type auto_save: ``bool``
        """
        self._session_path = path
        self._session_auto_save = auto_save

        with open(path, 'rb') as file:
            options = pickle.load(file)

        try:
            pgp = options['pgp']
            account_addresses = options['account_addresses']
            headers = options['headers']
            cookies = options['cookies']

            self.pgp.pairs_keys = [PgpPairKeys(**pair) for pair in pgp['pairs_keys']]
            self.pgp.aes256_keys = pgp['aes256_keys']

            self.account_addresses = [AccountAddress(
                id=account_address['id'],
                email=account_address['email'],
                name=account_address['name'],
            ) for account_address in account_addresses]

            self.session.headers = headers
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        except Exception as exc:
            raise LoadSessionError(LoadSessionError.__doc__, exc)

    @staticmethod
    def create_mail_user(**kwargs) -> UserMail:
        """Create UserMail."""
        kwargs = deepcopy(kwargs)
        address = kwargs['address']
        match = re.match(r'^(.*?)\s*<([^>]+)>$', address)
        if match:
            if not kwargs.get('name'):
                kwargs['name'] = match.group(1).strip()
            kwargs['address'] = match.group(2).strip()
        elif address.startswith('<') and address.endswith('>'):
            kwargs['address'] = address[1:-1]

        if not kwargs.get('name'):
            kwargs['name'] = address
        return UserMail(**kwargs)

    @staticmethod
    def create_attachment(content: bytes, name: str, mime_type: Optional[str] = None) -> Attachment:
        """
        Create Attachment.

        :param content: attachment content.
        :param name: filename including an extension. (extension is needed for automatic MIME type detection)
        :param mime_type: Optional. MIME type, it is necessary for mail to be able to display the file correctly.
                            for example, if you have a text file with an unusual extension, such as `pyproject.toml`,
                            you can specify mime_type='text/plain' and mail will treat it as a text file.
                            more: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
        :returns: :py:obj:`Attachment`
        """
        if not mime_type:
            mime_type, encoding = mimetypes.guess_type(name)
        if not mime_type:
            mime_type = 'application/octet-stream'
        attachment = Attachment(
            content=content,
            name=name,
            type=mime_type,
            is_decrypted=True,
        )
        return attachment

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
        cc = kwargs.get('cc', [])
        cc = [
            {'address': c}
            if isinstance(c, str)
            else c
            for c in cc
        ]
        kwargs['cc'] = [
            ProtonMail.create_mail_user(**i)
            for i in cc
        ]
        bcc = kwargs.get('bcc', [])
        bcc = [
            {'address': bc}
            if isinstance(bc, str)
            else bc
            for bc in bcc
        ]
        kwargs['bcc'] = [
            ProtonMail.create_mail_user(**i)
            for i in bcc
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
        cc = [
            UserMail(
                user['Name'],
                user['Address'],
                user
            ) for user in response.get('CCList', [])
        ]
        bcc = [
            UserMail(
                user['Name'],
                user['Address'],
                user
            ) for user in response.get('BCCList', [])
        ]
        attachments_dict = response.get('Attachments', [])
        attachments = []
        for attachment in attachments_dict:
            attachments.append(ProtonMail._convert_dict_to_attachment(attachment))

        message = Message(
            id=response['ID'],
            conversation_id=response['ConversationID'],
            subject=response['Subject'],
            unread=response['Unread'],
            sender=sender,
            recipients=recipients,
            cc=cc,
            bcc=bcc,
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
    def _convert_dict_to_attachment(attachment_data: dict) -> Attachment:
        """
        Converts dictionary to attachment object.

        :param attachment_data: The dictionary from which the attachment will be created.
        :type attachment_data: ``dict``
        :returns: :py:obj:`Attachment`
        """
        is_inserted = attachment_data['Disposition'] == 'inline'
        cid = attachment_data['Headers'].get('content-id')
        if cid:
            cid = cid[1:-1]
        attachment = Attachment(
            id=attachment_data['ID'],
            name=attachment_data['Name'],
            size=attachment_data['Size'],
            type=attachment_data['MIMEType'],
            is_inserted=is_inserted,
            key_packets=attachment_data['KeyPackets'],
            cid=cid,
            extra=attachment_data
        )
        return attachment

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
    def _prepare_message(message: Message, is_html: bool = True) -> str:
        """Converting an unencrypted message into a multipart mime."""
        data = message.body
        msg_mixed = MIMEMultipart('mixed')

        msg_plain = MIMEText('', _subtype='plain')
        msg_plain.replace_header('Content-Transfer-Encoding', 'quoted-printable')

        if not is_html:
            data = '=\n'.join([data[i:i + 76] for i in range(0, len(data), 76)])
            msg_plain.set_payload(data, 'utf-8')
            msg_mixed.attach(msg_plain)
        else:
            msg_plain.set_payload('', 'utf-8')
            data_base64 = b64encode(data.encode()).decode()
            data_base64 = '\n'.join([data_base64[i:i+76] for i in range(0, len(data_base64), 76)])

            msg_base = MIMEText('', _subtype='html')
            msg_base.replace_header('Content-Transfer-Encoding', 'base64')
            msg_base.set_payload(data_base64, 'utf-8')

            msg_related = MIMEMultipart('related')
            msg_related.attach(msg_base)

            msg_alt = MIMEMultipart('alternative')
            msg_alt.attach(msg_plain)
            msg_alt.attach(msg_related)

            msg_mixed.attach(msg_alt)

        for attachment in message.attachments:
            main_type, sub_type = attachment.type.split('/')
            filename_part = f'; filename="{attachment.name}"; name="{attachment.name}"'

            msg_attachment = MIMEBase(main_type, sub_type + filename_part)
            content_type = 'inline' if attachment.is_inserted else 'attachment'
            msg_attachment.add_header('Content-Disposition', content_type + filename_part)
            if attachment.is_inserted:
                msg_attachment.add_header('Content-ID', f'<{attachment.cid}>')
            msg_attachment.set_payload(attachment.content, 'utf-8')
            msg_mixed.attach(msg_attachment)

        message = msg_mixed.as_string().replace('MIME-Version: 1.0\n', '')

        return message

    def _crate_anonym_session(self) -> dict:
        """Create anonymous session."""
        self.session.headers['x-enforce-unauthsession'] = 'true'
        anonym_session_data = self._post('account', 'auth/v4/sessions').json()
        del self.session.headers['x-enforce-unauthsession']

        return anonym_session_data

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

    def _captcha_processing(self, auth: dict, captcha_config: CaptchaConfig):
        """ Processing CAPTCHA logic. """
        self.logger.warning("Got CAPTCHA")
        captcha_token = auth['Details']['HumanVerificationToken']
        params = {
            'Token': captcha_token,
            'ForceWebMessaging': 1,
        }
        js_captcha = self._get('account-api', 'core/v4/captcha', params=params).text
        send_token_func = re.search(r"return sendToken\((.*?)\);", js_captcha).group(1)
        sub_token = ''.join(re.findall(r"'([^']+)'", send_token_func))

        if captcha_config.type == CaptchaConfig.CaptchaType.AUTO:
            proved_token = self._captcha_auto_solving(captcha_token)
            self.logger.info("CAPTCHA auto solved")
        elif captcha_config.type == CaptchaConfig.CaptchaType.PYQT:
            self.logger.info("Opening a browser window to solve CAPTCHA...")
            proved_token = captcha_config.function_for_pyqt(auth)
            self.logger.info("CAPTCHA solved")
        else:
            proved_token = captcha_config.function_for_manual(auth)
            self.logger.info("CAPTCHA manual solved")

        hvt_token = f'{captcha_token}:{sub_token}{proved_token}'

        self.session.headers['x-pm-human-verification-token-type'] = 'captcha'
        self.session.headers['x-pm-human-verification-token'] = hvt_token

    def _captcha_auto_solving(self, captcha_token: str) -> str:

        from .utils.captcha_auto_solver_utils import get_captcha_puzzle_coordinates, solve_challenge

        """ Auto solve CAPTCHA. """
        params = {
            'challengeType': '2D',
            'parentURL': f'https://account-api.proton.me/core/v4/captcha?Token={captcha_token}&ForceWebMessaging=1',
            'displayedLang': 'en',
            'supportedLangs': 'en,en,en,en',
            'purpose': 'login',
            'token': captcha_token,
        }
        init_data = self._get('account-api', 'captcha/v1/api/init', params=params).json()

        params = {
            'token': init_data['token']
        }
        image_captcha = self._get('account-api', 'captcha/v1/api/bg', params=params).content

        puzzle_coordinates = get_captcha_puzzle_coordinates(image_captcha)
        if puzzle_coordinates is None:
            raise CantSolveImageCaptcha("Maybe this image is hard, just retry login or use manual CAPTCHA solver")

        answers = [solve_challenge(challenge) for challenge in init_data['challenges']]

        captcha_object = {
            'x': puzzle_coordinates[0],
            'y': puzzle_coordinates[1],
            'answers': answers,
            'clientData': None,
            'pieceLoadElapsedMs': 140,
            'bgLoadElapsedMs': 180,
            'challengeLoadElapsedMs': 180,
            'solveChallengeMs': 5000,
            'powElapsedMs': 540
        }
        pcaptcha = json.dumps(captcha_object)
        self.session.headers['pcaptcha'] = pcaptcha

        params = {
            'token': init_data['token'],
            'contestId': init_data['contestId'],
            'purpose': 'login'
        }
        validated = self._get('account-api', 'captcha/v1/api/validate', params=params)
        if validated.status_code != 200:
            raise InvalidCaptcha(f"Validate CAPTCHA returns code: {validated.status_code}")

        return init_data['token']

    def _login_process(self, auth: dict) -> bool:
        if auth["Code"] not in (1000, 1001):
            if auth["Code"] in [9001, 12087]:
                raise InvalidCaptcha(auth['Error'])
            if auth["Code"] == 2028:
                raise ConnectionRefusedError(f"Too many recent logins: {auth.get('Error')}")

        self.user.verify_session(b64decode(auth['ServerProof']))

        return self.user.authenticated()

    def _get_tokens(self, auth: dict) -> None:
        self.session.headers['authorization'] = f'{auth["TokenType"]} {auth["AccessToken"]}'
        self.session.headers['x-pm-uid'] = auth['UID']

        json_data = {
            'UID': auth['UID'],
            'ResponseType': 'token',
            'GrantType': 'refresh_token',
            'RefreshToken': auth['RefreshToken'],
            'RedirectURI': 'https://protonmail.com',
            'Persistent': 0,
            'State': self.__random_string(24),
        }
        response = self._post('mail', 'core/v4/auth/cookies', json=json_data)
        if response.status_code != 200:
            raise Exception(f"Can't get refresh token, status: {response.status_code}, json: {response.json()}")
        self.logger.info("got cookies", "green")

    def _parse_info_after_login(self, password: str, user_private_key_password: Optional[str] = None) -> None:
        user_info = self.__get_users()['User']
        user_pair_key = user_info['Keys'][0]

        if not user_private_key_password:
            user_private_key_password = self._get_user_private_key_password(password)

        self.pgp.pairs_keys.append(PgpPairKeys(
            is_user_key=True,
            is_primary=True,
            fingerprint_private=user_pair_key['Fingerprint'],
            private_key=user_pair_key['PrivateKey'],
            passphrase=user_private_key_password,
            email=user_info['Email'],
        ))
        self.logger.info("got user keys", "green")

        account_addresses = self.__addresses()['Addresses']

        self.account_addresses = [AccountAddress(
            id=account_address['ID'],
            email=account_address['Email'],
            name=account_address['DisplayName'],
        ) for account_address in account_addresses]

        for account_address in account_addresses:
            for address_key in account_address['Keys']:
                address_passphrase = self.pgp.decrypt(address_key['Token'], user_pair_key['PrivateKey'], user_private_key_password)

                self.pgp.pairs_keys.append(PgpPairKeys(
                    is_user_key=False,
                    is_primary=bool(address_key['Primary']),
                    fingerprint_public=address_key['Fingerprints'][0],
                    fingerprint_private=address_key['Fingerprints'][1],
                    public_key=address_key['PublicKey'],
                    private_key=address_key['PrivateKey'],
                    passphrase=address_passphrase,
                    email=account_address['Email'],
                ))
        self.logger.info("got email keys", "green")

    def _get_user_private_key_password(self, password: str) -> str:
        """
        Get password for the user PGP private key.

        :param password: User password for the account.
        :returns: Password for the user PGP private key.
        """
        salts = self.__get_salts()['KeySalts']
        key_salt = [salt['KeySalt'] for salt in salts if salt['KeySalt']][0]
        bcrypt_salt = bcrypt_b64_encode(b64decode(key_salt))[:22]
        user_private_key_password = bcrypt.hashpw(password.encode(), b'$2y$10$' + bcrypt_salt)[29:].decode()
        return user_private_key_password

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
        if json_response['Code'] == 33102:
            raise AddressNotFound(address, json_response['Error'])
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
            page_size: Optional[int] = 150,
            label_id: str = '5',
    ) -> list:
        params = {
            "Page": page,
            "PageSize": page_size,
            "Limit": page_size,
            "LabelID": label_id,
            "Sort": "Time",
            "Desc": "1",
        }
        response = await client.get(f"{urls_api['mail']}/mail/v4/messages", params=params, proxy=self.proxy, verify_ssl=False)
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
        response = await client.get(f"{urls_api['mail']}/mail/v4/conversations", params=params, proxy=self.proxy, verify_ssl=False)
        conversations = await response.json()
        return conversations['Conversations']

    async def _async_download_file(
            self, client: ClientSession,
            image: Attachment
    ) -> tuple[Attachment, bytes]:
        _id = image.id
        response = await client.get(f"{urls_api['mail']}/mail/v4/attachments/{_id}", proxy=self.proxy, verify_ssl=False)
        content = await response.read()
        return image, content

    def _upload_attachments(self, attachments: list[Attachment], draft_id: str) -> list[Attachment]:
        """upload attachments."""
        encrypted_attachments_with_signature = [self._encrypt_attachment(attachment) for attachment in attachments]

        uploaded_attachments = list()
        for attachment, signature in encrypted_attachments_with_signature:
            fields = {
                'Filename': (None, attachment.name),
                'MessageID': (None, draft_id),
                'ContentID': (None, attachment.cid),
                'MIMEType': (None, attachment.type),
                'KeyPackets': ('blob', b64decode(attachment.key_packets), 'application/octet-stream'),
                'DataPacket': ('blob', attachment.content, 'application/octet-stream'),
                'Signature': ('blob', signature, 'application/octet-stream'),
            }
            boundary = '------WebKitFormBoundary' + self.__random_string(16)
            multipart = MultipartEncoder(fields=fields, boundary=boundary)
            headers = {
                'Content-Type': multipart.content_type,
            }
            response = self._post('mail', 'mail/v4/attachments', headers=headers, data=multipart)
            response_data = response.json()
            if response_data['Code'] != 1000:
                raise CantUploadAttachment(response_data['Error'])
            uploaded_attachment = self._convert_dict_to_attachment(response_data['Attachment'])
            uploaded_attachments.append(uploaded_attachment)

        return uploaded_attachments

    def _encrypt_attachment(self, attachment: Attachment) -> tuple[Attachment, bytes]:
        """Encrypt an attachment."""
        encrypted_data, session_key, signature = self.pgp.encrypt_with_session_key(attachment.content)
        key_packet = b64encode(self.pgp.encrypt_session_key(session_key)).decode()

        encrypted_attachment = Attachment(**attachment.to_dict())
        encrypted_attachment.content = encrypted_data
        encrypted_attachment.is_decrypted = False
        encrypted_attachment.key_packets = key_packet

        return encrypted_attachment, signature

    def _multipart_encrypt(self, message: Message, uploaded_attachments: list[Attachment], recipients_info: list[dict], is_html: bool, delivery_time: Optional[int] = None) -> MultipartEncoder:
        session_key = None
        recipients_type = set(recipient['type'] for recipient in recipients_info)
        package_types = {
            1: 'text/html' if is_html else 'text/plain',  # send to proton
            32: 'multipart/mixed',  # send to other mails
        }
        fields = {
            "DelaySeconds": (None, '10'),
        }
        if delivery_time:
            fields['DeliveryTime'] = (None, str(delivery_time))

        for recipient_type in recipients_type:
            is_send_to_proton = recipient_type == 1

            if is_send_to_proton:
                prepared_body = message.body
            else:
                prepared_body = self._prepare_message(message, is_html)

            body_message, session_key, signature = self.pgp.encrypt_with_session_key(prepared_body, session_key)

            package_type = package_types[recipient_type]
            fields.update({
                f"Packages[{package_type}][MIMEType]": (None, package_type),
                f"Packages[{package_type}][Body]": ('blob', body_message, 'application/octet-stream'),
                f"Packages[{package_type}][Type]": (None, str(recipient_type)),
            })
            if not is_send_to_proton:
                fields.update({
                    f"Packages[{package_type}][BodyKey][Key]": (None, b64encode(session_key)),
                    f"Packages[{package_type}][BodyKey][Algorithm]": (None, 'aes256'),
                })

        for recipient in recipients_info:
            package_type = package_types[recipient['type']]
            address = recipient['address']
            fields.update({
                f"Packages[{package_type}][Addresses][{address}][Type]": (None, str(recipient['type'])),
                f"Packages[{package_type}][Addresses][{address}][Signature]": (None, '0'),
            })
            if recipient['public_key']:  # proton
                key_packet = b64encode(self.pgp.encrypt_session_key(session_key, recipient['public_key'])).decode()
                fields[f"Packages[{package_type}][Addresses][{address}][BodyKeyPacket]"] = (None, key_packet)
                for attachment in uploaded_attachments:
                    session_key_attachment = self.pgp.decrypt_session_key(attachment.key_packets)
                    key_packet_attachment = b64encode(self.pgp.encrypt_session_key(session_key_attachment, recipient['public_key'])).decode()
                    fields[f"Packages[{package_type}][Addresses][{address}][AttachmentKeyPackets][{attachment.id}]"] = (None, key_packet_attachment)

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

    @delete_duplicates_cookies_and_reset_domain
    def __request(self, method: str, base: str, endpoint: str, **kwargs) -> Response:
        methods = {
            'get': self.session.get,
            'post': self.session.post,
            'put': self.session.put,
            'delete': self.session.delete
        }
        response = methods[method](f'{urls_api[base]}/{endpoint}', **kwargs)
        if response.status_code == 401:  # access token is expired
            self.__refresh_tokens()
            response = methods[method](f'{urls_api[base]}/{endpoint}', **kwargs)
        return response

    def __refresh_tokens(self) -> None:
        response = self._post('mail', 'auth/refresh')
        if response.status_code != 200:
            raise Exception(f"Can't update tokens, status: {response.status_code} json: {response.json()}")
        if self._session_auto_save:
            self.save_session(self._session_path)

    def __addresses(self, params: dict = None) -> dict:
        params = params or {
            'Page': 0,
            'PageSize': 150,  # max page size
        }
        return self._get('api', 'core/v4/addresses', params=params).json()

    def __get_users(self) -> dict:
        return self._get('account', 'core/v4/users').json()

    def __get_salts(self) -> dict:
        return self._get('account', 'core/v4/keys/salts').json()
