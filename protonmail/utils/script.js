/**
* Some utils to pgp from OpenPGP.js
*/

async function decryptSessionKeys(options) {
	const privateKeyArmored = options[0];
	const passphrase = options[1];
	const rawEncryptedKey = options[2];

	const binaryKey = Uint8Array.from(rawEncryptedKey)
	const messageKey = await openpgp.readMessage({ binaryMessage: binaryKey });
	const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

	const message = {
		'decryptionKeys': [
			privateKey,
		],
		'message': messageKey,
	};
	const decryptedKeys = await openpgp.decryptSessionKeys(message);

	return decryptedKeys;
};

async function encryptMessage(options) {
	const privateKeyArmored = options[0]
	const passphrase = options[1]
	const sessionKey = options[2]
	const message = options[3]
	const dataType = "text"

	const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

	const session_key = Uint8Array.from(sessionKey);
	const pgp_message = await openpgp.createMessage({ [dataType]: message });

	const encrypted_message = await openpgp.encrypt({
		config: {preferredCompressionAlgorithm: 0},
		message: pgp_message,
		sessionKey: {
			algorithm: "aes256",
			data: session_key,
		},
		format: "binary",
		signingKeys: [privateKey,],
	});

	return encrypted_message;
};

async function decryptMessage(options) {
	const armoredMessage = options[0]
	const privateKeyArmored = options[1]
	const passphrase = options[2]

	const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });
	const pgp_message = await openpgp.readMessage({ armoredMessage })
	const message = {
		'decryptionKeys': [
			privateKey,
		],
		'message': pgp_message,
		'format': 'binary'
	}
	const decrypted_message = await openpgp.decrypt(message);

	return decrypted_message;
};
