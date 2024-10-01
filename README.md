Client for the Encrypted File Transfer. The client is responsible for:
* Register in the server (if not previously registered)
* Generate and exchange RSA keys with the server
* Decrypts an AES key received from the server
* Encrypt files using the AES key before sending them to the server
* Send the encrypted files to the server
* Verify successful file transfer using CRC checksums


Uses the Crypto++ library for cryptographic operations.

Reads connection information from a transfer.info file.

Stores client information in a me.info file.
