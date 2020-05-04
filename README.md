[![Version](http://img.shields.io/cocoapods/v/CryptomatorCryptoLib.svg)](https://cocoapods.org/pods/CryptomatorCryptoLib)

High level wrapper for cryptographic operations used by Cryptomator iOS App

In general, the following preference is used to choose the implementation of cryptographic primitives:
1. Apple Swift Crypto (HMAC)
2. Apple CommonCrypto (AES-CTR, RFC 3394 Key Derivation)
3. CryptoSwift (scrypt)
