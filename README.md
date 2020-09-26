[![Version](http://img.shields.io/cocoapods/v/CryptomatorCryptoLib.svg)](https://cocoapods.org/pods/CryptomatorCryptoLib)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/dba85991a19942bab0d3d587522397ef)](https://www.codacy.com/gh/cryptomator/cryptolib-swift)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/dba85991a19942bab0d3d587522397ef)](https://www.codacy.com/gh/cryptomator/cryptolib-swift)

# CryptoLib Swift

This library contains all cryptographic functions that are used by Cryptomator for iOS. The purpose of this project is to provide a separate light-weight library with its own release cycle that can be used in other projects, too.

For more information on the Cryptomator encryption scheme, visit the security architecture page on [docs.cryptomator.org](https://docs.cryptomator.org/en/1.5/security/architecture/).

## Requirements

- iOS 9.0 or higher
- macOS 10.12 or higher

## Installation

### Swift Package Manager

You can use [Swift Package Manager](https://swift.org/package-manager/ "Swift Package Manager").

```swift
.package(url: "https://github.com/cryptomator/cryptolib-swift.git", .upToNextMinor(from: "1.0.0"))
```

### CocoaPods

You can use [CocoaPods](https://cocoapods.org/ "CocoaPods").

```ruby
`pod 'CryptomatorCryptoLib', '~> 1.0.0'`
```

## Usage

### Masterkey

`Masterkey` is a factory for masterkey objects that contain the masterkey bytes for AES encryption/decryption and MAC authentication. The version states the vault format version.

#### Factory

This will create a new masterkey with secure random bytes. Version will be set to the latest version (currently 7).

```swift
let masterkey = try Masterkey.createNew()
```

Another way is to create a masterkey from an existing masterkey file. This is equivalent to an unlock attempt.

Either by URL:

```swift
let fileURL = ...
let password = ...
let pepper = ... // optional
let masterkey = try Masterkey.createFromMasterkeyFile(fileURL: fileURL, password: password, pepper: pepper)
```

Or by JSON data:

```swift
let jsonData = ...
let password = ...
let pepper = ... // optional
let masterkey = try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: password, pepper: pepper)
```

#### Export

For persisting the masterkey, use this method to export its encrypted/wrapped masterkey and other metadata as JSON data.

```swift
let masterkey = ...
let password = ...
let pepper = ... // optional
let jsonData = try masterkey.exportEncrypted(password: password, pepper: pepper)
```

### Cryptor

`Cryptor` is the core class for cryptographic operations on Cryptomator vaults.

#### Constructor

Create a cryptor by providing a masterkey.

```swift
let masterkey = ...
let cryptor = Cryptor(masterkey: masterkey)
```

#### Path Encryption and Decryption

Encrypt the directory ID in order to determine the encrypted directory URL.

```swift
let cryptor = ...
let dirId = ...
let encryptedDirId = try cryptor.encryptDirId(dirId)
```

Encrypt and decrypt filenames by providing a directory ID.

```swift
let cryptor = ...
let filename = ...
let dirId = ...
let ciphertextName = try cryptor.encryptFileName(filename, dirId: dirId)
let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
```

#### File Content Encryption and Decryption

Encrypt and decrypt file content via URLs. These methods support [implicit progress composition](https://developer.apple.com/documentation/foundation/progress#1661068).

```swift
let cryptor = ...
let fileURL = ...
let ciphertextURL = ...
let cleartextURL = ...
try cryptor.encryptContent(from: fileURL, to: ciphertextURL)
try cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
```

#### File Size Calculation

Determine the cleartext and ciphertext sizes in O(1).

```swift
let cryptor = ...
let size = ...
let ciphertextSize = cryptor.calculateCiphertextSize(size)
let cleartextSize = try cryptor.calculateCleartextSize(ciphertextSize)
```

## Contributing to CryptoLib Swift

Please read our [contribution guide](.github/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

In general, the following preference is used to choose the implementation of cryptographic primitives:

1. Apple Swift Crypto (HMAC)
2. Apple CommonCrypto (AES-CTR, RFC 3394 Key Derivation)
3. CryptoSwift (scrypt)

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](.github/CODE_OF_CONDUCT.md).

## License

Distributed under the AGPLv3. See the LICENSE file for more info.
