[![Swift Compatibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fcryptomator%2Fcryptolib-swift%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/cryptomator/cryptolib-swift)
[![Platform Compatibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fcryptomator%2Fcryptolib-swift%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/cryptomator/cryptolib-swift)
[![Codacy Code Quality](https://app.codacy.com/project/badge/Grade/dba85991a19942bab0d3d587522397ef)](https://www.codacy.com/gh/cryptomator/cryptolib-swift/dashboard)
[![Codacy Coverage](https://app.codacy.com/project/badge/Coverage/dba85991a19942bab0d3d587522397ef)](https://www.codacy.com/gh/cryptomator/cryptolib-swift/dashboard)

# CryptoLib Swift

This library contains all cryptographic functions that are used by Cryptomator for iOS. The purpose of this project is to provide a separate light-weight library with its own release cycle that can be used in other projects, too.

For more information on the Cryptomator encryption scheme, visit the security architecture page on [docs.cryptomator.org](https://docs.cryptomator.org/en/1.6/security/architecture/).

## Requirements

- iOS 9.0 or higher
- macOS 10.12 or higher

## Installation

### Swift Package Manager

You can use [Swift Package Manager](https://swift.org/package-manager/ "Swift Package Manager").

```swift
.package(url: "https://github.com/cryptomator/cryptolib-swift.git", .upToNextMinor(from: "1.0.0"))
```

## Usage

### Masterkey

`Masterkey` is a class that only contains the key material for AES encryption/decryption and MAC authentication. 

#### Factory

This will create a new masterkey with secure random bytes.

```swift
let masterkey = try Masterkey.createNew()
```

Another way is to create a masterkey from raw bytes.

```swift
let aesMasterKey = ...
let macMasterKey = ...
let masterkey = Masterkey.createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
```

### MasterkeyFile

`MasterkeyFile` is a representation of the masterkey file. With that, you can unlock a masterkey file (and get a `Masterkey`), lock a masterkey file (and serialize it as JSON), or change the passphrase.

#### Factory

Create a masterkey file with content provided either from URL:

```swift
let url = ...
let masterkeyFile = try MasterkeyFile.withContentFromURL(url: url)
```

Or from JSON data:

```swift
let data = ...
let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
```

#### Unlock

When you have a masterkey file, you can attempt an unlock. When successful, it unwraps the stored encryption and MAC keys into the masterkey, which can be used for the cryptor.

```swift
let masterkeyFile = ...
let passphrase = ...
let pepper = ... // optional
let masterkey = try masterkeyFile.unlock(passphrase: passphrase, pepper: pepper)
```

The unlock process can also be performed in two steps:

```swift
let masterkeyFile = ...
let passphrase = ...
let pepper = ... // optional
let kek = try masterkeyFile.deriveKey(passphrase: passphrase, pepper: pepper)
let masterkey = try masterkeyFile.unlock(kek: kek)
```

This is useful if you'd like to derive the key in an extra step since the function is memory-intensive (using scrypt). The result can then be used elsewhere, e.g. in a memory-restricted process.

#### Lock

For persisting the masterkey, use this method to export its encrypted/wrapped masterkey and other metadata as JSON data.

```swift
let masterkey = ...
let vaultVersion = ...
let passphrase = ...
let pepper = ... // optional
let scryptCostParam = ... // optional
let data = try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: vaultVersion, passphrase: passphrase, pepper: pepper, scryptCostParam: scryptCostParam)
```

#### Change Passphrase

The masterkey can be re-encrypted with a new passphrase.

```swift
let masterkeyFileData = ...
let oldPassphrase = ...
let newPassphrase = ...
let pepper = ... // optional
let scryptCostParam = ... // optional
try MasterkeyFile.changePassphrase(masterkeyFileData: masterkeyFileData, oldPassphrase: oldPassphrase, newPassphrase: newPassphrase, pepper: pepper, scryptCostParam: scryptCostParam)
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

## Contributing

Please read our [contribution guide](.github/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

In general, the following preference is used to choose the implementation of cryptographic primitives:

1. Apple Swift Crypto (HMAC)
2. Apple CommonCrypto (AES-CTR, RFC 3394 Key Derivation)

This project uses [SwiftFormat](https://github.com/nicklockwood/SwiftFormat) and [SwiftLint](https://github.com/realm/SwiftLint) to enforce code style and conventions. Install these tools if you haven't already.

Please make sure that your code is correctly formatted and passes linter validations. The easiest way to do that is to set up a pre-commit hook. Create a file at `.git/hooks/pre-commit` with this content:

```sh
./Scripts/process.sh --staged
exit $?
```

And make your pre-commit hook executable:

```sh
chmod +x .git/hooks/pre-commit
```

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](.github/CODE_OF_CONDUCT.md).

## License

This project is dual-licensed under the AGPLv3 for FOSS projects as well as a commercial license derived from the LGPL for independent software vendors and resellers. If you want to use this library in applications that are *not* licensed under the AGPL, feel free to contact our [sales team](https://cryptomator.org/enterprise/).
