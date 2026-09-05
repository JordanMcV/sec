import CryptoKit
import Foundation

// Only linked into the test executable. Production has no software-key switch.
final class VaultKey {
    private let key: P256.KeyAgreement.PrivateKey

    init(wrapped: Data? = nil, reason: String) throws {
        if ProcessInfo.processInfo.environment["TEST_UNAVAILABLE"] == "1" {
            throw SecError("Secure Enclave unavailable (test)")
        }
        if let wrapped {
            if ProcessInfo.processInfo.environment["TEST_FAIL_RESTORE"] == "1" {
                throw SecError("could not restore key (test)")
            }
            key = try P256.KeyAgreement.PrivateKey(rawRepresentation: wrapped)
        } else {
            key = P256.KeyAgreement.PrivateKey()
            FileHandle.standardError.write(Data("TEST key-created\n".utf8))
        }
    }

    var wrapped: Data { key.rawRepresentation }
    var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }

    func open(_ sealed: SealedSecret, name: String) throws -> Data {
        if ProcessInfo.processInfo.environment["TEST_DENY"] == "1" {
            throw SecError("Touch ID denied (test)")
        }
        FileHandle.standardError.write(Data("TEST authenticated\n".utf8))
        return try sealed.open(name: name, privateKey: key)
    }
}
