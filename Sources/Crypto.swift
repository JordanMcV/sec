import CryptoKit
import Foundation

struct SealedSecret: Codable {
    let version: Int
    let keyID: Data
    let encapsulatedKey: Data
    let ciphertext: Data

    private static let info = Data("sec.hpke.v1".utf8)

    private static func keyID(_ publicKey: P256.KeyAgreement.PublicKey) -> Data {
        Data(SHA256.hash(data: publicKey.x963Representation))
    }

    private static func binding(name: String, keyID: Data) -> Data {
        // Fixed domain, 32-byte key ID, big-endian byte count, then exact UTF-8 name.
        var data = Data("sec.secret.v1\0".utf8)
        data.append(keyID)
        var length = UInt64(name.utf8.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(contentsOf: name.utf8)
        return data
    }

    static func seal(_ secret: Data, name: String, publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let id = keyID(publicKey)
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
        let ciphertext = try sender.seal(secret, authenticating: binding(name: name, keyID: id))
        return try JSONEncoder().encode(SealedSecret(version: 1, keyID: id,
                                                    encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext))
    }

    static func decode(_ data: Data, publicKey: P256.KeyAgreement.PublicKey) throws -> SealedSecret {
        let sealed: SealedSecret
        do { sealed = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw SecError("invalid encrypted secret; no legacy or plaintext fallback is allowed") }
        guard sealed.version == 1 else { throw SecError("unsupported encrypted secret version") }
        guard sealed.keyID == keyID(publicKey) else { throw SecError("secret belongs to a different encryption key") }
        return sealed
    }

    func open<K: HPKEDiffieHellmanPrivateKey>(name: String, privateKey: K) throws -> Data {
        var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                           info: Self.info, encapsulatedKey: encapsulatedKey)
        return try recipient.open(ciphertext, authenticating: Self.binding(name: name, keyID: keyID))
    }
}
