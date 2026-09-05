import Foundation

struct Vault {
    let keys = KeychainStore(service: "sec.enclave-key.v1")
    let secrets = KeychainStore(service: "sec.encrypted.v1")
    let legacy = KeychainStore(service: "sec")
    private let keyAccount = "default"

    func loadKey(reason: String) throws -> VaultKey {
        guard let wrapped = try keys.read(keyAccount) else {
            throw SecError("not initialized. Run 'sec init'. If you previously initialized this Mac, restore the original key; do not delete encrypted entries.")
        }
        return try VaultKey(wrapped: wrapped, reason: reason)
    }

    private func verify(_ key: VaultKey) throws {
        let challenge = Data(UUID().uuidString.utf8)
        let encrypted = try SealedSecret.seal(challenge, name: "sec.init.check", publicKey: key.publicKey)
        let sealed = try SealedSecret.decode(encrypted, publicKey: key.publicKey)
        guard try key.open(sealed, name: "sec.init.check") == challenge else {
            throw SecError("encryption key verification failed")
        }
    }

    func initialize() throws {
        if let wrapped = try keys.read(keyAccount) {
            try verify(VaultKey(wrapped: wrapped, reason: "verify your sec encryption key"))
            note("already initialized; existing key verified")
            return
        }
        guard try secrets.names().isEmpty else {
            throw SecError("encrypted secrets exist but their key is missing. Restore the original key; refusing to generate a replacement.")
        }
        note("Touch ID protects this key. Changing enrolled fingerprints can make your secrets unrecoverable. Keep recovery copies elsewhere.")
        let key = try VaultKey(reason: "initialize sec on this Mac")
        // Exercise the persisted representation before saving anything, not just the in-memory key.
        try verify(VaultKey(wrapped: key.wrapped, reason: "verify your new sec encryption key"))
        try keys.insert(keyAccount, data: key.wrapped)
        note("initialized a device-local, Touch ID-protected encryption key")
        if try !legacy.names().isEmpty { note("legacy entries remain unchanged; use 'sec list' and 'sec migrate <name>...'") }
    }

    func read(_ name: String) throws -> Data {
        guard let encrypted = try secrets.read(name) else {
            if try legacy.names().contains(name) {
                throw SecError("'\(name)' is a legacy entry. Run 'sec migrate \(name)' first; legacy reads are never used by 'sec run'.")
            }
            throw SecError("no secret named '\(name)'. Store one with: sec set \(name)")
        }
        return encrypted
    }

    func migrate(_ names: [String]) throws {
        let key = try loadKey(reason: "migrate legacy sec entries to encrypted storage")
        // Authenticate before reading any unprotected legacy values.
        try verify(key)
        for name in names {
            guard let original = try legacy.read(name) else { throw SecError("no legacy entry named '\(name)'") }
            _ = try environmentValue(for: original, name: name)
            if let existing = try secrets.read(name) {
                let sealed = try SealedSecret.decode(existing, publicKey: key.publicKey)
                guard try key.open(sealed, name: name) == original else {
                    throw SecError("encrypted '\(name)' differs from its legacy entry; neither was changed")
                }
            } else {
                let encrypted = try SealedSecret.seal(original, name: name, publicKey: key.publicKey)
                let sealed = try SealedSecret.decode(encrypted, publicKey: key.publicKey)
                guard try key.open(sealed, name: name) == original else { throw SecError("migration verification failed") }
                // Do not overwrite another process's concurrent write.
                try secrets.insert(name, data: encrypted)
            }
            let stored = try SealedSecret.decode(read(name), publicKey: key.publicKey)
            guard try key.open(stored, name: name) == original else { throw SecError("stored migration verification failed") }
            note("migrated and verified '\(name)'")
        }
        note("legacy copies are still unprotected. After checking your commands, remove the old entries with service 'sec' in Keychain Access. Do not remove 'sec.enclave-key.v1' or 'sec.encrypted.v1'.")
    }
}
