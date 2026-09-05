import Foundation
import Security

struct SecError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

struct KeychainStore {
    let service: String

    private func query(_ name: String) -> [String: Any] {
        // This store holds ciphertext/wrapped blobs, not native enclave keys.
        // The file-based Keychain does not require provisioned access groups.
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: name,
         kSecUseDataProtectionKeychain as String: false,
         kSecAttrSynchronizable as String: false]
    }

    private func failure(_ operation: String, _ status: OSStatus) -> SecError {
        let detail = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
        return SecError("could not \(operation): \(detail)")
    }

    func read(_ name: String) throws -> Data? {
        var attributes = query(name)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw failure("read '\(name)'", status) }
        guard let data = item as? Data else { throw SecError("invalid stored data for '\(name)'") }
        return data
    }

    func insert(_ name: String, data: Data) throws {
        var attributes = query(name)
        attributes[kSecValueData as String] = data
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw failure("create '\(name)' (existing items are never replaced)", status) }
    }

    func store(_ name: String, data: Data) throws {
        let attributes = [kSecValueData as String: data]
        var status = SecItemUpdate(query(name) as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw failure("store '\(name)'", status) }
        var item = query(name)
        item[kSecValueData as String] = data
        status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(query(name) as CFDictionary, attributes as CFDictionary)
        }
        guard status == errSecSuccess else { throw failure("store '\(name)'", status) }
    }

    func remove(_ name: String) throws {
        let status = SecItemDelete(query(name) as CFDictionary)
        guard status == errSecSuccess else { throw failure("delete '\(name)'", status) }
    }

    func names() throws -> [String] {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: false,
            kSecAttrSynchronizable as String: false,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: false,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &items)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw failure("list secrets", status) }
        guard let entries = items as? [[String: Any]] else { throw SecError("invalid secret list") }
        return entries.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }
}
