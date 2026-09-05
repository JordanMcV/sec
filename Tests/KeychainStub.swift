import CryptoKit
import Foundation
import Security
import Darwin

func setenv(_ name: UnsafePointer<CChar>, _ value: UnsafePointer<CChar>, _ overwrite: Int32) -> Int32 {
    if ProcessInfo.processInfo.environment["TEST_FAIL_SETENV"] == "1" {
        errno = ENOMEM
        return -1
    }
    return Darwin.setenv(name, value, overwrite)
}

private let stateURL = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TEST_STATE"]!)
private var items: [String: [String: Data]] = {
    var state = try! JSONDecoder().decode([String: [String: Data]].self, from: Data(contentsOf: stateURL))
    if let json = ProcessInfo.processInfo.environment["TEST_FIXTURES"] {
        let fixtures = try! JSONDecoder().decode([String: Data].self, from: Data(json.utf8))
        let key = try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        for (name, data) in fixtures {
            state["sec.encrypted.v1", default: [:]][name] = try! SealedSecret.seal(data, name: name, publicKey: key.publicKey)
        }
    }
    try! JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
    return state
}()

private func record(_ operation: String, service: String, name: String) {
    FileHandle.standardError.write(Data("TEST \(operation) \(service)/\(name)\n".utf8))
}

private func persist() {
    try! JSONEncoder().encode(items).write(to: stateURL, options: .atomic)
}

private func target(_ query: CFDictionary) -> (String, String) {
    let attributes = query as NSDictionary
    precondition(attributes[kSecAttrSynchronizable as String] as? Bool == false)
    precondition(attributes[kSecUseDataProtectionKeychain as String] as? Bool == false)
    return (attributes[kSecAttrService as String] as! String, attributes[kSecAttrAccount as String] as! String)
}

func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    let (service, name) = target(query)
    if ProcessInfo.processInfo.environment["TEST_FAIL_UPDATE"] == "1" {
        record("update-failed", service: service, name: name)
        return errSecIO
    }
    guard items[service]?[name] != nil else { return errSecItemNotFound }
    items[service]![name] = (attributes as NSDictionary)[kSecValueData as String] as? Data
    persist()
    record("updated", service: service, name: name)
    return errSecSuccess
}

func SecItemAdd(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    let (service, name) = target(query)
    if ProcessInfo.processInfo.environment["TEST_ADD_RACE"] == "1" {
        items[service, default: [:]][name] = Data("concurrent-value".utf8)
        persist()
        return errSecDuplicateItem
    }
    if ProcessInfo.processInfo.environment["TEST_FAIL_ADD"] == "1" { return errSecIO }
    if items[service]?[name] != nil { return errSecDuplicateItem }
    items[service, default: [:]][name] = (query as NSDictionary)[kSecValueData as String] as? Data
    persist()
    record("added", service: service, name: name)
    return errSecSuccess
}

func SecItemDelete(_ query: CFDictionary) -> OSStatus {
    let (service, name) = target(query)
    guard items[service]?.removeValue(forKey: name) != nil else { return errSecItemNotFound }
    persist()
    record("deleted", service: service, name: name)
    return errSecSuccess
}

func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    let attributes = query as NSDictionary
    let service = attributes[kSecAttrService as String] as! String
    if ProcessInfo.processInfo.environment["TEST_FAIL_READ"] == "1" { return errSecIO }
    if let name = attributes[kSecAttrAccount as String] as? String {
        record("read", service: service, name: name)
        guard let data = items[service]?[name] else { return errSecItemNotFound }
        result?.pointee = data as CFData
    } else {
        guard let entries = items[service], !entries.isEmpty else { return errSecItemNotFound }
        result?.pointee = entries.keys.map { [kSecAttrAccount as String: $0] } as CFArray
    }
    return errSecSuccess
}
