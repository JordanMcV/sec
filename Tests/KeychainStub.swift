import Foundation
import Security

private var items: [String: Data] = {
    let json = ProcessInfo.processInfo.environment["TEST_ITEMS"] ?? "{}"
    let values = (try! JSONSerialization.jsonObject(with: Data(json.utf8))) as! [String: String]
    return values.mapValues { Data(base64Encoded: $0)! }
}()

private func record(_ operation: String, name: String) {
    let value = items[name]?.base64EncodedString() ?? "absent"
    FileHandle.standardError.write(Data("TEST \(operation) \(name)=\(value)\n".utf8))
}

func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    let name = (query as NSDictionary)[kSecAttrAccount as String] as! String
    if ProcessInfo.processInfo.environment["TEST_FAIL_UPDATE"] == "1" {
        record("update-failed", name: name)
        return errSecIO
    }
    guard items[name] != nil else { return errSecItemNotFound }
    items[name] = (attributes as NSDictionary)[kSecValueData as String] as? Data
    record("updated", name: name)
    return errSecSuccess
}

func SecItemAdd(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    let attributes = query as NSDictionary
    let name = attributes[kSecAttrAccount as String] as! String
    if ProcessInfo.processInfo.environment["TEST_ADD_RACE"] == "1" {
        items[name] = Data("concurrent-value".utf8)
        return errSecDuplicateItem
    }
    if ProcessInfo.processInfo.environment["TEST_FAIL_ADD"] == "1" { return errSecIO }
    if items[name] != nil { return errSecDuplicateItem }
    items[name] = attributes[kSecValueData as String] as? Data
    record("added", name: name)
    return errSecSuccess
}

@discardableResult
func SecItemDelete(_ query: CFDictionary) -> OSStatus {
    let name = (query as NSDictionary)[kSecAttrAccount as String] as! String
    record("deleted", name: name)
    return items.removeValue(forKey: name) == nil ? errSecItemNotFound : errSecSuccess
}

func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    let attributes = query as NSDictionary
    if let name = attributes[kSecAttrAccount as String] as? String {
        guard let data = items[name] else { return errSecItemNotFound }
        result?.pointee = data as CFData
    } else {
        if items.isEmpty { return errSecItemNotFound }
        result?.pointee = items.keys.map { [kSecAttrAccount as String: $0] } as CFArray
    }
    return errSecSuccess
}
