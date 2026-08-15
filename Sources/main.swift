import Foundation
import LocalAuthentication
import Security

let keychainService = "sec"
let toolName = "sec"

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(toolName): \(message)\n".utf8))
    exit(1)
}

func note(_ message: String) {
    FileHandle.standardError.write(Data("\(toolName): \(message)\n".utf8))
}

// komodo-api-key -> KOMODO_API_KEY
func defaultVarName(for name: String) -> String {
    let mapped = name.map { c -> Character in
        c.isLetter || c.isNumber ? c : "_"
    }
    return String(mapped).uppercased()
}

// MARK: - Keychain

func baseQuery(_ name: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: name,
    ]
}

func storeSecret(name: String, secret: Data) {
    var query = baseQuery(name)
    SecItemDelete(query as CFDictionary)
    query[kSecValueData as String] = secret
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        die("could not store '\(name)': \(secErrorMessage(status))")
    }
}

func loadSecret(name: String) -> Data {
    var query = baseQuery(name)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
        die("no secret named '\(name)'. Store one with: \(toolName) set \(name)")
    }
    guard status == errSecSuccess, let data = item as? Data else {
        die("could not read '\(name)': \(secErrorMessage(status))")
    }
    return data
}

func deleteSecret(name: String) {
    let status = SecItemDelete(baseQuery(name) as CFDictionary)
    if status == errSecItemNotFound {
        die("no secret named '\(name)'")
    }
    guard status == errSecSuccess else {
        die("could not delete '\(name)': \(secErrorMessage(status))")
    }
}

func listSecretNames() -> [String] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnAttributes as String: true,
    ]
    query[kSecReturnData as String] = false

    var items: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &items)
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess, let entries = items as? [[String: Any]] else {
        die("could not list secrets: \(secErrorMessage(status))")
    }
    return entries.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
}

func secErrorMessage(_ status: OSStatus) -> String {
    (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
}

// MARK: - Biometrics

// Advisory gate. The Keychain item is not cryptographically bound to biometry,
// so this proves a human approved the read; it does not stop another process
// running as this user from reading the item directly.
func authenticate(reason: String) {
    if ProcessInfo.processInfo.environment["SEC_SKIP_BIOMETRY"] == "1" {
        note("SEC_SKIP_BIOMETRY=1 set, skipping Touch ID")
        return
    }

    let context = LAContext()
    context.localizedCancelTitle = "Cancel"

    // .deviceOwnerAuthentication, not .deviceOwnerAuthenticationWithBiometrics.
    // The biometrics-only policy returns LAError.systemCancel (-4) for a
    // command line process on macOS 27, because it has no foreground GUI
    // context to host the dialog. Device owner authentication uses Touch ID
    // when it can and falls back to the login password, which also keeps the
    // tool usable over SSH and on headless machines.
    var policyError: NSError?
    let policy: LAPolicy = .deviceOwnerAuthentication
    guard context.canEvaluatePolicy(policy, error: &policyError) else {
        let detail = policyError.map { "\($0.localizedDescription) (code \($0.code))" } ?? "unknown"
        die("authentication unavailable: \(detail). Set SEC_SKIP_BIOMETRY=1 to bypass.")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var granted = false
    var failure: Error?

    context.evaluatePolicy(policy, localizedReason: reason) { success, error in
        granted = success
        failure = error
        semaphore.signal()
    }
    semaphore.wait()

    guard granted else {
        die("authentication failed: \(failure?.localizedDescription ?? "denied")")
    }
}

// MARK: - Commands

func cmdSet(_ args: [String]) {
    guard args.count == 1 else {
        die("usage: \(toolName) set <name>   (secret is read from stdin)")
    }
    let name = args[0]

    if isatty(FileHandle.standardInput.fileDescriptor) == 1 {
        die("refusing to read a secret from a terminal. Pipe it in:\n"
            + "  printf %s 'VALUE' | \(toolName) set \(name)")
    }

    let data = FileHandle.standardInput.readDataToEndOfFile()
    var bytes = [UInt8](data)
    while let last = bytes.last, last == 0x0A || last == 0x0D {
        bytes.removeLast()
    }
    guard !bytes.isEmpty else { die("refusing to store an empty secret") }

    storeSecret(name: name, secret: Data(bytes))
    note("stored '\(name)' (\(bytes.count) bytes) as $\(defaultVarName(for: name))")
}

func cmdRun(_ args: [String]) {
    guard let separator = args.firstIndex(of: "--") else {
        die("usage: \(toolName) run <name|VAR=name>... -- <command> [args...]")
    }
    let specs = Array(args[..<separator])
    let command = Array(args[(separator + 1)...])

    guard !specs.isEmpty else { die("name at least one secret before --") }
    guard !command.isEmpty else { die("no command given after --") }

    var resolved: [(variable: String, name: String)] = []
    for spec in specs {
        if let eq = spec.firstIndex(of: "="), eq != spec.startIndex {
            resolved.append((String(spec[..<eq]), String(spec[spec.index(after: eq)...])))
        } else {
            resolved.append((defaultVarName(for: spec), spec))
        }
    }

    let names = resolved.map(\.name).joined(separator: ", ")
    authenticate(reason: "release \(names) to \(command[0])")

    for entry in resolved {
        let secret = loadSecret(name: entry.name)
        guard let value = String(data: secret, encoding: .utf8) else {
            die("'\(entry.name)' is not valid UTF-8 and cannot be an environment variable")
        }
        setenv(entry.variable, value, 1)
    }

    // exec replaces this process, so the secret never outlives the child.
    let argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
    execvp(command[0], argv)

    die("could not exec '\(command[0])': \(String(cString: strerror(errno)))")
}

func cmdList() {
    let names = listSecretNames()
    if names.isEmpty {
        note("no secrets stored")
        return
    }
    for name in names {
        print("\(name)\t$\(defaultVarName(for: name))")
    }
}

func cmdRemove(_ args: [String]) {
    guard args.count == 1 else { die("usage: \(toolName) rm <name>") }
    deleteSecret(name: args[0])
    note("deleted '\(args[0])'")
}

let usage = """
\(toolName) - hand secrets to a child process without printing them

USAGE
  \(toolName) set <name>                       store a secret read from stdin
  \(toolName) run <name|VAR=name>... -- <cmd>  Touch ID, inject, exec
  \(toolName) list                             list names (never values)
  \(toolName) rm <name>                        delete a secret

EXAMPLES
  printf %s 'abc123' | \(toolName) set komodo-api-key

  \(toolName) run komodo-api-key -- \\
    sh -c 'curl -sS -H "X-Api-Key: $KOMODO_API_KEY" https://komodo/read'

  Quote the inner command with single quotes so the child expands the
  variable. Double quotes make your own shell expand it first, which
  both breaks the call and leaks the value into shell history.

NOTES
  No subcommand ever writes a secret to stdout. That is the entire point:
  stdout is captured by agents, CI logs, and terminal scrollback.
"""

let arguments = Array(CommandLine.arguments.dropFirst())
guard let subcommand = arguments.first else {
    print(usage)
    exit(0)
}
let rest = Array(arguments.dropFirst())

switch subcommand {
case "set": cmdSet(rest)
case "run": cmdRun(rest)
case "list", "ls": cmdList()
case "rm", "delete": cmdRemove(rest)
case "-h", "--help", "help": print(usage)
default: die("unknown command '\(subcommand)'. Run '\(toolName) --help'.")
}
