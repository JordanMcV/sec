import Foundation

let toolName = "sec"
let vault = Vault()

func die(_ message: String) -> Never {
    note(message)
    exit(1)
}

func note(_ message: String) {
    FileHandle.standardError.write(Data("\(toolName): \(message)\n".utf8))
}

func defaultVarName(for name: String) -> String {
    String(name.map { $0.isLetter || $0.isNumber ? $0 : "_" }).uppercased()
}

func isValidVariableName(_ name: String) -> Bool {
    name.range(of: #"\A[A-Za-z_][A-Za-z0-9_]*\z"#, options: .regularExpression) != nil
}

func environmentValue(for secret: Data, name: String) throws -> String {
    guard let value = String(data: secret, encoding: .utf8) else {
        throw SecError("'\(name)' is not valid UTF-8 and cannot be an environment variable")
    }
    guard !secret.contains(0) else {
        throw SecError("'\(name)' contains a NUL byte and cannot be an environment variable")
    }
    return value
}

func cmdSet(_ args: [String]) throws {
    guard args.count == 1, !args[0].isEmpty else {
        throw SecError("usage: sec set <name>   (nonempty name; secret is read from stdin)")
    }
    let name = args[0]
    if isatty(FileHandle.standardInput.fileDescriptor) == 1 {
        throw SecError("refusing to read a secret from a terminal. Pipe it in from your password manager or another trusted source.")
    }
    var bytes = [UInt8](FileHandle.standardInput.readDataToEndOfFile())
    while let last = bytes.last, last == 0x0A || last == 0x0D { bytes.removeLast() }
    guard !bytes.isEmpty else { throw SecError("refusing to store an empty secret") }
    let secret = Data(bytes)
    _ = try environmentValue(for: secret, name: name)
    let key = try vault.loadKey(reason: "verify and store '\(name)' with sec")
    let encrypted = try SealedSecret.seal(secret, name: name, publicKey: key.publicKey)
    let sealed = try SealedSecret.decode(encrypted, publicKey: key.publicKey)
    guard try key.open(sealed, name: name) == secret else {
        throw SecError("encryption verification failed; existing entry was not changed")
    }
    try vault.secrets.store(name, data: encrypted)
    note("stored '\(name)' encrypted")
    if try vault.legacy.names().contains(name) {
        note("an old unprotected copy of '\(name)' still exists under service 'sec' in Keychain Access")
    }
}

func cmdRun(_ args: [String]) throws {
    guard let separator = args.firstIndex(of: "--") else {
        throw SecError("usage: sec run <name|VAR=name>... -- <command> [args...]")
    }
    let specs = Array(args[..<separator])
    let command = Array(args[(separator + 1)...])
    guard !specs.isEmpty else { throw SecError("name at least one secret before --") }
    guard !command.isEmpty, !command[0].isEmpty else { throw SecError("no command given after --") }

    var resolved: [(variable: String, name: String)] = []
    var variables = Set<String>()
    for spec in specs {
        let variable: String
        let name: String
        if let eq = spec.firstIndex(of: "=") {
            variable = String(spec[..<eq])
            name = String(spec[spec.index(after: eq)...])
        } else {
            variable = defaultVarName(for: spec)
            name = spec
        }
        guard !name.isEmpty else { throw SecError("secret name cannot be empty") }
        guard isValidVariableName(variable) else {
            throw SecError("invalid environment variable '\(variable)'; use VAR=name with a name matching [A-Za-z_][A-Za-z0-9_]*")
        }
        guard variables.insert(variable).inserted else {
            throw SecError("duplicate environment variable '\(variable)'; choose distinct names with VAR=name")
        }
        resolved.append((variable, name))
    }

    // Read and validate every envelope before a private-key operation can prompt.
    let encrypted = try resolved.map { try vault.read($0.name) }
    let key = try vault.loadKey(reason: "release \(resolved.map(\.name).joined(separator: ", ")) to \(command[0])")
    let sealed = try encrypted.map { try SealedSecret.decode($0, publicKey: key.publicKey) }
    var values: [String] = []
    for (entry, record) in zip(resolved, sealed) {
        values.append(try environmentValue(for: key.open(record, name: entry.name), name: entry.name))
    }
    for (entry, value) in zip(resolved, values) {
        guard setenv(entry.variable, value, 1) == 0 else {
            throw SecError("could not set environment variable '\(entry.variable)': \(String(cString: strerror(errno)))")
        }
    }

    let argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
    execvp(command[0], argv)
    throw SecError("could not exec '\(command[0])': \(String(cString: strerror(errno)))")
}

func cmdList() throws {
    let encrypted = Set(try vault.secrets.names())
    let legacy = Set(try vault.legacy.names())
    let names = encrypted.union(legacy).sorted()
    if names.isEmpty { note("no secrets stored"); return }
    for name in names {
        let variable = defaultVarName(for: name)
        let mapping = isValidVariableName(variable) ? "$\(variable)" : "(use VAR=name)"
        let status = !encrypted.contains(name) ? "\tlegacy: migration required" : legacy.contains(name) ? "\tlegacy copy remains" : ""
        print("\(name)\t\(mapping)\(status)")
    }
}

let usage = """
sec - release encrypted secrets to a command with Touch ID

USAGE
  sec init                              initialize this Mac's encryption key
  sec set <name>                        encrypt and verify a secret from stdin
  sec run <name|VAR=name>... -- <cmd>     Touch ID, decrypt, inject, exec
  sec list                              list names, never values
  sec rm <name>                         delete an encrypted secret
  sec migrate <name>...                  copy and verify legacy entries

EXAMPLES
  sec init
  printf %s 'example-token' | sec set api-token
  sec run TOKEN=api-token -- ./deploy.sh
  sec run api-token -- \\
    sh -c 'printf "Authorization: Bearer %s\\n" "$API_TOKEN" |
      curl -sS --header @- https://api.example.com/resource'

NOTES
  Requires macOS 14+, Secure Enclave, and enrolled Touch ID. No password
  fallback or biometric bypass. Keep recovery copies of your credentials:
  changing fingerprints or losing this Mac's key can make them unrecoverable.
  sec never prints values; your command must also avoid exposing them.
  Migration keeps legacy copies; remove those separately in Keychain Access.
"""

let arguments = Array(CommandLine.arguments.dropFirst())
let subcommand = arguments.first ?? "--help"
let rest = Array(arguments.dropFirst())
do {
    switch subcommand {
    case "init":
        guard rest.isEmpty else { throw SecError("usage: sec init") }
        try vault.initialize()
    case "set": try cmdSet(rest)
    case "run": try cmdRun(rest)
    case "list", "ls":
        guard rest.isEmpty else { throw SecError("usage: sec list") }
        try cmdList()
    case "rm", "delete":
        guard rest.count == 1, !rest[0].isEmpty else { throw SecError("usage: sec rm <name>") }
        try vault.secrets.remove(rest[0])
        note("deleted encrypted '\(rest[0])'")
        if try vault.legacy.names().contains(rest[0]) { note("legacy copy remains under service 'sec' in Keychain Access") }
    case "migrate":
        guard !rest.isEmpty, rest.allSatisfy({ !$0.isEmpty }) else { throw SecError("usage: sec migrate <name>...") }
        try vault.migrate(rest)
    case "-h", "--help", "help": print(usage)
    default: throw SecError("unknown command '\(subcommand)'. Run 'sec --help'.")
    }
} catch let error as SecError {
    die(error.description)
} catch {
    // Avoid dumping crypto objects or stored bytes through error descriptions.
    die("operation failed (\((error as NSError).code)); no command was launched")
}
