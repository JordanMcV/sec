import CryptoKit
import Foundation
import LocalAuthentication
import Security

final class VaultKey {
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    private let context: LAContext

    init(wrapped: Data? = nil, reason: String) throws {
        guard SecureEnclave.isAvailable else {
            throw SecError("Secure Enclave unavailable. Use a supported Mac with Touch ID in a local GUI session.")
        }
        context = LAContext()
        context.localizedReason = reason
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        do {
            if let wrapped {
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: wrapped,
                                                                    authenticationContext: context)
            } else {
                var error: Unmanaged<CFError>?
                guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                   [.privateKeyUsage, .biometryCurrentSet], &error) else {
                    throw SecError("could not create biometric access control")
                }
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access,
                                                                    authenticationContext: context)
            }
        } catch {
            throw SecError("could not open or create the Secure Enclave key (\((error as NSError).code)). "
                           + "Check Touch ID enrollment. Existing keys are never automatically replaced.")
        }
    }

    deinit { context.invalidate() }

    var wrapped: Data { key.dataRepresentation }
    var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }

    func open(_ sealed: SealedSecret, name: String) throws -> Data {
        do { return try sealed.open(name: name, privateKey: key) }
        catch {
            throw SecError("decryption failed (\((error as NSError).code)). Touch ID is required; "
                           + "cancellation, changed fingerprints, or damaged data prevent release.")
        }
    }
}
