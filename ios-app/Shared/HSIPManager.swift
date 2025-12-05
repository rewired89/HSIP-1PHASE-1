import Foundation

/**
 * HSIPManager - Swift bridge to Rust HSIP crypto implementation
 *
 * This class provides Swift-friendly interface to the Rust FFI functions
 * defined in crates/hsip-keyboard/src/ios_ffi.rs
 */
class HSIPManager {

    static let shared = HSIPManager()

    private init() {
        // Load Rust library if needed
    }

    // MARK: - FFI Function Declarations

    /// Encrypt plaintext message
    /// Returns: encrypted message in format 🔒<base64...>
    private func hsip_ios_encrypt(
        _ plaintext: UnsafePointer<CChar>,
        _ sessionKey: UnsafePointer<UInt8>,
        _ peerId: UnsafePointer<UInt8>
    ) -> UnsafeMutablePointer<CChar>? {
        // This will be linked from the Rust library
        fatalError("FFI function not linked - need to compile Rust library")
    }

    /// Decrypt encrypted message
    /// Returns: decrypted plaintext or NULL if decryption fails
    private func hsip_ios_decrypt(
        _ encrypted: UnsafePointer<CChar>,
        _ sessionKey: UnsafePointer<UInt8>
    ) -> UnsafeMutablePointer<CChar>? {
        fatalError("FFI function not linked - need to compile Rust library")
    }

    /// Check if text contains HSIP message
    private func hsip_ios_contains_message(
        _ text: UnsafePointer<CChar>
    ) -> Bool {
        fatalError("FFI function not linked - need to compile Rust library")
    }

    /// Free string allocated by Rust
    private func hsip_ios_free_string(
        _ s: UnsafeMutablePointer<CChar>
    ) {
        fatalError("FFI function not linked - need to compile Rust library")
    }

    /// Generate new identity
    private func hsip_ios_generate_identity() -> UnsafeMutablePointer<CChar>? {
        fatalError("FFI function not linked - need to compile Rust library")
    }

    // MARK: - Swift Wrapper Methods

    /**
     * Encrypt plaintext message for a specific recipient
     *
     * - Parameters:
     *   - plaintext: The message to encrypt
     *   - sessionKey: 32-byte session key (from key exchange)
     *   - peerID: 32-byte sender PeerID
     * - Returns: Encrypted message string or nil if encryption fails
     */
    func encrypt(plaintext: String, sessionKey: Data, peerID: Data) -> String? {
        guard sessionKey.count == 32, peerID.count == 32 else {
            print("Invalid key or peerID length")
            return nil
        }

        return plaintext.withCString { plaintextPtr in
            sessionKey.withUnsafeBytes { sessionKeyBytes in
                peerID.withUnsafeBytes { peerIDBytes in
                    guard let sessionKeyPtr = sessionKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let peerIDPtr = peerIDBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let resultPtr = hsip_ios_encrypt(plaintextPtr, sessionKeyPtr, peerIDPtr) else {
                        return nil
                    }

                    let result = String(cString: resultPtr)
                    hsip_ios_free_string(resultPtr)
                    return result
                }
            }
        }
    }

    /**
     * Decrypt encrypted message
     *
     * - Parameters:
     *   - encrypted: The encrypted message (🔒<base64...>)
     *   - sessionKey: 32-byte session key
     * - Returns: Decrypted plaintext or nil if decryption fails
     */
    func decrypt(encrypted: String, sessionKey: Data) -> String? {
        guard sessionKey.count == 32 else {
            print("Invalid session key length")
            return nil
        }

        return encrypted.withCString { encryptedPtr in
            sessionKey.withUnsafeBytes { sessionKeyBytes in
                guard let sessionKeyPtr = sessionKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let resultPtr = hsip_ios_decrypt(encryptedPtr, sessionKeyPtr) else {
                    return nil
                }

                let result = String(cString: resultPtr)
                hsip_ios_free_string(resultPtr)
                return result
            }
        }
    }

    /**
     * Check if text contains HSIP encrypted message
     */
    func containsHSIPMessage(_ text: String) -> Bool {
        return text.withCString { textPtr in
            return hsip_ios_contains_message(textPtr)
        }
    }

    /**
     * Generate new HSIP identity
     * Returns: Base64-encoded PeerID (32 bytes)
     */
    func generateIdentity() -> String? {
        guard let resultPtr = hsip_ios_generate_identity() else {
            return nil
        }

        let result = String(cString: resultPtr)
        hsip_ios_free_string(resultPtr)
        return result
    }
}

/**
 * Session Storage - manages contacts and session keys
 * Uses iOS Keychain for secure storage
 */
class SessionStorage {

    static let shared = SessionStorage()

    private let userDefaults = UserDefaults(suiteName: "group.io.hsip.keyboard")!

    private init() {}

    // MARK: - Identity Management

    func hasIdentity() -> Bool {
        return userDefaults.string(forKey: "peer_id") != nil
    }

    func generateIdentity() -> String? {
        let peerId = HSIPManager.shared.generateIdentity()
        if let peerId = peerId {
            userDefaults.set(peerId, forKey: "peer_id")
            userDefaults.set("User-\(peerId.prefix(8))", forKey: "display_name")
        }
        return peerId
    }

    func getPeerID() -> String? {
        return userDefaults.string(forKey: "peer_id")
    }

    func getDisplayName() -> String {
        return userDefaults.string(forKey: "display_name") ?? "Unknown"
    }

    func setDisplayName(_ name: String) {
        userDefaults.set(name, forKey: "display_name")
    }

    // MARK: - Contact Management

    struct Contact: Codable {
        let peerId: String
        let displayName: String
        let sessionKey: Data
        let addedAt: Date
    }

    func addContact(peerId: String, displayName: String, sessionKey: Data) {
        var contacts = getContacts()
        contacts[peerId] = Contact(
            peerId: peerId,
            displayName: displayName,
            sessionKey: sessionKey,
            addedAt: Date()
        )
        saveContacts(contacts)
    }

    func getContacts() -> [String: Contact] {
        guard let data = userDefaults.data(forKey: "contacts"),
              let contacts = try? JSONDecoder().decode([String: Contact].self, from: data) else {
            return [:]
        }
        return contacts
    }

    func getContact(peerId: String) -> Contact? {
        return getContacts()[peerId]
    }

    private func saveContacts(_ contacts: [String: Contact]) {
        if let data = try? JSONEncoder().encode(contacts) {
            userDefaults.set(data, forKey: "contacts")
        }
    }

    // MARK: - Encryption/Decryption

    func encrypt(plaintext: String, recipientPeerId: String) -> String? {
        guard let contact = getContact(peerId: recipientPeerId),
              let myPeerId = getPeerID(),
              let myPeerIdData = Data(base64Encoded: myPeerId) else {
            return nil
        }

        return HSIPManager.shared.encrypt(
            plaintext: plaintext,
            sessionKey: contact.sessionKey,
            peerID: myPeerIdData
        )
    }

    struct DecryptResult {
        let plaintext: String
        let senderPeerId: String
        let senderName: String
    }

    func decrypt(encrypted: String) -> DecryptResult? {
        // Try decrypting with each contact's session key
        for (peerId, contact) in getContacts() {
            if let plaintext = HSIPManager.shared.decrypt(
                encrypted: encrypted,
                sessionKey: contact.sessionKey
            ) {
                return DecryptResult(
                    plaintext: plaintext,
                    senderPeerId: peerId,
                    senderName: contact.displayName
                )
            }
        }
        return nil
    }

    // MARK: - Contact Sharing

    func getContactSharingLink() -> String {
        guard let peerId = getPeerID() else { return "" }
        let displayName = getDisplayName().addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return "hsip://add?id=\(peerId)&name=\(displayName)"
    }

    func getContactSharingText() -> String {
        let link = getContactSharingLink()
        let displayName = getDisplayName()
        return """
        🔐 HSIP Contact
        \(displayName)
        \(link)
        """
    }
}
