package io.hsip.keyboard.crypto

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * JNI Bridge to Rust HSIP crypto implementation
 */
class HSIPEngine(context: Context) {

    private val prefs: SharedPreferences

    init {
        // Use EncryptedSharedPreferences for key storage
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        prefs = EncryptedSharedPreferences.create(
            context,
            "hsip_secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // ============================================
    // Native JNI methods (TODO: implement in Rust)
    // ============================================

    /**
     * Generate new Ed25519 identity
     * Returns: Base64-encoded PeerID (32 bytes)
     */
    private fun nativeGenerateIdentity(): String {
        // TODO: Replace with actual Rust JNI implementation
        // For now, generate a mock PeerID for testing
        return android.util.Base64.encodeToString(
            java.security.SecureRandom().let { random ->
                ByteArray(32).also { random.nextBytes(it) }
            },
            android.util.Base64.NO_WRAP
        )
    }

    /**
     * Encrypt plaintext message
     *
     * @param plaintext The message to encrypt
     * @param sessionKey 32-byte session key (Base64)
     * @param peerId 32-byte recipient PeerID (Base64)
     * @return Encrypted message in format: 🔒<base64(version+peerID+nonce+ciphertext+tag)>
     */
    private fun nativeEncrypt(
        plaintext: String,
        sessionKey: String,
        peerId: String
    ): String {
        // TODO: Replace with actual ChaCha20-Poly1305 encryption
        // For now, return a mock encrypted message
        return "🔒MOCK_ENCRYPTED_MESSAGE_$plaintext"
    }

    /**
     * Decrypt encrypted message
     *
     * @param encrypted The encrypted message (🔒<base64...>)
     * @param sessionKey 32-byte session key (Base64)
     * @return Decrypted plaintext or null if decryption fails
     */
    private fun nativeDecrypt(
        encrypted: String,
        sessionKey: String
    ): String? {
        // TODO: Replace with actual ChaCha20-Poly1305 decryption
        // For now, return mock decrypted message
        return encrypted.removePrefix("🔒MOCK_ENCRYPTED_MESSAGE_")
    }

    /**
     * Check if text contains HSIP encrypted message
     */
    private fun nativeContainsHSIPMessage(text: String): Boolean {
        // TODO: Replace with actual HSIP message detection
        return text.contains("🔒")
    }

    /**
     * Extract HSIP message from text
     */
    private fun nativeExtractMessage(text: String): String? {
        // TODO: Replace with actual HSIP message extraction
        return if (text.contains("🔒")) text else null
    }

    /**
     * Derive PeerID from public key
     */
    private fun nativeDerivePeerID(publicKey: String): String {
        // TODO: Replace with actual Ed25519 PeerID derivation
        return publicKey
    }

    // ============================================
    // Kotlin wrapper methods
    // ============================================

    fun hasIdentity(): Boolean {
        return prefs.contains("peer_id")
    }

    fun generateIdentity(): String {
        val peerId = nativeGenerateIdentity()
        prefs.edit()
            .putString("peer_id", peerId)
            .putString("display_name", "User-${peerId.take(8)}")
            .apply()
        return peerId
    }

    fun getPeerID(): String? {
        return prefs.getString("peer_id", null)
    }

    fun getDisplayName(): String {
        return prefs.getString("display_name", "Unknown") ?: "Unknown"
    }

    fun setDisplayName(name: String) {
        prefs.edit().putString("display_name", name).apply()
    }

    /**
     * Add a contact (from deep link or QR scan)
     *
     * @param peerId Base64-encoded PeerID
     * @param displayName Contact's display name
     * @param sessionKey Base64-encoded session key (derived via X25519 key exchange)
     */
    fun addContact(peerId: String, displayName: String, sessionKey: String) {
        val contactsJson = prefs.getString("contacts", "{}") ?: "{}"
        val contacts = parseContactsJson(contactsJson).toMutableMap()

        contacts[peerId] = Contact(
            peerId = peerId,
            displayName = displayName,
            sessionKey = sessionKey,
            addedAt = System.currentTimeMillis()
        )

        prefs.edit()
            .putString("contacts", serializeContacts(contacts))
            .apply()
    }

    fun getContacts(): Map<String, Contact> {
        val contactsJson = prefs.getString("contacts", "{}") ?: "{}"
        return parseContactsJson(contactsJson)
    }

    fun getContact(peerId: String): Contact? {
        return getContacts()[peerId]
    }

    /**
     * Encrypt message for a specific contact
     */
    fun encrypt(plaintext: String, recipientPeerId: String): String? {
        val contact = getContact(recipientPeerId) ?: return null
        val myPeerId = getPeerID() ?: return null

        return try {
            nativeEncrypt(plaintext, contact.sessionKey, myPeerId)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Decrypt message from any contact
     */
    fun decrypt(encrypted: String): DecryptResult? {
        // Try decrypting with each contact's session key
        for ((peerId, contact) in getContacts()) {
            try {
                val plaintext = nativeDecrypt(encrypted, contact.sessionKey)
                if (plaintext != null) {
                    return DecryptResult(
                        plaintext = plaintext,
                        senderPeerId = peerId,
                        senderName = contact.displayName
                    )
                }
            } catch (e: Exception) {
                // Try next contact
                continue
            }
        }
        return null
    }

    fun containsHSIPMessage(text: String): Boolean {
        return nativeContainsHSIPMessage(text)
    }

    fun extractMessage(text: String): String? {
        return nativeExtractMessage(text)
    }

    /**
     * Generate contact sharing link
     * Format: hsip://add?id=<BASE64_PEER_ID>&name=<DISPLAY_NAME>
     */
    fun getContactSharingLink(): String {
        val peerId = getPeerID() ?: return ""
        val displayName = getDisplayName()
        return "hsip://add?id=$peerId&name=${displayName.replace(" ", "%20")}"
    }

    /**
     * Generate shareable text for contact exchange
     */
    fun getContactSharingText(): String {
        val link = getContactSharingLink()
        val displayName = getDisplayName()
        return """
            🔐 HSIP Contact
            $displayName
            $link
        """.trimIndent()
    }

    // ============================================
    // Helper methods for JSON serialization
    // ============================================

    private fun parseContactsJson(json: String): Map<String, Contact> {
        // Simple JSON parsing (use Gson in production)
        // For now, return empty map
        return emptyMap()
    }

    private fun serializeContacts(contacts: Map<String, Contact>): String {
        // Simple JSON serialization (use Gson in production)
        return "{}"
    }
}

data class Contact(
    val peerId: String,
    val displayName: String,
    val sessionKey: String,
    val addedAt: Long
)

data class DecryptResult(
    val plaintext: String,
    val senderPeerId: String,
    val senderName: String
)
