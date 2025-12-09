package io.hsip.keyboard.keyboard

import android.inputmethodservice.InputMethodService
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.ComposeView
import androidx.lifecycle.ViewTreeLifecycleOwner
import androidx.savedstate.setViewTreeSavedStateRegistryOwner
import io.hsip.keyboard.HSIPApplication
import io.hsip.keyboard.crypto.Contact
import io.hsip.keyboard.crypto.HSIPEngine
import io.hsip.keyboard.ui.keyboard.KeyboardView

/**
 * HSIP Secure Keyboard Service
 *
 * Main InputMethodService that provides the keyboard UI and handles
 * encryption/decryption of messages.
 */
class HSIPKeyboardService : InputMethodService() {

    private lateinit var hsipEngine: HSIPEngine
    private var selectedRecipient by mutableStateOf<Contact?>(null)
    private var keyboardView: ComposeView? = null

    override fun onCreate() {
        super.onCreate()
        hsipEngine = HSIPApplication.instance.hsipEngine
    }

    override fun onCreateInputView(): View {
        // Create Jetpack Compose view for keyboard UI
        keyboardView = ComposeView(this).apply {
            setContent {
                KeyboardView(
                    onKeyPress = { key -> handleKeyPress(key) },
                    onBackspace = { handleBackspace() },
                    onSpace = { handleSpace() },
                    onEnter = { handleEnter() },
                    onRecipientSelect = { recipient -> handleRecipientSelect(recipient) },
                    selectedRecipient = selectedRecipient,
                    contacts = hsipEngine.getContacts().values.toList()
                )
            }
        }

        return keyboardView!!
    }

    override fun onStartInputView(info: EditorInfo?, restarting: Boolean) {
        super.onStartInputView(info, restarting)

        // Check if current text contains HSIP messages
        val currentText = currentInputConnection?.getExtractedText(null, 0)?.text?.toString()
        if (currentText != null && hsipEngine.containsHSIPMessage(currentText)) {
            // Show notification that encrypted messages are detected
            showEncryptedMessageDetected()
        }
    }

    // ============================================
    // Key Press Handlers
    // ============================================

    private fun handleKeyPress(key: Char) {
        currentInputConnection?.commitText(key.toString(), 1)
    }

    private fun handleBackspace() {
        currentInputConnection?.deleteSurroundingText(1, 0)
    }

    private fun handleSpace() {
        currentInputConnection?.commitText(" ", 1)
    }

    private fun handleEnter() {
        // Check if we should encrypt the current text
        if (selectedRecipient != null) {
            encryptCurrentText()
        } else {
            // Just send newline
            currentInputConnection?.commitText("\n", 1)
        }
    }

    private fun handleRecipientSelect(recipient: Contact?) {
        selectedRecipient = recipient
    }

    // ============================================
    // Encryption/Decryption
    // ============================================

    private fun encryptCurrentText() {
        val recipient = selectedRecipient ?: return

        // Get current text from input field
        val currentText = currentInputConnection?.getExtractedText(null, 0)?.text?.toString()
        if (currentText.isNullOrBlank()) return

        // Encrypt the text
        val encrypted = hsipEngine.encrypt(currentText, recipient.peerId)
        if (encrypted != null) {
            // Replace entire text with encrypted version
            currentInputConnection?.setComposingRegion(0, currentText.length)
            currentInputConnection?.setComposingText(encrypted, 1)
            currentInputConnection?.finishComposingText()

            // Clear recipient selection after encrypting
            selectedRecipient = null
        } else {
            // Show error
            showEncryptionError()
        }
    }

    /**
     * Detect and offer to decrypt HSIP messages
     */
    private fun showEncryptedMessageDetected() {
        val currentText = currentInputConnection?.getExtractedText(null, 0)?.text?.toString()
        if (currentText == null) return

        val encryptedMessage = hsipEngine.extractMessage(currentText)
        if (encryptedMessage != null) {
            // Show decrypt button/notification
            // This would trigger a popup or notification in a full implementation
        }
    }

    private fun showEncryptionError() {
        // Show error toast or notification
    }

    override fun onDestroy() {
        super.onDestroy()
        keyboardView = null
    }
}
