import UIKit
import SwiftUI

/**
 * HSIP Keyboard View Controller
 *
 * Main keyboard extension controller that provides the keyboard UI
 * and handles encryption/decryption
 */
class KeyboardViewController: UIInputViewController {

    private var hostingController: UIHostingController<KeyboardView>?
    private var selectedRecipient: SessionStorage.Contact?

    override func viewDidLoad() {
        super.viewDidLoad()

        // Create SwiftUI keyboard view
        let keyboardView = KeyboardView(
            onKeyPress: { [weak self] key in
                self?.handleKeyPress(key)
            },
            onBackspace: { [weak self] in
                self?.handleBackspace()
            },
            onSpace: { [weak self] in
                self?.handleSpace()
            },
            onReturn: { [weak self] in
                self?.handleReturn()
            },
            onRecipientSelect: { [weak self] recipient in
                self?.selectedRecipient = recipient
            },
            selectedRecipient: selectedRecipient,
            contacts: Array(SessionStorage.shared.getContacts().values)
        )

        // Wrap in hosting controller
        hostingController = UIHostingController(rootView: keyboardView)

        if let hostingView = hostingController?.view {
            hostingView.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(hostingView)

            NSLayoutConstraint.activate([
                hostingView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                hostingView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                hostingView.topAnchor.constraint(equalTo: view.topAnchor),
                hostingView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
            ])
        }
    }

    // MARK: - Key Press Handlers

    private func handleKeyPress(_ key: Character) {
        textDocumentProxy.insertText(String(key))
    }

    private func handleBackspace() {
        textDocumentProxy.deleteBackward()
    }

    private func handleSpace() {
        textDocumentProxy.insertText(" ")
    }

    private func handleReturn() {
        // Check if we should encrypt the current text
        if let recipient = selectedRecipient {
            encryptCurrentText(recipient: recipient)
        } else {
            textDocumentProxy.insertText("\n")
        }
    }

    // MARK: - Encryption/Decryption

    private func encryptCurrentText(recipient: SessionStorage.Contact) {
        guard let currentText = textDocumentProxy.documentContextBeforeInput else {
            return
        }

        if currentText.isEmpty {
            return
        }

        // Encrypt the text
        if let encrypted = SessionStorage.shared.encrypt(
            plaintext: currentText,
            recipientPeerId: recipient.peerId
        ) {
            // Delete current text
            for _ in 0..<currentText.count {
                textDocumentProxy.deleteBackward()
            }

            // Insert encrypted text
            textDocumentProxy.insertText(encrypted)

            // Clear recipient selection
            selectedRecipient = nil
        }
    }

    override func textWillChange(_ textInput: UITextInput?) {
        // Called when text is about to change
    }

    override func textDidChange(_ textInput: UITextInput?) {
        // Called after text changed - could detect HSIP messages here
    }
}

// MARK: - SwiftUI Keyboard View

struct KeyboardView: View {
    let onKeyPress: (Character) -> Void
    let onBackspace: () -> Void
    let onSpace: () -> Void
    let onReturn: () -> Void
    let onRecipientSelect: (SessionStorage.Contact?) -> Void

    @State var selectedRecipient: SessionStorage.Contact?
    let contacts: [SessionStorage.Contact]

    @State private var showRecipientSelector = false

    var body: some View {
        VStack(spacing: 4) {
            // Top bar with HSIP indicator
            TopBar(
                selectedRecipient: selectedRecipient,
                onRecipientClick: { showRecipientSelector.toggle() },
                onClearRecipient: {
                    selectedRecipient = nil
                    onRecipientSelect(nil)
                }
            )

            // Recipient selector
            if showRecipientSelector {
                RecipientSelector(
                    contacts: contacts,
                    onSelect: { contact in
                        selectedRecipient = contact
                        onRecipientSelect(contact)
                        showRecipientSelector = false
                    },
                    onDismiss: { showRecipientSelector = false }
                )
            }

            // QWERTY keyboard layout
            QWERTYLayout(
                onKeyPress: onKeyPress,
                onBackspace: onBackspace,
                onSpace: onSpace,
                onReturn: onReturn
            )
        }
        .padding(4)
        .background(Color(UIColor.systemGray6))
    }
}

struct TopBar: View {
    let selectedRecipient: SessionStorage.Contact?
    let onRecipientClick: () -> Void
    let onClearRecipient: () -> Void

    var body: some View {
        HStack {
            // HSIP lock icon
            Image(systemName: "lock.fill")
                .foregroundColor(selectedRecipient != nil ? .green : .gray)
                .font(.system(size: 16))

            // Recipient name or "No Encryption"
            Button(action: onRecipientClick) {
                Text(selectedRecipient?.displayName ?? "No Encryption")
                    .font(.system(size: 14))
                    .foregroundColor(selectedRecipient != nil ? .primary : .secondary)
            }

            Spacer()

            // Clear button
            if selectedRecipient != nil {
                Button(action: onClearRecipient) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.gray)
                        .font(.system(size: 16))
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(UIColor.systemGray5))
        .cornerRadius(8)
    }
}

struct RecipientSelector: View {
    let contacts: [SessionStorage.Contact]
    let onSelect: (SessionStorage.Contact) -> Void
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Encrypt for:")
                .font(.system(size: 12, weight: .bold))
                .padding(.horizontal, 12)
                .padding(.top, 8)

            if contacts.isEmpty {
                Text("No contacts. Open HSIP app to add contacts.")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
            } else {
                ForEach(contacts, id: \.peerId) { contact in
                    Button(action: { onSelect(contact) }) {
                        HStack {
                            Image(systemName: "person.fill")
                                .foregroundColor(.green)
                            Text(contact.displayName)
                                .foregroundColor(.primary)
                            Spacer()
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }
                }
            }
        }
        .background(Color(UIColor.systemGray5))
        .cornerRadius(8)
    }
}

struct QWERTYLayout: View {
    let onKeyPress: (Character) -> Void
    let onBackspace: () -> Void
    let onSpace: () -> Void
    let onReturn: () -> Void

    let row1: [Character] = ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"]
    let row2: [Character] = ["A", "S", "D", "F", "G", "H", "J", "K", "L"]
    let row3: [Character] = ["Z", "X", "C", "V", "B", "N", "M"]

    var body: some View {
        VStack(spacing: 8) {
            // Row 1
            HStack(spacing: 4) {
                ForEach(row1, id: \.self) { key in
                    KeyButton(text: String(key)) {
                        onKeyPress(key)
                    }
                }
            }

            // Row 2
            HStack(spacing: 4) {
                Spacer().frame(width: 16)
                ForEach(row2, id: \.self) { key in
                    KeyButton(text: String(key)) {
                        onKeyPress(key)
                    }
                }
                Spacer().frame(width: 16)
            }

            // Row 3
            HStack(spacing: 4) {
                ForEach(row3, id: \.self) { key in
                    KeyButton(text: String(key)) {
                        onKeyPress(key)
                    }
                }
                KeyButton(text: "⌫", width: 60) {
                    onBackspace()
                }
            }

            // Row 4 - Space and Return
            HStack(spacing: 4) {
                KeyButton(text: "123", width: 60) {
                    // TODO: Switch to numbers
                }
                KeyButton(text: "Space", isWide: true) {
                    onSpace()
                }
                KeyButton(text: "↵", width: 60, color: .blue) {
                    onReturn()
                }
            }
        }
    }
}

struct KeyButton: View {
    let text: String
    var width: CGFloat? = nil
    var isWide: Bool = false
    var color: Color = Color(UIColor.systemGray4)
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(text)
                .font(.system(size: 18, weight: .medium))
                .foregroundColor(.primary)
                .frame(maxWidth: isWide ? .infinity : width, minHeight: 44)
                .frame(width: width)
                .background(color)
                .cornerRadius(6)
        }
    }
}
