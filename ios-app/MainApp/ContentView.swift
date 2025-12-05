import SwiftUI

@main
struct HSIPKeyboardApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .onOpenURL { url in
                    appState.handleDeepLink(url)
                }
        }
    }
}

class AppState: ObservableObject {
    @Published var showContactAdded = false
    @Published var addedContactName: String = ""

    func handleDeepLink(_ url: URL) {
        guard url.scheme == "hsip", url.host == "add" else { return }

        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        guard let peerId = components?.queryItems?.first(where: { $0.name == "id" })?.value,
              let displayName = components?.queryItems?.first(where: { $0.name == "name" })?.value else {
            return
        }

        // TODO: In production, generate session key via X25519 key exchange
        let dummySessionKey = Data(repeating: 0, count: 32)

        SessionStorage.shared.addContact(
            peerId: peerId,
            displayName: displayName,
            sessionKey: dummySessionKey
        )

        addedContactName = displayName
        showContactAdded = true
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var currentStep: SetupStep = .welcome

    var body: some View {
        NavigationView {
            ZStack {
                switch currentStep {
                case .welcome:
                    WelcomeView(onContinue: { currentStep = .identity })
                case .identity:
                    IdentityView(onContinue: { currentStep = .contacts })
                case .contacts:
                    ContactsView(onContinue: { currentStep = .enableKeyboard })
                case .enableKeyboard:
                    EnableKeyboardView()
                }

                if appState.showContactAdded {
                    ContactAddedOverlay(
                        contactName: appState.addedContactName,
                        onDismiss: { appState.showContactAdded = false }
                    )
                }
            }
        }
    }
}

enum SetupStep {
    case welcome
    case identity
    case contacts
    case enableKeyboard
}

// MARK: - Welcome View

struct WelcomeView: View {
    let onContinue: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Text("🔐")
                .font(.system(size: 72))

            Text("Welcome to HSIP")
                .font(.system(size: 32, weight: .bold))

            Text("End-to-end encrypted messaging in any app")
                .font(.system(size: 16))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Spacer()

            Button(action: onContinue) {
                Text("Get Started")
                    .font(.system(size: 18, weight: .semibold))
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
            }
        }
        .padding(32)
    }
}

// MARK: - Identity View

struct IdentityView: View {
    let onContinue: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                Text("Your Identity")
                    .font(.system(size: 28, weight: .bold))
                    .padding(.top, 32)

                Text("Your HSIP identity has been generated!")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)

                VStack(alignment: .leading, spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Display Name")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                        Text(SessionStorage.shared.getDisplayName())
                            .font(.system(size: 18, weight: .medium))
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Peer ID (First 32 chars)")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                        Text((SessionStorage.shared.getPeerID() ?? "").prefix(32) + "...")
                            .font(.system(size: 14, design: .monospaced))
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.systemGray6))
                .cornerRadius(12)

                Spacer()

                Button(action: onContinue) {
                    Text("Continue")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
            }
            .padding(32)
        }
    }
}

// MARK: - Contacts View

struct ContactsView: View {
    let onContinue: () -> Void
    @State private var showShareSheet = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                Text("Add Contacts")
                    .font(.system(size: 28, weight: .bold))
                    .padding(.top, 32)

                Text("Share your contact info to exchange encrypted messages")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                Button(action: { showShareSheet = true }) {
                    HStack {
                        Text("📤")
                        Text("Share My Contact")
                    }
                    .font(.system(size: 18, weight: .semibold))
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color(.systemGray6))
                    .foregroundColor(.primary)
                    .cornerRadius(12)
                }

                Button(action: {}) {
                    HStack {
                        Text("📱")
                        Text("Show QR Code")
                    }
                    .font(.system(size: 18, weight: .semibold))
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color(.systemGray6))
                    .foregroundColor(.primary)
                    .cornerRadius(12)
                }

                Divider()
                    .padding(.vertical)

                Text("When someone shares their HSIP contact with you, just click the link to add them.")
                    .font(.system(size: 14))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                Spacer()

                VStack(spacing: 12) {
                    Button(action: onContinue) {
                        Text("Continue")
                            .font(.system(size: 18, weight: .semibold))
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(12)
                    }

                    Button(action: onContinue) {
                        Text("Skip for now")
                            .font(.system(size: 16))
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding(32)
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: [SessionStorage.shared.getContactSharingText()])
        }
    }
}

// MARK: - Enable Keyboard View

struct EnableKeyboardView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                Text("Enable HSIP Keyboard")
                    .font(.system(size: 28, weight: .bold))
                    .padding(.top, 32)

                Text("To use HSIP encryption, enable the keyboard in your system settings:")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 12) {
                    InstructionRow(number: "1", text: "Open Settings app")
                    InstructionRow(number: "2", text: "Tap General → Keyboard")
                    InstructionRow(number: "3", text: "Tap Keyboards")
                    InstructionRow(number: "4", text: "Tap Add New Keyboard...")
                    InstructionRow(number: "5", text: "Select 'HSIP Keyboard'")
                    InstructionRow(number: "6", text: "Enable 'Allow Full Access'")
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.systemGray6))
                .cornerRadius(12)

                Spacer()

                Button(action: {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                }) {
                    Text("Open Settings")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
            }
            .padding(32)
        }
    }
}

struct InstructionRow: View {
    let number: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number)
                .font(.system(size: 16, weight: .bold))
                .frame(width: 24, height: 24)
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(12)

            Text(text)
                .font(.system(size: 16, weight: .medium))
        }
    }
}

// MARK: - Contact Added Overlay

struct ContactAddedOverlay: View {
    let contactName: String
    let onDismiss: () -> Void

    var body: some View {
        ZStack {
            Color.black.opacity(0.4)
                .ignoresSafeArea()
                .onTapGesture {
                    onDismiss()
                }

            VStack(spacing: 16) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.green)

                Text("Contact Added!")
                    .font(.system(size: 24, weight: .bold))

                Text(contactName)
                    .font(.system(size: 18))
                    .foregroundColor(.secondary)

                Button(action: onDismiss) {
                    Text("OK")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
            }
            .padding(32)
            .background(Color(.systemBackground))
            .cornerRadius(20)
            .shadow(radius: 20)
            .padding(32)
        }
    }
}

// MARK: - Share Sheet

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
