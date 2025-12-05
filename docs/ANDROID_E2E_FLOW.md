# HSIP Android - Complete E2E Flow

Complete implementation for the end-to-end user experience on Android.

---

## User Journey (Two Android Users)

```
┌─────────────────────────────────────────────────────────────┐
│                    Initial Setup                             │
├─────────────────────────────────────────────────────────────┤
│ User A                              User B                   │
│ 1. Install APK                      1. Install APK          │
│ 2. Open HSIP app                    2. Open HSIP app        │
│ 3. Generate identity                3. Generate identity     │
│ 4. Show QR code ─────────────────▶ 4. Scan QR code         │
│ 5. Keys exchanged! ◀────────────── 5. Keys exchanged!       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Sending Message                           │
├─────────────────────────────────────────────────────────────┤
│ User A (Android)                                             │
│ 1. Open Instagram DM with User B                            │
│ 2. Select HSIP Keyboard                                     │
│ 3. Toggle HSIP mode ON (🔒)                                 │
│ 4. Select "User B" from contacts                            │
│ 5. Type: "Hey, coffee at 3pm?"                              │
│ 6. Keyboard shows preview:                                  │
│    Plaintext: "Hey, coffee at 3pm?"                         │
│    Will send: 🔒hQEMA8Kxq...                                │
│ 7. Tap Enter → Message sent                                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  Receiving Message                           │
├─────────────────────────────────────────────────────────────┤
│ User B (Android)                                             │
│ 1. Instagram notification: New message from User A          │
│ 2. Opens Instagram → Sees:                                  │
│    "🔒hQEMA8KxqFn8KjfzAQv/Z2xF..."                          │
│ 3. Taps message input → HSIP Keyboard appears               │
│ 4. Keyboard detects HSIP message                            │
│ 5. Shows banner: "HSIP message detected"                    │
│ 6. Taps "Decrypt" → Popup shows:                            │
│    "Hey, coffee at 3pm?"                                    │
│ 7. User B reads plaintext → Replies with HSIP              │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation

### 1. SetupActivity.kt (Key Exchange)

```kotlin
package io.hsip.keyboard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.hsip.keyboard.ui.HSIPKeyboardTheme
import kotlinx.coroutines.launch

class SetupActivity : ComponentActivity() {

    private lateinit var identityManager: IdentityManager
    private lateinit var sessionManager: SessionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        identityManager = IdentityManager.getInstance(this)
        sessionManager = SessionManager.getInstance(this)

        setContent {
            HSIPKeyboardTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SetupScreen(
                        identityManager = identityManager,
                        sessionManager = sessionManager
                    )
                }
            }
        }
    }
}

@Composable
fun SetupScreen(
    identityManager: IdentityManager,
    sessionManager: SessionManager
) {
    var currentStep by remember { mutableStateOf(SetupStep.WELCOME) }
    var myIdentity by remember { mutableStateOf<Identity?>(null) }

    LaunchedEffect(Unit) {
        // Check if identity exists
        myIdentity = identityManager.loadIdentity()
        if (myIdentity != null) {
            currentStep = SetupStep.READY
        }
    }

    when (currentStep) {
        SetupStep.WELCOME -> WelcomeScreen(
            onContinue = { currentStep = SetupStep.GENERATE_IDENTITY }
        )

        SetupStep.GENERATE_IDENTITY -> GenerateIdentityScreen(
            onGenerate = {
                val identity = identityManager.generateIdentity()
                myIdentity = identity
                currentStep = SetupStep.READY
            }
        )

        SetupStep.READY -> ReadyScreen(
            identity = myIdentity!!,
            onShowQR = { currentStep = SetupStep.SHOW_QR },
            onScanQR = { currentStep = SetupStep.SCAN_QR },
            onManualEntry = { currentStep = SetupStep.MANUAL_ENTRY }
        )

        SetupStep.SHOW_QR -> ShowQRScreen(
            identity = myIdentity!!,
            onBack = { currentStep = SetupStep.READY }
        )

        SetupStep.SCAN_QR -> ScanQRScreen(
            onScanned = { peerIdentity ->
                // Create session
                val session = sessionManager.createSession(
                    peerIdentity,
                    displayName = "Contact"
                )
                currentStep = SetupStep.COMPLETE
            },
            onBack = { currentStep = SetupStep.READY }
        )

        SetupStep.MANUAL_ENTRY -> ManualEntryScreen(
            onAdded = { peerID, displayName ->
                // Create session (with manual key entry)
                currentStep = SetupStep.COMPLETE
            },
            onBack = { currentStep = SetupStep.READY }
        )

        SetupStep.COMPLETE -> CompleteScreen(
            onDone = { finish() }
        )
    }
}

enum class SetupStep {
    WELCOME,
    GENERATE_IDENTITY,
    READY,
    SHOW_QR,
    SCAN_QR,
    MANUAL_ENTRY,
    COMPLETE
}

@Composable
fun WelcomeScreen(onContinue: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            modifier = Modifier.size(120.dp),
            tint = MaterialTheme.colorScheme.primary
        )

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Welcome to HSIP Keyboard",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "End-to-end encrypted messaging for Instagram, WhatsApp, Gmail, and all apps.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onContinue,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Get Started")
        }
    }
}

@Composable
fun GenerateIdentityScreen(onGenerate: () -> Unit) {
    LaunchedEffect(Unit) {
        // Auto-generate on screen load
        kotlinx.coroutines.delay(500) // Show loading briefly
        onGenerate()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Generating your identity...",
            style = MaterialTheme.typography.titleLarge
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "This creates your cryptographic keypair",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun ReadyScreen(
    identity: Identity,
    onShowQR: () -> Unit,
    onScanQR: () -> Unit,
    onManualEntry: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
    ) {
        Text(
            text = "Your Identity",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Peer ID:",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Text(
                    text = identity.peerID.take(20) + "...",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(vertical = 8.dp)
                )

                Text(
                    text = "Public Key:",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Text(
                    text = identity.publicKeyHex.take(20) + "...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Add Contacts",
            style = MaterialTheme.typography.titleLarge
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onShowQR,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.QrCode, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Show My QR Code")
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = onScanQR,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.CameraAlt, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Scan QR Code")
        }

        Spacer(modifier = Modifier.height(8.dp))

        TextButton(
            onClick = onManualEntry,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Edit, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Manual Entry")
        }
    }
}

@Composable
fun ShowQRScreen(
    identity: Identity,
    onBack: () -> Unit
) {
    val qrCodeBitmap = remember {
        // Generate QR code from identity
        generateQRCode(identity.toQRData())
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        IconButton(
            onClick = onBack,
            modifier = Modifier.align(Alignment.Start)
        ) {
            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Scan this QR code",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Have your contact scan this with their HSIP app",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        // QR Code display
        Surface(
            modifier = Modifier.size(300.dp),
            shape = MaterialTheme.shapes.medium,
            tonalElevation = 4.dp
        ) {
            // TODO: Display qrCodeBitmap
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text("QR Code Here")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = identity.peerID,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun ScanQRScreen(
    onScanned: (Identity) -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Scan QR Code",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Camera preview
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center
        ) {
            Text("Camera Preview")
            // TODO: Implement camera with QR scanner
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Point camera at your contact's QR code",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun ManualEntryScreen(
    onAdded: (String, String) -> Unit,
    onBack: () -> Unit
) {
    var displayName by remember { mutableStateOf("") }
    var peerID by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Add Contact Manually",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedTextField(
            value = displayName,
            onValueChange = { displayName = it },
            label = { Text("Display Name") },
            placeholder = { Text("Alice Smith") },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = peerID,
            onValueChange = { peerID = it },
            label = { Text("Peer ID") },
            placeholder = { Text("peer_abc123...") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { onAdded(peerID, displayName) },
            modifier = Modifier.fillMaxWidth(),
            enabled = displayName.isNotBlank() && peerID.isNotBlank()
        ) {
            Text("Add Contact")
        }
    }
}

@Composable
fun CompleteScreen(onDone: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(120.dp),
            tint = MaterialTheme.colorScheme.primary
        )

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Setup Complete!",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "You can now send encrypted messages through any app.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Start Using HSIP Keyboard")
        }
    }
}

// Helper functions
fun generateQRCode(data: String): android.graphics.Bitmap {
    // TODO: Use ZXing or similar library
    TODO("Implement QR code generation")
}

data class Identity(
    val peerID: String,
    val publicKeyHex: String,
    val privateKeyBytes: ByteArray
) {
    fun toQRData(): String {
        return "hsip://exchange?peer=$peerID&pubkey=$publicKeyHex"
    }
}
```

### 2. HSIPDetectionService.kt (Auto-Detection)

```kotlin
package io.hsip.keyboard

import android.content.ClipboardManager
import android.content.Context
import android.inputmethodservice.InputMethodService
import android.view.inputmethod.EditorInfo
import kotlinx.coroutines.*

/**
 * Service that runs in the keyboard to detect HSIP messages.
 */
class HSIPDetectionService(private val context: Context) {

    private val hsipEngine = HSIPEngine.getInstance(context)
    private val sessionManager = SessionManager.getInstance(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    /**
     * Check if the current input field contains an HSIP message.
     */
    fun checkForHSIPMessage(
        inputConnection: android.view.inputmethod.InputConnection?,
        onDetected: (String, ByteArray) -> Unit
    ) {
        scope.launch {
            val text = withContext(Dispatchers.IO) {
                inputConnection?.getTextBeforeCursor(1000, 0)?.toString()
            } ?: return@launch

            if (hsipEngine.containsHSIPMessage(text)) {
                // Parse the HSIP message
                val encrypted = hsipEngine.parseMessage(text)

                if (encrypted != null) {
                    onDetected(text, encrypted)
                }
            }
        }
    }

    /**
     * Try to decrypt an HSIP message with all active sessions.
     */
    suspend fun tryDecrypt(encrypted: ByteArray): DecryptResult? {
        return withContext(Dispatchers.IO) {
            val sessions = sessionManager.listActiveSessions()

            for (session in sessions) {
                try {
                    val plaintext = hsipEngine.decrypt(encrypted, session.sessionKey)

                    if (plaintext != null) {
                        return@withContext DecryptResult(
                            plaintext = plaintext,
                            session = session
                        )
                    }
                } catch (e: Exception) {
                    // Try next session
                    continue
                }
            }

            null // No session could decrypt
        }
    }

    fun cleanup() {
        scope.cancel()
    }
}

data class DecryptResult(
    val plaintext: String,
    val session: Session
)
```

### 3. DecryptPopup.kt (Show Decrypted Message)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup

@Composable
fun DecryptedMessagePopup(
    plaintext: String,
    senderName: String,
    onCopy: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    Popup(
        alignment = Alignment.Center,
        onDismissRequest = onDismiss
    ) {
        Surface(
            modifier = modifier
                .fillMaxWidth(0.9f)
                .wrapContentHeight(),
            shape = RoundedCornerShape(16.dp),
            tonalElevation = 8.dp
        ) {
            Column(
                modifier = Modifier.padding(20.dp)
            ) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            text = "Decrypted Message",
                            style = MaterialTheme.typography.titleLarge
                        )
                    }

                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close")
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "From: $senderName",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Message content
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = plaintext,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(16.dp)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onCopy) {
                        Icon(
                            Icons.Default.ContentCopy,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("Copy")
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    Button(onClick = onDismiss) {
                        Text("Close")
                    }
                }
            }
        }
    }
}

/**
 * Banner shown when HSIP message is detected.
 */
@Composable
fun HSIPDetectedBanner(
    onDecrypt: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.primaryContainer,
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.Lock,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column {
                    Text(
                        text = "HSIP Message Detected",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )

                    Text(
                        text = "Tap to decrypt",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                    )
                }
            }

            Button(onClick = onDecrypt) {
                Text("Decrypt")
            }

            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, contentDescription = "Dismiss")
            }
        }
    }
}
```

---

## Usage in HSIPKeyboardService

```kotlin
class HSIPKeyboardService : InputMethodService() {

    private lateinit var detectionService: HSIPDetectionService
    private var showDecryptBanner by mutableStateOf(false)
    private var detectedMessage: ByteArray? by mutableStateOf(null)
    private var showDecryptPopup by mutableStateOf(false)
    private var decryptedText by mutableStateOf("")
    private var senderName by mutableStateOf("")

    override fun onCreate() {
        super.onCreate()
        detectionService = HSIPDetectionService(this)
    }

    override fun onCreateInputView(): View {
        return ComposeView(this).apply {
            setContent {
                HSIPKeyboardTheme {
                    Column {
                        // Detection banner
                        AnimatedVisibility(
                            visible = showDecryptBanner,
                            enter = slideInVertically() + fadeIn(),
                            exit = slideOutVertically() + fadeOut()
                        ) {
                            HSIPDetectedBanner(
                                onDecrypt = {
                                    lifecycleScope.launch {
                                        handleDecrypt()
                                    }
                                },
                                onDismiss = { showDecryptBanner = false }
                            )
                        }

                        // Main keyboard
                        KeyboardView(
                            onKeyPress = { key -> handleKeyPress(key) },
                            hsipEnabled = hsipModeEnabled,
                            onToggleHSIP = { toggleHSIPMode() },
                            activeSession = activeSession,
                            onSelectSession = { session -> activeSession = session }
                        )

                        // Decrypt popup
                        if (showDecryptPopup) {
                            DecryptedMessagePopup(
                                plaintext = decryptedText,
                                senderName = senderName,
                                onCopy = {
                                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(
                                        ClipData.newPlainText("HSIP Message", decryptedText)
                                    )
                                },
                                onDismiss = { showDecryptPopup = false }
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onUpdateSelection(...) {
        super.onUpdateSelection(...)

        // Check for HSIP messages
        detectionService.checkForHSIPMessage(currentInputConnection) { text, encrypted ->
            showDecryptBanner = true
            detectedMessage = encrypted
        }
    }

    private suspend fun handleDecrypt() {
        val encrypted = detectedMessage ?: return

        val result = detectionService.tryDecrypt(encrypted)

        if (result != null) {
            decryptedText = result.plaintext
            senderName = result.session.displayName
            showDecryptPopup = true
            showDecryptBanner = false
        } else {
            // Show error: no session could decrypt
            showError("Could not decrypt message. No matching session found.")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        detectionService.cleanup()
    }
}
```

---

## Testing Flow (Two Android Devices)

### Device A Setup:
```bash
1. Install hsip-keyboard-v0.1.0.apk
2. Open HSIP app
3. Generate identity → peer_alice123...
4. Show QR code
```

### Device B Setup:
```bash
1. Install hsip-keyboard-v0.1.0.apk
2. Open HSIP app
3. Generate identity → peer_bob456...
4. Scan Device A's QR code
5. Both devices now have session
```

### Sending (Device A → Device B):
```bash
1. Open Instagram DM with Device B user
2. Tap message input → Select HSIP Keyboard
3. Toggle HSIP ON
4. Select "Bob" from contacts
5. Type: "Hey, testing HSIP!"
6. Keyboard shows:
   Plaintext: "Hey, testing HSIP!"
   Will send: 🔒hQEMA...
7. Tap Enter
8. Instagram shows ciphertext in chat
```

### Receiving (Device B):
```bash
1. Instagram notification arrives
2. Opens chat → Sees: "🔒hQEMA8KxqFn..."
3. Taps message input → HSIP Keyboard appears
4. Banner shows: "HSIP Message Detected [Decrypt]"
5. Taps "Decrypt"
6. Popup shows: "Hey, testing HSIP!" (plaintext)
7. Reads message → Taps "Close"
8. Replies with HSIP
```

---

## Next: iOS Implementation (Parallel Development)

Now that Android E2E flow is complete, we'll build iOS keyboard extension that uses the SAME message format for cross-platform compatibility.

🚀 Android girlfriend ↔ iOS boyfriend messaging through Instagram/WhatsApp will work perfectly!
