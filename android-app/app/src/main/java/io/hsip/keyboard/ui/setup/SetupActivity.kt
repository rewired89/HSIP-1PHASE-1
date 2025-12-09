package io.hsip.keyboard.ui.setup

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.hsip.keyboard.HSIPApplication
import io.hsip.keyboard.ui.theme.HSIPKeyboardTheme

class SetupActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Handle deep link for contact sharing
        handleDeepLink(intent)

        setContent {
            HSIPKeyboardTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SetupFlow()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleDeepLink(it) }
    }

    private fun handleDeepLink(intent: Intent) {
        if (intent.action == Intent.ACTION_VIEW) {
            val uri = intent.data
            if (uri != null && uri.scheme == "hsip" && uri.host == "add") {
                val peerId = uri.getQueryParameter("id")
                val displayName = uri.getQueryParameter("name")

                if (peerId != null && displayName != null) {
                    // TODO: Show contact confirmation dialog
                    // For now, automatically add contact
                    // In production, generate session key via X25519 key exchange
                    val dummySessionKey = "TEMP_SESSION_KEY_BASE64"

                    HSIPApplication.instance.hsipEngine.addContact(
                        peerId = peerId,
                        displayName = displayName,
                        sessionKey = dummySessionKey
                    )
                }
            }
        }
    }
}

@Composable
fun SetupFlow() {
    var currentStep by remember { mutableStateOf(SetupStep.WELCOME) }
    val hsipEngine = HSIPApplication.instance.hsipEngine

    when (currentStep) {
        SetupStep.WELCOME -> WelcomeScreen(
            onContinue = { currentStep = SetupStep.IDENTITY }
        )

        SetupStep.IDENTITY -> IdentityScreen(
            hsipEngine = hsipEngine,
            onContinue = { currentStep = SetupStep.CONTACTS }
        )

        SetupStep.CONTACTS -> ContactsScreen(
            hsipEngine = hsipEngine,
            onContinue = { currentStep = SetupStep.ENABLE_KEYBOARD }
        )

        SetupStep.ENABLE_KEYBOARD -> EnableKeyboardScreen(
            onFinish = { /* Go to main app */ }
        )
    }
}

enum class SetupStep {
    WELCOME,
    IDENTITY,
    CONTACTS,
    ENABLE_KEYBOARD
}

@Composable
fun WelcomeScreen(onContinue: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "🔐",
            fontSize = 72.sp
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Welcome to HSIP",
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "End-to-end encrypted messaging in any app",
            fontSize = 16.sp,
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
fun IdentityScreen(
    hsipEngine: io.hsip.keyboard.crypto.HSIPEngine,
    onContinue: () -> Unit
) {
    val peerId = hsipEngine.getPeerID() ?: ""
    val displayName = hsipEngine.getDisplayName()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Your Identity",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Your HSIP identity has been generated!",
            fontSize = 16.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Display Name",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = displayName,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Medium
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Peer ID (First 32 chars)",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = peerId.take(32) + "...",
                    fontSize = 14.sp,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }
        }

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onContinue,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Continue")
        }
    }
}

@Composable
fun ContactsScreen(
    hsipEngine: io.hsip.keyboard.crypto.HSIPEngine,
    onContinue: () -> Unit
) {
    val context = LocalContext.current
    val contactSharingText = hsipEngine.getContactSharingText()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Add Contacts",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Share your contact info to exchange encrypted messages",
            fontSize = 16.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Share Contact Button
        OutlinedButton(
            onClick = {
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, contactSharingText)
                }
                context.startActivity(Intent.createChooser(shareIntent, "Share HSIP Contact"))
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("📤 Share My Contact")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // QR Code Button (TODO: implement QR generation)
        OutlinedButton(
            onClick = { /* Show QR code */ },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("📱 Show QR Code")
        }

        Spacer(modifier = Modifier.height(32.dp))

        Divider()

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "When someone shares their HSIP contact with you, just click the link to add them.",
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onContinue,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Continue")
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(
            onClick = onContinue
        ) {
            Text("Skip for now")
        }
    }
}

@Composable
fun EnableKeyboardScreen(onFinish: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Enable HSIP Keyboard",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "To use HSIP encryption, enable the keyboard in your system settings:",
            fontSize = 16.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text("1. Go to Settings", fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("2. Tap System → Keyboard", fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("3. Tap On-screen keyboard", fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("4. Enable 'HSIP Keyboard'", fontWeight = FontWeight.Medium)
            }
        }

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onFinish,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Finish Setup")
        }
    }
}
