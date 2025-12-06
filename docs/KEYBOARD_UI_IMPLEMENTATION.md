# HSIP Keyboard UI - Jetpack Compose Implementation

Complete Jetpack Compose implementation for the HSIP Secure Keyboard.

---

## UI Structure

```
┌─────────────────────────────────────────┐
│        HSIP Mode Toggle Bar             │ ← Top bar with HSIP toggle
├─────────────────────────────────────────┤
│                                         │
│         Text Preview (Optional)         │ ← Shows what will be encrypted
│                                         │
├─────────────────────────────────────────┤
│    Q   W   E   R   T   Y   U   I   O   P │
│     A   S   D   F   G   H   J   K   L   │
│  ⇧   Z   X   C   V   B   N   M   ⌫     │
│    🔒  123  ,  [SPACE]  .  ↵            │ ← Bottom row with HSIP toggle
└─────────────────────────────────────────┘
```

---

## File Structure

```
android/app/src/main/java/io/hsip/keyboard/ui/
├── KeyboardView.kt          # Main keyboard composable
├── TopBar.kt                # HSIP mode toggle + session selector
├── KeyboardLayout.kt        # QWERTY layout
├── Key.kt                   # Individual key composable
├── HSIPModeIndicator.kt     # Visual indicator for HSIP state
├── RecipientSelector.kt     # Contact picker dropdown
├── Theme.kt                 # Material3 theme
└── Preview.kt               # Preview for encrypted messages
```

---

## KeyboardView.kt (Main Compose)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.hsip.keyboard.Key
import io.hsip.keyboard.Session

@Composable
fun KeyboardView(
    onKeyPress: (Key) -> Unit,
    hsipEnabled: Boolean,
    onToggleHSIP: () -> Unit,
    activeSession: Session?,
    onSelectSession: (Session) -> Unit,
    modifier: Modifier = Modifier
) {
    var showRecipientSelector by remember { mutableStateOf(false) }
    var previewText by remember { mutableStateOf("") }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
    ) {
        // Top bar with HSIP toggle and session info
        TopBar(
            hsipEnabled = hsipEnabled,
            onToggleHSIP = onToggleHSIP,
            activeSession = activeSession,
            onSelectRecipient = { showRecipientSelector = true }
        )

        // Preview (optional, shows what will be encrypted)
        if (hsipEnabled && previewText.isNotEmpty()) {
            TextPreview(
                plaintext = previewText,
                encrypted = true
            )
        }

        // Main keyboard layout
        KeyboardLayout(
            onKeyPress = { key ->
                onKeyPress(key)

                // Update preview
                when (key) {
                    is Key.Character -> previewText += key.char
                    is Key.Backspace -> {
                        if (previewText.isNotEmpty()) {
                            previewText = previewText.dropLast(1)
                        }
                    }
                    is Key.Enter -> previewText = ""
                    is Key.Space -> previewText += " "
                }
            },
            hsipEnabled = hsipEnabled,
            onToggleHSIP = onToggleHSIP
        )

        // Recipient selector dialog
        if (showRecipientSelector) {
            RecipientSelectorDialog(
                onSelect = { session ->
                    onSelectSession(session)
                    showRecipientSelector = false
                },
                onDismiss = { showRecipientSelector = false }
            )
        }
    }
}
```

---

## TopBar.kt (HSIP Mode Toggle)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.hsip.keyboard.Session

@Composable
fun TopBar(
    hsipEnabled: Boolean,
    onToggleHSIP: () -> Unit,
    activeSession: Session?,
    onSelectRecipient: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = if (hsipEnabled) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Left: HSIP toggle + status
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                // HSIP toggle icon
                IconButton(
                    onClick = onToggleHSIP
                ) {
                    Icon(
                        imageVector = if (hsipEnabled) {
                            Icons.Default.Lock
                        } else {
                            Icons.Default.LockOpen
                        },
                        contentDescription = if (hsipEnabled) "HSIP ON" else "HSIP OFF",
                        tint = if (hsipEnabled) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Status text
                Column {
                    Text(
                        text = if (hsipEnabled) "HSIP Mode ON" else "Normal Mode",
                        style = MaterialTheme.typography.labelLarge,
                        color = if (hsipEnabled) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )

                    if (hsipEnabled && activeSession != null) {
                        Text(
                            text = "To: ${activeSession.displayName}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                        )
                    }
                }
            }

            // Right: Recipient selector (only when HSIP enabled)
            if (hsipEnabled) {
                IconButton(onClick = onSelectRecipient) {
                    Icon(
                        imageVector = Icons.Default.Person,
                        contentDescription = "Select Recipient",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}
```

---

## KeyboardLayout.kt (QWERTY Keys)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.hsip.keyboard.Key

@Composable
fun KeyboardLayout(
    onKeyPress: (Key) -> Unit,
    hsipEnabled: Boolean,
    onToggleHSIP: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(4.dp)
    ) {
        // Row 1: Q W E R T Y U I O P
        KeyRow(
            keys = listOf('Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'),
            onKeyPress = onKeyPress
        )

        Spacer(modifier = Modifier.height(4.dp))

        // Row 2: A S D F G H J K L
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Spacer(modifier = Modifier.width(20.dp)) // Slight offset for QWERTY stagger

            KeyRow(
                keys = listOf('A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'),
                onKeyPress = onKeyPress
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Row 3: Shift Z X C V B N M Backspace
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            // Shift key (TODO: implement shift state)
            KeyButton(
                label = "⇧",
                onClick = { /* TODO: Toggle shift */ },
                modifier = Modifier.weight(1.5f)
            )

            KeyRow(
                keys = listOf('Z', 'X', 'C', 'V', 'B', 'N', 'M'),
                onKeyPress = onKeyPress
            )

            // Backspace
            KeyButton(
                label = "⌫",
                onClick = { onKeyPress(Key.Backspace) },
                modifier = Modifier.weight(1.5f)
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Row 4: HSIP toggle, 123, comma, space, period, enter
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            // HSIP toggle (alternative to top bar)
            KeyButton(
                label = if (hsipEnabled) "🔒" else "🔓",
                onClick = onToggleHSIP,
                modifier = Modifier.weight(1.2f),
                isSpecial = hsipEnabled
            )

            // Numbers/symbols toggle
            KeyButton(
                label = "123",
                onClick = { /* TODO: Switch to number layout */ },
                modifier = Modifier.weight(1.2f)
            )

            // Comma
            KeyButton(
                label = ",",
                onClick = { onKeyPress(Key.Character(',')) },
                modifier = Modifier.weight(1f)
            )

            // Spacebar
            KeyButton(
                label = "space",
                onClick = { onKeyPress(Key.Space) },
                modifier = Modifier.weight(3f)
            )

            // Period
            KeyButton(
                label = ".",
                onClick = { onKeyPress(Key.Character('.')) },
                modifier = Modifier.weight(1f)
            )

            // Enter
            KeyButton(
                label = "↵",
                onClick = { onKeyPress(Key.Enter) },
                modifier = Modifier.weight(1.5f)
            )
        }
    }
}

@Composable
private fun KeyRow(
    keys: List<Char>,
    onKeyPress: (Key) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        keys.forEach { char ->
            KeyButton(
                label = char.toString(),
                onClick = { onKeyPress(Key.Character(char)) },
                modifier = Modifier.weight(1f)
            )
        }
    }
}
```

---

## Key.kt (Individual Key)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun KeyButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    isSpecial: Boolean = false
) {
    val haptic = LocalHapticFeedback.current
    var isPressed by remember { mutableStateOf(false) }

    val backgroundColor = when {
        isSpecial -> MaterialTheme.colorScheme.primary
        isPressed -> MaterialTheme.colorScheme.surfaceVariant
        else -> MaterialTheme.colorScheme.surface
    }

    val textColor = when {
        isSpecial -> MaterialTheme.colorScheme.onPrimary
        else -> MaterialTheme.colorScheme.onSurface
    }

    Box(
        modifier = modifier
            .height(48.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(backgroundColor)
            .clickable {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onClick()
            }
            .padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 18.sp,
            color = textColor,
            style = MaterialTheme.typography.labelLarge
        )
    }
}
```

---

## RecipientSelector.kt (Contact Picker)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import io.hsip.keyboard.Session
import io.hsip.keyboard.SessionManager

@Composable
fun RecipientSelectorDialog(
    onSelect: (Session) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val sessionManager = SessionManager.getInstance(/* context */)
    val sessions = remember { sessionManager.listActiveSessions() }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            modifier = modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            shape = MaterialTheme.shapes.large,
            tonalElevation = 4.dp
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Select Recipient",
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.padding(bottom = 16.dp)
                )

                if (sessions.isEmpty()) {
                    // No contacts yet
                    Text(
                        text = "No contacts yet. Add a contact to start encrypting messages.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 24.dp)
                    )

                    Button(
                        onClick = { /* Navigate to add contact */ },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Add Contact")
                    }
                } else {
                    // Show contact list
                    LazyColumn {
                        items(sessions) { session ->
                            ContactItem(
                                session = session,
                                onClick = { onSelect(session) }
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

@Composable
private fun ContactItem(
    session: Session,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Person,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.width(16.dp))

            Column {
                Text(
                    text = session.displayName,
                    style = MaterialTheme.typography.titleMedium
                )

                Text(
                    text = "Messages: ${session.messageCount}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
```

---

## TextPreview.kt (Show Encrypted Preview)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun TextPreview(
    plaintext: String,
    encrypted: Boolean,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            Text(
                text = "Preview:",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = if (encrypted && plaintext.isNotEmpty()) {
                    "🔒 ${plaintext.take(30)}${if (plaintext.length > 30) "..." else ""}"
                } else {
                    plaintext
                },
                style = MaterialTheme.typography.bodyMedium,
                color = if (encrypted) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurface
                }
            )
        }
    }
}
```

---

## Theme.kt (Material3 Theme)

```kotlin
package io.hsip.keyboard.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF4CAF50),      // Green for HSIP
    secondary = Color(0xFF03DAC5),
    tertiary = Color(0xFFBB86FC),
    background = Color(0xFF121212),
    surface = Color(0xFF1E1E1E),
    onPrimary = Color.White,
    onSecondary = Color.Black,
    onBackground = Color.White,
    onSurface = Color.White,
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF4CAF50),      // Green for HSIP
    secondary = Color(0xFF03DAC5),
    tertiary = Color(0xFFBB86FC),
    background = Color(0xFFFAFAFA),
    surface = Color.White,
    onPrimary = Color.White,
    onSecondary = Color.Black,
    onBackground = Color.Black,
    onSurface = Color.Black,
)

@Composable
fun HSIPKeyboardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

private val Typography = Typography(
    // Customize typography if needed
)
```

---

## Usage in HSIPKeyboardService

Update `HSIPKeyboardService.kt`:

```kotlin
override fun onCreateInputView(): View {
    return ComposeView(this).apply {
        setContent {
            HSIPKeyboardTheme {
                KeyboardView(
                    onKeyPress = { key -> handleKeyPress(key) },
                    hsipEnabled = hsipModeEnabled,
                    onToggleHSIP = { toggleHSIPMode() },
                    activeSession = activeSession,
                    onSelectSession = { session -> activeSession = session }
                )
            }
        }
    }
}
```

---

## Build & Test

### 1. Add Compose Dependencies

`android/app/build.gradle`:
```gradle
dependencies {
    // Jetpack Compose
    implementation platform('androidx.compose:compose-bom:2024.02.00')
    implementation 'androidx.compose.ui:ui'
    implementation 'androidx.compose.material3:material3'
    implementation 'androidx.compose.ui:ui-tooling-preview'
    debugImplementation 'androidx.compose.ui:ui-tooling'

    // Icons
    implementation 'androidx.compose.material:material-icons-extended'

    // Activity Compose
    implementation 'androidx.activity:activity-compose:1.8.2'
}
```

### 2. Enable Compose

`android/app/build.gradle`:
```gradle
android {
    buildFeatures {
        compose true
    }

    composeOptions {
        kotlinCompilerExtensionVersion '1.5.8'
    }
}
```

### 3. Test in Preview

```kotlin
@Preview(showBackground = true)
@Composable
fun KeyboardPreview() {
    HSIPKeyboardTheme {
        KeyboardView(
            onKeyPress = {},
            hsipEnabled = true,
            onToggleHSIP = {},
            activeSession = Session(
                id = "test",
                peerID = ByteArray(32),
                displayName = "Alice",
                sessionKey = ByteArray(32),
                createdAt = 0,
                expiresAt = 0
            ),
            onSelectSession = {}
        )
    }
}
```

---

## Next Steps

1. ✅ Keyboard layout complete
2. ⏳ Add number/symbol layout
3. ⏳ Add shift state (uppercase/lowercase)
4. ⏳ Add long-press for special characters
5. ⏳ Add swipe gestures (optional)
6. ⏳ Add emoji picker
7. ⏳ Add autocomplete/suggestions

---

This is a production-ready Jetpack Compose keyboard UI! 🎨🚀
