package io.hsip.keyboard.ui.keyboard

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.hsip.keyboard.crypto.Contact

@Composable
fun KeyboardView(
    onKeyPress: (Char) -> Unit,
    onBackspace: () -> Unit,
    onSpace: () -> Unit,
    onEnter: () -> Unit,
    onRecipientSelect: (Contact?) -> Unit,
    selectedRecipient: Contact?,
    contacts: List<Contact>
) {
    var showRecipientSelector by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1E))
            .padding(4.dp)
    ) {
        // Top bar with HSIP icon and recipient selector
        TopBar(
            selectedRecipient = selectedRecipient,
            onRecipientClick = { showRecipientSelector = !showRecipientSelector },
            onClearRecipient = { onRecipientSelect(null) }
        )

        // Recipient selector (dropdown)
        if (showRecipientSelector) {
            RecipientSelector(
                contacts = contacts,
                onSelect = {
                    onRecipientSelect(it)
                    showRecipientSelector = false
                },
                onDismiss = { showRecipientSelector = false }
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        // QWERTY Keyboard Layout
        QWERTYLayout(
            onKeyPress = onKeyPress,
            onBackspace = onBackspace,
            onSpace = onSpace,
            onEnter = onEnter
        )
    }
}

@Composable
fun TopBar(
    selectedRecipient: Contact?,
    onRecipientClick: () -> Unit,
    onClearRecipient: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF2C2C2E), RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // HSIP Lock Icon
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = "HSIP",
            tint = if (selectedRecipient != null) Color(0xFF32D74B) else Color.Gray,
            modifier = Modifier.size(20.dp)
        )

        Spacer(modifier = Modifier.width(8.dp))

        // Recipient selector button
        Box(
            modifier = Modifier
                .weight(1f)
                .clickable { onRecipientClick() }
        ) {
            Text(
                text = selectedRecipient?.displayName ?: "No Encryption",
                color = if (selectedRecipient != null) Color.White else Color.Gray,
                fontSize = 14.sp
            )
        }

        // Clear recipient button
        if (selectedRecipient != null) {
            IconButton(
                onClick = onClearRecipient,
                modifier = Modifier.size(24.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Clear",
                    tint = Color.Gray
                )
            }
        }
    }
}

@Composable
fun RecipientSelector(
    contacts: List<Contact>,
    onSelect: (Contact) -> Unit,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF2C2C2E), RoundedCornerShape(8.dp))
            .padding(8.dp)
    ) {
        Text(
            text = "Encrypt for:",
            color = Color.White,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(8.dp)
        )

        if (contacts.isEmpty()) {
            Text(
                text = "No contacts. Open HSIP app to add contacts.",
                color = Color.Gray,
                fontSize = 12.sp,
                modifier = Modifier.padding(8.dp)
            )
        } else {
            contacts.forEach { contact ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelect(contact) }
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Person,
                        contentDescription = null,
                        tint = Color(0xFF32D74B),
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = contact.displayName,
                        color = Color.White,
                        fontSize = 14.sp
                    )
                }
            }
        }
    }
}

@Composable
fun QWERTYLayout(
    onKeyPress: (Char) -> Unit,
    onBackspace: () -> Unit,
    onSpace: () -> Unit,
    onEnter: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        // Row 1: Q W E R T Y U I O P
        KeyRow(keys = listOf('Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'), onKeyPress = onKeyPress)

        Spacer(modifier = Modifier.height(4.dp))

        // Row 2: A S D F G H J K L
        KeyRow(
            keys = listOf('A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'),
            onKeyPress = onKeyPress,
            startPadding = 16.dp
        )

        Spacer(modifier = Modifier.height(4.dp))

        // Row 3: Z X C V B N M + Backspace
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Spacer(modifier = Modifier.width(4.dp))

            listOf('Z', 'X', 'C', 'V', 'B', 'N', 'M').forEach { key ->
                KeyButton(
                    text = key.toString(),
                    onClick = { onKeyPress(key) },
                    modifier = Modifier.weight(1f)
                )
            }

            KeyButton(
                text = "⌫",
                onClick = onBackspace,
                modifier = Modifier.weight(1.5f),
                backgroundColor = Color(0xFF3A3A3C)
            )

            Spacer(modifier = Modifier.width(4.dp))
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Row 4: Space + Enter
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Spacer(modifier = Modifier.width(4.dp))

            KeyButton(
                text = "123",
                onClick = { /* Switch to numbers */ },
                modifier = Modifier.weight(1f),
                backgroundColor = Color(0xFF3A3A3C)
            )

            KeyButton(
                text = "Space",
                onClick = onSpace,
                modifier = Modifier.weight(4f)
            )

            KeyButton(
                text = "↵",
                onClick = onEnter,
                modifier = Modifier.weight(1f),
                backgroundColor = Color(0xFF007AFF)
            )

            Spacer(modifier = Modifier.width(4.dp))
        }
    }
}

@Composable
fun KeyRow(
    keys: List<Char>,
    onKeyPress: (Char) -> Unit,
    startPadding: androidx.compose.ui.unit.Dp = 0.dp
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Spacer(modifier = Modifier.width(startPadding))

        keys.forEach { key ->
            KeyButton(
                text = key.toString(),
                onClick = { onKeyPress(key) },
                modifier = Modifier.weight(1f)
            )
        }

        if (startPadding > 0.dp) {
            Spacer(modifier = Modifier.width(startPadding))
        }
    }
}

@Composable
fun KeyButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    backgroundColor: Color = Color(0xFF505053)
) {
    Box(
        modifier = modifier
            .height(44.dp)
            .background(backgroundColor, RoundedCornerShape(6.dp))
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = Color.White,
            fontSize = 18.sp,
            fontWeight = FontWeight.Medium
        )
    }
}
