package com.appmattus.crypto.sample.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun CryptoHashPlaceholderScreen(
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = "Crypto Hash",
            style = MaterialTheme.typography.headlineMedium
        )
        Text(
            text = "Navigation 3 is now routing to a dedicated destination. The old sample feature logic is the next piece to port into this screen.",
            style = MaterialTheme.typography.bodyLarge
        )
        SampleRow(
            text = "Back",
            onClick = onBack
        )
    }
}
