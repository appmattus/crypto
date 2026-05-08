package com.appmattus.crypto.sample.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun TwoLineTextRow(
    primaryText: String,
    secondaryText: String
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 16.dp)
    ) {
        Text(
            text = primaryText,
            style = MaterialTheme.typography.titleMedium
        )
        SelectionContainer {
            Text(
                text = secondaryText,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
