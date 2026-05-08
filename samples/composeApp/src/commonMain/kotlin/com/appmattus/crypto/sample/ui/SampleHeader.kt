package com.appmattus.crypto.sample.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.padding

@Composable
fun SampleHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.headlineSmall,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)
    )
}

@Preview
@Composable
private fun SampleHeaderPreview() {
    SamplePreview {
        SampleHeader(text = "Samples > cryptohash")
    }
}
