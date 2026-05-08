package com.appmattus.crypto.sample.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable

@Composable
internal fun SamplePreview(
    content: @Composable () -> Unit
) {
    MaterialTheme {
        Surface {
            content()
        }
    }
}
