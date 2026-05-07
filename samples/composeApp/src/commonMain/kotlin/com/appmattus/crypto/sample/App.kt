package com.appmattus.crypto.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.appmattus.crypto.sample.app.AppViewModel
import com.appmattus.crypto.sample.di.sampleAppModule
import org.koin.compose.KoinApplication
import org.koin.compose.koinInject

@Composable
@Preview
fun App() {
    KoinApplication(application = {
        modules(sampleAppModule)
    }) {
        MaterialTheme {
            Surface {
                val appViewModel = koinInject<AppViewModel>()
                val state by appViewModel.container.stateFlow.collectAsState()

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = state.title,
                        style = MaterialTheme.typography.headlineMedium
                    )
                    Text(
                        text = state.subtitle,
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Text(
                        text = "Sample SHA-256: ${state.previewHash}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}
