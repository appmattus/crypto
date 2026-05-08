package com.appmattus.crypto.sample

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import com.appmattus.crypto.sample.app.AppRoute
import com.appmattus.crypto.sample.di.sampleAppModule
import org.koin.compose.KoinApplication
import org.koin.compose.koinInject
import org.koin.dsl.koinConfiguration

@Composable
@Preview
fun App() {
    KoinApplication(
        configuration = koinConfiguration {
            modules(sampleAppModule)
        }
    ) {
        MaterialTheme {
            Surface {
                val appViewModel = koinInject<AppViewModel>()
                val state by appViewModel.container.stateFlow.collectAsState()
                when (state.backStack.last()) {
                    AppRoute.Home -> {
                        HomeScreen(
                            onOpenCryptoHash = appViewModel::openCryptoHash
                        )
                    }

                    AppRoute.CryptoHash -> {
                        CryptoHashPlaceholderScreen(
                            onBack = appViewModel::navigateBack
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(
    onOpenCryptoHash: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        SampleHeader(text = "Samples")
        SampleRow(
            text = "cryptohash",
            onClick = onOpenCryptoHash
        )
    }
}

@Composable
private fun CryptoHashPlaceholderScreen(
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

@Composable
private fun SampleHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.headlineSmall,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)
    )
}

@Composable
private fun SampleRow(
    text: String,
    onClick: () -> Unit
) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 16.dp)
    )
}
