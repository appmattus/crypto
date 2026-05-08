package com.appmattus.crypto.sample

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.tooling.preview.Preview
import com.appmattus.crypto.sample.app.AppViewModel
import com.appmattus.crypto.sample.app.AppRoute
import com.appmattus.crypto.sample.di.sampleAppModule
import com.appmattus.crypto.sample.ui.CryptoHashScreen
import com.appmattus.crypto.sample.ui.HomeScreen
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
                        CryptoHashScreen(
                            onBack = appViewModel::navigateBack
                        )
                    }
                }
            }
        }
    }
}
