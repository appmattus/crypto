/*
 * Copyright 2026 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto.sample

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.appmattus.crypto.sample.app.AppRoute
import com.appmattus.crypto.sample.app.AppViewModel
import com.appmattus.crypto.sample.di.sampleAppModule
import com.appmattus.crypto.sample.ui.CryptoHashScreen
import com.appmattus.crypto.sample.ui.HomeScreen
import org.koin.compose.KoinApplication
import org.koin.compose.koinInject
import org.koin.dsl.koinConfiguration
import org.orbitmvi.orbit.compose.collectAsState

@Composable
@Preview
fun App() {
    KoinApplication(
        configuration = koinConfiguration {
            modules(sampleAppModule)
        }
    ) {
        MaterialTheme {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .safeDrawingPadding()
            ) {
                val appViewModel = koinInject<AppViewModel>()
                val state by appViewModel.collectAsState()
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
