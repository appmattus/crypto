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

package com.appmattus.crypto.sample.cryptohash

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.ViewModel
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.viewmodel.container

class CryptoHashViewModel : ViewModel(), ContainerHost<CryptoHashState, Nothing> {

    override val container: Container<CryptoHashState, Nothing> = container(
        initialState = CryptoHashState(input = TextFieldState()),
        onCreate = {
            snapshotFlow { state.input.text.toString() }.collect { input ->
                reduce {
                    state.copy(
                        hash = generateHash(
                            algorithmName = state.selectedAlgorithm,
                            inputText = input
                        )
                    )
                }
            }
        }
    )

    fun selectAlgorithm(name: String) = intent {
        reduce {
            state.copy(
                selectedAlgorithm = name,
                hash = generateHash(
                    algorithmName = name,
                    inputText = state.input.text.toString()
                )
            )
        }
    }

    private fun generateHash(
        algorithmName: String,
        inputText: String
    ): String {
        val algorithm = cryptoHashAlgorithms.firstOrNull { it.algorithmName == algorithmName }

        return try {
            algorithm?.createDigest()?.digest(inputText.encodeToByteArray())?.toHexString() ?: "n/a"
        } catch (expected: Exception) {
            expected.message ?: expected.toString()
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
