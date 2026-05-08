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
