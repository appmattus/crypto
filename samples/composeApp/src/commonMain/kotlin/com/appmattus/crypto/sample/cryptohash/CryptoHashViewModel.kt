package com.appmattus.crypto.sample.cryptohash

import androidx.lifecycle.ViewModel
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.viewmodel.container

class CryptoHashViewModel : ViewModel(), ContainerHost<CryptoHashState, Nothing> {

    private var currentAlgorithmName: String = ""
    private var inputText: String = ""

    override val container: Container<CryptoHashState, Nothing> = container(CryptoHashState())

    fun selectAlgorithm(name: String) = intent {
        currentAlgorithmName = name
        reduce {
            state.copy(
                selectedAlgorithm = name,
                hash = generateHash()
            )
        }
    }

    fun setInputText(input: String) = intent {
        inputText = input
        reduce {
            state.copy(
                input = input,
                hash = generateHash()
            )
        }
    }

    private fun generateHash(): String {
        val algorithm = cryptoHashAlgorithms.firstOrNull { it.algorithmName == currentAlgorithmName }

        return try {
            algorithm?.createDigest()?.digest(inputText.encodeToByteArray())?.toHexString() ?: "n/a"
        } catch (expected: Exception) {
            expected.message ?: expected.toString()
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
