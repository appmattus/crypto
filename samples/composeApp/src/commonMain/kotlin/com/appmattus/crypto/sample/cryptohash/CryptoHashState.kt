package com.appmattus.crypto.sample.cryptohash

import androidx.compose.foundation.text.input.TextFieldState

data class CryptoHashState(
    val algorithms: List<String> = cryptoHashAlgorithms.map { it.algorithmName },
    val selectedAlgorithm: String = "",
    val input: TextFieldState = TextFieldState(),
    val hash: String = "n/a"
)
