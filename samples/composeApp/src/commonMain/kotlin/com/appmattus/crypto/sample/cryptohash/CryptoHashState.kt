package com.appmattus.crypto.sample.cryptohash

data class CryptoHashState(
    val algorithms: List<String> = cryptoHashAlgorithms.map { it.algorithmName },
    val selectedAlgorithm: String = "",
    val input: String = "",
    val hash: String = "n/a"
)
