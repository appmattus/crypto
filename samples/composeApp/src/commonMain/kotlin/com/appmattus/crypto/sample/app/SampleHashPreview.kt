package com.appmattus.crypto.sample.app

import com.appmattus.crypto.Algorithm

class SampleHashPreview {
    fun hash(input: String = "crypto"): String = Algorithm.SHA_256
        .hash(input.encodeToByteArray())
        .toHexString()

    private fun ByteArray.toHexString(): String = joinToString("") {
        (it.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
