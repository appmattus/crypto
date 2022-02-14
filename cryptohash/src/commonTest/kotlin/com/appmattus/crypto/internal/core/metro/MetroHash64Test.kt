package com.appmattus.crypto.internal.core.metro

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class MetroHash64Test {

    private fun createDigest(seed: ULong = 0u) = Algorithm.MetroHash64(seed).createDigest()

    @Test
    fun test() {
        testKat({ createDigest(0u) }, "", "705fb008071e967d")
        testKat({ createDigest(1u) }, "", "e6f660fe36b85a05")

        testKat({ createDigest(0u) }, "a", "af6f242b7ed32bcb")
        testKat({ createDigest(1u) }, "a", "ba497622530ddb60")

        testKat({ createDigest(0u) }, "test", "b2baf77de212d136")
        testKat({ createDigest(1u) }, "test", "47ebcfa27ef910cf")

        testKat({ createDigest(0u) }, "012345678901234567890123456789012345678901234567890123456789012", "ad4b7006ae3d756b")
        testKat({ createDigest(1u) }, "012345678901234567890123456789012345678901234567890123456789012", "dfb8b9f41c480d3b")

        testKat({ createDigest(0u) }, "hello world", "22d16db35723c197")
        testKat({ createDigest(123u) }, "hello world", "f0563caba306566e")

        testKat({ createDigest(0u) }, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "b4f5c6747b307a94")
        testKat({ createDigest(1u) }, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "41c8a6a0fdf96892")

        testKat(
            { createDigest(0u) },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0ae948a6deef3c72"
        )
        testKat(
            { createDigest(123456u) },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "aa6f685d12c48cf0"
        )
    }
}
