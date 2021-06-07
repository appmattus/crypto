package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSHA0Test {

    @Test
    fun misc() {
        // From https://github.com/crypto-browserify/hash-test-vectors/blob/master/hmac.json

        testHmac(
            Algorithm.SHA_0,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "c2cbaa7817447fb494ca153a88f2f013f934ff58"
        )

        testHmacHex(
            Algorithm.SHA_0,
            "4a656665",
            "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
            "b058879503487b824bfb6bdd59d10e910f55a428"
        )

        testHmacHex(
            Algorithm.SHA_0,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "20b8027a3e4b3a7485d16d3297ea05389d64b4bf"
        )

        testHmacHex(
            Algorithm.SHA_0,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "8e47262e2e939da3cd487ddffe3f6bbb9f2809e7"
        )

        testHmac(
            Algorithm.SHA_0,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "3a29508f315d0548c140e8a8c0b4cd58",
            // truncate to 128 bits
            16
        )
        testHmac(
            Algorithm.SHA_0,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "8b0a2731db7a6c716644354dbebdf8f4b0eb4e1f"
        )
    }
}
