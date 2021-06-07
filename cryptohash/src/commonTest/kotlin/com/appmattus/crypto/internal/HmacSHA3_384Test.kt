package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSHA3_384Test {

    @Test
    fun testSha3_384() {
        // From https://fossies.org/linux/peazip/tv_hmac-sha3.txt

        testHmac(
            Algorithm.SHA3_384,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "68d2dcf7fd4ddd0a"
                    + "2240c8a437305f61"
                    + "fb7334cfb5d0226e"
                    + "1bc27dc10a2e723a"
                    + "20d370b47743130e"
                    + "26ac7e3d532886bd"
        )

        testHmac(
            Algorithm.SHA3_384,
            "4a656665",
            "what do ya want for nothing?",
            "f1101f8cbf9766fd"
                    + "6764d2ed61903f21"
                    + "ca9b18f57cf3e1a2"
                    + "3ca13508a93243ce"
                    + "48c045dc007f26a2"
                    + "1b3f5e0e9df4c20a"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "0fc19513bf6bd878"
                    + "037016706a0e57bc"
                    + "528139836b9a42c3"
                    + "d419e498e0e1fb96"
                    + "16fd669138d33a11"
                    + "05e07c72b6953bcc"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "026fdf6b50741e37"
                    + "3899c9f7d5406d4e"
                    + "b09fc6665636fc1a"
                    + "530029ddf5cf3ca5"
                    + "a900edce01f5f61e"
                    + "2f408cdf2fd3e7e8"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "713dff0302c85086ec5ad0768dd65a13ddd79068d8d4c6212b712e41649449111480230044185a99103ed82004ddbfcc"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "cad18a8ff6c4cc3ad487b95f9769e9b61c062aefd6952569e6e6421897054cfc70b5fdc6605c18457112fc6aaad45585"
        )

        testHmacHex(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e"
        )

        testHmacHex(
            Algorithm.SHA3_384,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984da2d0f9449b3ba8425ec7fb8c31bc136"
        )

        testHmac(
            Algorithm.SHA3_384,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "47c51ace1ffacffd7494724682615783",
            16
        )
    }
}
