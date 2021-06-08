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
            "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd"
        )

        testHmac(
            Algorithm.SHA3_384,
            "4a656665",
            "what do ya want for nothing?",
            "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc"
        )

        testHmac(
            Algorithm.SHA3_384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5a900edce01f5f61e2f408cdf2fd3e7e8"
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

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SHA3HMacTest.java

        testHmacHex(
            Algorithm.SHA3_384,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e",
            "d588a3c51f3f2d906e8298c1199aa8ff" +
                    "6296218127f6b38a90b6afe2c5617725" +
                    "bc99987f79b22a557b6520db710b7f42"
        )
        testHmacHex(
            Algorithm.SHA3_384,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f" +
                    "505152535455565758595a5b5c5d5e5f" +
                    "6061626364656667",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3d626c6f636b6c" +
                    "656e",
            "a27d24b592e8c8cbf6d4ce6fc5bf62d8" +
                    "fc98bf2d486640d9eb8099e24047837f" +
                    "5f3bffbe92dcce90b4ed5b1e7e44fa90"
        )
        testHmacHex(
            Algorithm.SHA3_384,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f" +
                    "505152535455565758595a5b5c5d5e5f" +
                    "606162636465666768696a6b6c6d6e6f" +
                    "707172737475767778797a7b7c7d7e7f" +
                    "808182838485868788898a8b8c8d8e8f" +
                    "9091929394959697",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3e626c6f636b6c" +
                    "656e",
            "e5ae4c739f455279368ebf36d4f5354c" +
                    "95aa184c899d3870e460ebc288ef1f94" +
                    "70053f73f7c6da2a71bcaec38ce7d6ac"
        )
        testHmacHex(
            Algorithm.SHA3_384,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e2c2077697468207472756e636174" +
                    "656420746167",
            "25f4bf53606e91af79d24a4bb1fd6aec" +
                    "d44414a30c8ebb0a",
            24
        )
    }
}
