package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSHA3_256Test {

    @Test
    fun testSha3_256() {
        // From https://fossies.org/linux/peazip/tv_hmac-sha3.txt

        testHmac(
            Algorithm.SHA3_256,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"
        )

        testHmac(
            Algorithm.SHA3_256,
            "4a656665",
            "what do ya want for nothing?",
            "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"
        )

        testHmac(
            Algorithm.SHA3_256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b"
        )

        testHmac(
            Algorithm.SHA3_256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123"
        )

        testHmac(
            Algorithm.SHA3_256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "a6072f86de52b38bb349fe84cd6d97fb6a37c4c0f62aae93981193a7229d3467"
        )

        testHmac(
            Algorithm.SHA3_256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "e6a36d9b915f86a093cac7d110e9e04cf1d6100d30475509c2475f571b758b5a"
        )

        testHmacHex(
            Algorithm.SHA3_256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207"
        )

        testHmacHex(
            Algorithm.SHA3_256,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7"
        )

        testHmac(
            Algorithm.SHA3_256,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "6e02c64537fb118057abb7fb66a23b3c",
            16
        )
    }

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SHA3HMacTest.java

        testHmacHex(
            Algorithm.SHA3_256,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e",
            "4fe8e202c4f058e8dddc23d8c34e4673" +
                    "43e23555e24fc2f025d598f558f67205"
        )
        testHmacHex(
            Algorithm.SHA3_256,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f" +
                    "505152535455565758595a5b5c5d5e5f" +
                    "606162636465666768696a6b6c6d6e6f" +
                    "707172737475767778797a7b7c7d7e7f" +
                    "8081828384858687",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3d626c6f636b6c" +
                    "656e",
            "68b94e2e538a9be4103bebb5aa016d47" +
                    "961d4d1aa906061313b557f8af2c3faa"
        )
        testHmacHex(
            Algorithm.SHA3_256,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f" +
                    "505152535455565758595a5b5c5d5e5f" +
                    "606162636465666768696a6b6c6d6e6f" +
                    "707172737475767778797a7b7c7d7e7f" +
                    "808182838485868788898a8b8c8d8e8f" +
                    "909192939495969798999a9b9c9d9e9f" +
                    "a0a1a2a3a4a5a6a7",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3e626c6f636b6c" +
                    "656e",
            "9bcf2c238e235c3ce88404e813bd2f3a" +
                    "97185ac6f238c63d6229a00b07974258"
        )
        testHmacHex(
            Algorithm.SHA3_256,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e2c2077697468207472756e636174" +
                    "656420746167",
            "c8dc7148d8c1423aa549105dafdf9cad",
            16
        )
    }
}
