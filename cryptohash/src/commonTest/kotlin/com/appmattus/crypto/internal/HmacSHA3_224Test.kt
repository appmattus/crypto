package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSHA3_224Test {

    @Test
    fun testSha3_224() {
        // From https://fossies.org/linux/peazip/tv_hmac-sha3.txt

        testHmac(
            Algorithm.SHA3_224,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7",
        )

        testHmac(
            Algorithm.SHA3_224,
            "4a656665",
            "what do ya want for nothing?",
            "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "b96d730c148c2daad8649d83defaa3719738d34775397b7571c38515"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "c79c9b093424e588a9878bbcb089e018270096e9b4b1a9e8220c866a"
        )

        testHmacHex(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a"
        )

        testHmacHex(
            Algorithm.SHA3_224,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb"
        )

        testHmac(
            Algorithm.SHA3_224,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "49fdd3abd005ebb8ae63fea946d1883c",
            16
        )
    }

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SHA3HMacTest.java

        testHmacHex(
            Algorithm.SHA3_224,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
            "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04"
        )
        testHmacHex(
            Algorithm.SHA3_224,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f" +
                    "505152535455565758595a5b5c5d5e5f" +
                    "606162636465666768696a6b6c6d6e6f" +
                    "707172737475767778797a7b7c7d7e7f" +
                    "808182838485868788898a8b8c8d8e8f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3d626c6f636b6c" +
                    "656e",
            "d8b733bcf66c644a12323d564e24dcf3" +
                    "fc75f231f3b67968359100c7"
        )
        testHmacHex(
            Algorithm.SHA3_224,
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
                    "a0a1a2a3a4a5a6a7a8a9aaab",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3e626c6f636b6c" +
                    "656e",
            "078695eecc227c636ad31d063a15dd05" +
                    "a7e819a66ec6d8de1e193e59"
        )
        testHmacHex(
            Algorithm.SHA3_224,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e2c2077697468207472756e636174" +
                    "656420746167",
            "8569c54cbb00a9b78ff1b391b0e5",
            14
        )
    }
}
