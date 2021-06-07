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
            "3b16546bbc7be270"
                    + "6a031dcafd56373d"
                    + "9884367641d8c59a"
                    + "f3c860f7",
        )

        testHmac(
            Algorithm.SHA3_224,
            "4a656665",
            "what do ya want for nothing?",
            "7fdb8dd88bd2f60d"
                    + "1b798634ad386811"
                    + "c2cfc85bfaf5d52b"
                    + "bace5e66"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "b4a1f04c00287a9b"
                    + "7f6075b313d279b8"
                    + "33bc8f75124352d0"
                    + "5fb9995f"
        )

        testHmac(
            Algorithm.SHA3_224,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "05d8cd6d00faea8d"
                    + "1eb68ade28730bbd"
                    + "3cbab6929f0a086b"
                    + "29cd62a0"
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
}
