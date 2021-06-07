package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacSHA3_512Test {

    @Test
    fun testSha3_512() {
        // From https://fossies.org/linux/peazip/tv_hmac-sha3.txt

        testHmac(
            Algorithm.SHA3_512,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "eb3fbd4b2eaab8f5"
                    + "c504bd3a41465aac"
                    + "ec15770a7cabac53"
                    + "1e482f860b5ec7ba"
                    + "47ccb2c6f2afce8f"
                    + "88d22b6dc61380f2"
                    + "3a668fd3888bb805"
                    + "37c0a0b86407689e"
        )

        testHmac(
            Algorithm.SHA3_512,
            "4a656665",
            "what do ya want for nothing?",
            "5a4bfeab6166427c"
                    + "7a3647b747292b83"
                    + "84537cdb89afb3bf"
                    + "5665e4c5e709350b"
                    + "287baec921fd7ca0"
                    + "ee7a0c31d022a95e"
                    + "1fc92ba9d77df883"
                    + "960275beb4e62024"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "00f751a9e50695b0"
                    + "90ed6911a4b65524"
                    + "951cdc15a73a5d58"
                    + "bb55215ea2cd839a"
                    + "c79d2b44a39bafab"
                    + "27e83fde9e11f634"
                    + "0b11d991b1b91bf2"
                    + "eee7fc872426c3a4"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "38a456a004bd10d3"
                    + "2c9ab83366841128"
                    + "62c3db61adcca318"
                    + "29355eaf46fd5c73"
                    + "d06a1f0d13fec9a6"
                    + "52fb3811b577b1b1"
                    + "d1b9789f97ae5b83"
                    + "c6f44dfcf1d67eba"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "b14835c819a290efb010ace6d8568dc6b84de60bc49b004c3b13eda763589451e5dd74292884d1bdce64e6b919dd61dc9c56a282a81c0bd14f1f365b49b83a5b"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "dc030ee7887034f32cf402df34622f311f3e6cf04860c6bbd7fa488674782b4659fdbdf3fd877852885cfe6e22185fe7b2ee952043629bc9d5f3298a41d02c66"
        )

        testHmacHex(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03"
        )

        testHmacHex(
            Algorithm.SHA3_512,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d"
        )

        testHmac(
            Algorithm.SHA3_512,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "0fa7475948f43f48ca0516671e18978c",
            16
        )
    }
}
