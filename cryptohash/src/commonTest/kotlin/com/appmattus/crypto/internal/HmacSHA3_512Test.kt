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
            "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"
        )

        testHmac(
            Algorithm.SHA3_512,
            "4a656665",
            "what do ya want for nothing?",
            "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4"
        )

        testHmac(
            Algorithm.SHA3_512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba"
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

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SHA3HMacTest.java

        testHmacHex(
            Algorithm.SHA3_512,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e",
            "4efd629d6c71bf86162658f29943b1c3" +
                    "08ce27cdfa6db0d9c3ce81763f9cbce5" +
                    "f7ebe9868031db1a8f8eb7b6b95e5c5e" +
                    "3f657a8996c86a2f6527e307f0213196"
        )
        testHmacHex(
            Algorithm.SHA3_512,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f" +
                    "4041424344454647",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3d626c6f636b6c" +
                    "656e",
            "544e257ea2a3e5ea19a590e6a24b724c" +
                    "e6327757723fe2751b75bf007d80f6b3" +
                    "60744bf1b7a88ea585f9765b47911976" +
                    "d3191cf83c039f5ffab0d29cc9d9b6da"
        )
        testHmacHex(
            Algorithm.SHA3_512,
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
                    "6f72206b65796c656e3e626c6f636b6c" +
                    "656e",
            "5f464f5e5b7848e3885e49b2c385f069" +
                    "4985d0e38966242dc4a5fe3fea4b37d4" +
                    "6b65ceced5dcf59438dd840bab22269f" +
                    "0ba7febdb9fcf74602a35666b2a32915"
        )
        testHmacHex(
            Algorithm.SHA3_512,
            "000102030405060708090a0b0c0d0e0f" +
                    "101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f" +
                    "303132333435363738393a3b3c3d3e3f",
            "53616d706c65206d6573736167652066" +
                    "6f72206b65796c656e3c626c6f636b6c" +
                    "656e2c2077697468207472756e636174" +
                    "656420746167",
            "7bb06d859257b25ce73ca700df34c5cb" +
                    "ef5c898bac91029e0b27975d4e526a08",
            32
        )
    }
}
