package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacBMW224Test {

    /**
     * Test HMAC BMW-224 implementation.
     */
    @Test
    fun testHmacBmw224() {
        /*
		 * From Blue Midnight Wish specification.
		 */
        testHmac(
            Algorithm.BMW224,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "Sample #1",
            "A208BC287D297A967C12801F12302EB7FB5511DE357D5B5677D8C050"
        )
        testHmac(
            Algorithm.BMW224,
            "303132333435363738393A3B3C3D3E3F40414243",
            "Sample #2",
            "525E551A5B890B00A7A99E27FF8C99AC6CD77E89E3B803007710DF4B"
        )
        testHmac(
            Algorithm.BMW224,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.",
            "D1674B83B37830E6AF7DBCC6260E3DECB8BB23F56DDA2CA828C60B87"
        )
        testHmac(
            Algorithm.BMW224,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance that a source with no knowledge of the key can present a purported MAC.",
            "16F9D79EF410A118DDD398396A6A3FD0AC9816ED7110ECA90A05430A"
        )
    }
}
