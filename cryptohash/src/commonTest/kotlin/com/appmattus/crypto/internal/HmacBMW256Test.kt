package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacBMW256Test {

    /**
     * Test HMAC BMW-256 implementation.
     */
    @Test
    fun testHmacBmw256() {
        testHmac(
            Algorithm.BMW256,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "Sample #1",
            "B5F059FD59189FA9B4C0C11C2B132C67D89CBAE1F116A2D2A1539344D8E2F938"
        )
        testHmac(
            Algorithm.BMW256,
            "303132333435363738393A3B3C3D3E3F40414243",
            "Sample #2",
            "7B203B5415EEF50E6E64C1C758BD06D0ED23D9931F74F713D49BD07583251FFE"
        )
        testHmac(
            Algorithm.BMW256,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.",
            "6696C4094F8D89BCEE17AF4350DC4D3E84A2E2CA1A239DE8C5B689F07FAF6248"
        )
        testHmac(
            Algorithm.BMW256,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance that a source with no knowledge of the key can present a purported MAC.",
            "F5C8A1F531FD09D1F33845E705075A8CE5EEB29B33EFF70BAE97B750E3231383"
        )
    }
}
