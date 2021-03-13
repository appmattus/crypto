/*
 * Copyright 2021 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class cSHAKE128CoreTest : cSHAKE128Test() {
    override fun digest(algorithm: Algorithm.cSHAKE128): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.cSHAKE128(null, null)))
    }
}

// cSHAKE128 with no customisation matches SHAKE128
class cSHAKE128asShakeTest : SHAKE128Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.cSHAKE128())

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Bouncy castle v1.68 implementation broken but issue already fixed
class cSHAKE128InstalledProviderTest {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.cSHAKE128()))
    }
}

/**
 * Test cSHAKE128 implementation.
 */
abstract class cSHAKE128Test {

    abstract fun digest(algorithm: Algorithm.cSHAKE128): Digest<*>

    private val customisation = "Email Signature".encodeToByteArray()

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
    @Test
    fun spec() {
        // sample 1
        testKatHex(
            dig = digest(Algorithm.cSHAKE128(customisation)),
            data = "00010203",
            ref = "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"
        )

        // sample 2
        testKatHex(
            dig = digest(Algorithm.cSHAKE128(customisation)),
            data = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            ref = "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun longS() {
        testKatHex(
            dig = digest(
                Algorithm.cSHAKE128(
                    strtobin("5468697320697320612076657279206c6f6e6720637573746f6d697a6174696f6e20737472696e672e20497420697320736f206c6f6e6720746861742069742074616b6573206d6f7265207468616e206f6e65206279746520746f20656e636f646520697473206c656e6774682c20696e206164646974696f6e20746f207468652062797465207468617420656e636f64657320746865206c656e677468206f6620746865206c656e6774682e2053696e636520746865206c656e67746820697320656e636f646564206173206d6f7265207468616e206f6e6520627974652c20746869732074657374732074686520656e6469616e6e657373206f662074686520656e636f64696e672e")
                )
            ),
            data = "00010203",
            ref = "1c34d5963a5caf3db12d392bc231e87339f84aab14171fe706691295435c93c4"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun longNandS() {
        testKatHex(
            dig = digest(
                Algorithm.cSHAKE128(
                    customisation = strtobin("5468697320697320612076657279206c6f6e6720637573746f6d697a6174696f6e20737472696e672e20497420697320736f206c6f6e6720746861742069742074616b6573206d6f7265207468616e206f6e65206279746520746f20656e636f646520697473206c656e6774682c20696e206164646974696f6e20746f207468652062797465207468617420656e636f64657320746865206c656e677468206f6620746865206c656e6774682e2053696e636520746865206c656e67746820697320656e636f646564206173206d6f7265207468616e206f6e6520627974652c20746869732074657374732074686520656e6469616e6e657373206f662074686520656e636f64696e672e"),
                    functionName = strtobin("546869732066756e6374696f6e206e616d65206973206d6f7265207468616e203235362062697473206c6f6e672e")
                )
            ),
            data = "00010203",
            ref = "1847b1c9f9ac3aef9c10436ca32700511b559424b0ddf236bb3d59a981f4aff1"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun bytepadAddsZeroBytes() {
        testKatLen(
            dig = digest(
                Algorithm.cSHAKE128(
                    strtobin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0")
                )
            ),
            data = strtobin("00010203"),
            ref = "ee9ec6d40a26b2cb311b36a97bca654884ce8196582fd9e7c3b29a0b48d839b545e6195a2bebaef7c31d70256633c8ab3370343a44c35d741bf4ed00e7ff3269"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun emptyNandSmeansShake128() {
        testKatLen(
            dig = digest(
                Algorithm.cSHAKE128()
            ),
            data = strtobin("84e950051876050dc851fbd99e6247b8"),
            ref = "8599bd89f63a848c49ca593ec37a12c6"
        )
    }

    private fun testKatLen(dig: Digest<*>, data: ByteArray, ref: String) {
        val buffer = ByteArray(ref.length / 2)

        /*
         * First test the hashing itself.
         */
        dig.update(data)
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())

        /*
         * Now the update() API; this also exercises auto-reset.
         */
        for (i in data.indices) dig.update(data[i])
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())

        /*
         * The cloning API.
         */
        val blen = data.size
        dig.update(data, 0, blen / 2)
        val dig2 = dig.copy()
        dig.update(data, blen / 2, blen - blen / 2)
        dig.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())
        dig2.update(data, blen / 2, blen - blen / 2)
        dig2.digest(buffer, 0, buffer.size)
        kotlin.test.assertEquals(ref.toLowerCase(), buffer.toHexString().toLowerCase())
    }
}
