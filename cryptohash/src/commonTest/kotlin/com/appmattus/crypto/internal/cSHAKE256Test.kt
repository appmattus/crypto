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

class cSHAKE256CoreTest : cSHAKE256Test() {
    override fun digest(algorithm: Algorithm.cSHAKE256): Digest<*> = CoreDigest.create(algorithm)

    @Test
    fun hasImplementation() {
        assertNotNull(digest(Algorithm.cSHAKE256(null, null)))
    }
}

// cSHAKE256 with no customisation matches SHAKE256
class cSHAKE256asShakeTest : SHAKE256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.cSHAKE256())

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// Bouncy castle v1.68 implementation broken so we don't use it
class cSHAKE256InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.cSHAKE256()))
    }
}

/**
 * Test cSHAKE256 implementation.
 */
abstract class cSHAKE256Test {

    abstract fun digest(algorithm: Algorithm.cSHAKE256): Digest<*>

    // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
    @Test
    fun spec() {
        val customisation = "Email Signature".encodeToByteArray()

        // sample 3
        testKatHex(
            dig = digest(Algorithm.cSHAKE256(customisation = customisation)),
            data = "00010203",
            ref = "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"
        )

        // sample 4
        testKatHex(
            dig = digest(Algorithm.cSHAKE256(customisation = customisation)),
            data = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
            ref = "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun longS() {
        testKatHex(
            dig = digest(
                Algorithm.cSHAKE256(
                    strtobin("5468697320697320612076657279206c6f6e6720637573746f6d697a6174696f6e20737472696e672e20497420697320736f206c6f6e6720746861742069742074616b6573206d6f7265207468616e206f6e65206279746520746f20656e636f646520697473206c656e6774682c20696e206164646974696f6e20746f207468652062797465207468617420656e636f64657320746865206c656e677468206f6620746865206c656e6774682e2053696e636520746865206c656e67746820697320656e636f646564206173206d6f7265207468616e206f6e6520627974652c20746869732074657374732074686520656e6469616e6e657373206f662074686520656e636f64696e672e")
                )
            ),
            data = "00010203",
            ref = "0977608119b5f3a373379e980086e40bbed397a6d071495e6933bdb2197c4262bd251c0b9c5ba332f72ad4892bf6ad6d13461eec90f2d5f7d6ae8cbd711a289a"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun longNandS() {
        testKatHex(
            dig = digest(
                Algorithm.cSHAKE256(
                    customisation = strtobin("5468697320697320612076657279206c6f6e6720637573746f6d697a6174696f6e20737472696e672e20497420697320736f206c6f6e6720746861742069742074616b6573206d6f7265207468616e206f6e65206279746520746f20656e636f646520697473206c656e6774682c20696e206164646974696f6e20746f207468652062797465207468617420656e636f64657320746865206c656e677468206f6620746865206c656e6774682e2053696e636520746865206c656e67746820697320656e636f646564206173206d6f7265207468616e206f6e6520627974652c20746869732074657374732074686520656e6469616e6e657373206f662074686520656e636f64696e672e"),
                    functionName = strtobin("546869732066756e6374696f6e206e616d65206973206d6f7265207468616e203235362062697473206c6f6e672e")
                )
            ),
            data = "00010203",
            ref = "4af334bc296f08f66f3dfa224bae82604ea9d4fd102fe6169d82aba824a67cbc4e93cb6a1b9daf6f04d3734d99e4f0ef6018eb1de32501a8a91c7da29c87d562"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun bytepadAddsZeroBytes() {
        testKatLen(
            dig = digest(
                Algorithm.cSHAKE256(
                    strtobin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80")
                )
            ),
            data = strtobin("00010203"),
            ref = "7d837103f8e447b6b1d2d50cf6a652a9740bfcf491cfa13f45b8b6992b9916e78088438f53e7d9826bc82de86b3c43bbcdc5f44e848884011ae44aa602ea12c0"
        )
    }

    // From https://github.com/DominicLittlewood/quantum-mbedtls/blob/d9104b0c3e4587143bbd9b6903111f7393920b17/tests/suites/test_suite_shake.data
    @Test
    fun emptyNandSmeansShake256() {
        testKatLen(
            dig = digest(
                Algorithm.cSHAKE256()
            ),
            data = strtobin("c61a9188812ae73994bc0d6d4021e31bf124dc72669749111232da7ac29e61c4"),
            ref = "23cebdd984b84c15e341f1fe0187264fe44093ebddfe91fb04b9e9456ae0d70801cfa88ed370ef5a6250a76a17d83cecc7e7bf2794035b6a78129bac6eb233e8"
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
