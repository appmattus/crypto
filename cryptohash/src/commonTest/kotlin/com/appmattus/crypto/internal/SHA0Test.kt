package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class SHA0CoreTest : SHA0Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.SHA_0)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class SHA0InstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.SHA_0))
    }
}

/**
 * Test SHA-0 implementation.
 */
abstract class SHA0Test {

    abstract fun digest(): Digest<*>

    @Test
    fun testSHA0() {
        val dig = digest()
        testKat(
            dig,
            "abc",
            "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8"
        )
        testKatMillionA(
            dig,
            "3232affa48628a26653b5aaa44541fd90d690603"
        )
        testCollision(
            dig,
            "a766a602b65cffe773bcf25826b322b3d01b1a972684ef533e" +
                    "3b4b7f53fe376224c08e47e959b2bc3b519880b928656824" +
                    "7d110f70f5c5e2b4590ca3f55f52feeffd4c8fe68de83532" +
                    "9e603cc51e7f02545410d1671d108df5a4000dcf20a43949" +
                    "49d72cd14fbb0345cf3a295dcda89f998f87552c9a58b1bd" +
                    "c384835e477185f96e68bebb0025d2d2b69edf21724198f6" +
                    "88b41deb9b4913fbe696b5457ab39921e1d7591f89de8457" +
                    "e8613c6c9e3b242879d4d8783b2d9ca9935ea526a729c06e" +
                    "dfc50137e69330be976012cc5dfe1c14c4c68bd1db3ecb24" +
                    "438a59a09b5db435563e0d8bdf572f77b53065cef31f32dc" +
                    "9dbaa04146261e9994bd5cd0758e3d",
            "a766a602b65cffe773bcf25826b322b1d01b1ad72684ef51be" +
                    "3b4b7fd3fe3762a4c08e45e959b2fc3b51988039286528a4" +
                    "7d110d70f5c5e034590ce3755f52fc6ffd4c8d668de87532" +
                    "9e603e451e7f02d45410d1e71d108df5a4000dcf20a43949" +
                    "49d72cd14fbb0145cf3a695dcda89d198f8755ac9a58b13d" +
                    "c384815e4771c5796e68febb0025d052b69edda17241d876" +
                    "88b41f6b9b49117be696f5c57ab399a1e1d7199f89de8657" +
                    "e8613cec9e3b26a879d498783b2d9e29935ea7a6a729806e" +
                    "dfc50337e693303e9760104c5dfe5c14c4c68951db3ecba4" +
                    "438a59209b5db435563e0d8bdf572f77b53065cef31f30dc" +
                    "9dbae04146261c1994bd5c50758e3d"
        )
    }
}
