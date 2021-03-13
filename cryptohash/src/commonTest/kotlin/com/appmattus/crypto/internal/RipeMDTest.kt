package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.RipeMD
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class RipeMDCoreTest : RipeMDTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.RipeMD)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class RipeMDInstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.RipeMD))
    }
}

abstract class RipeMDTest {

    abstract fun digest(): Digest<*>

    /**
     * Test RIPEMD implementation.
     */
    @Test
    fun testRIPEMD() {
        val dig = RipeMD()
        testKat(
            dig,
            "",
            "9f73aa9b372a9dacfb86a6108852e2d9"
        )
        testKat(
            dig,
            "a",
            "486f74f790bc95ef7963cd2382b4bbc9"
        )
        testKat(
            dig,
            "abc",
            "3f14bad4c2f9b0ea805e5485d3d6882d"
        )
        testKat(
            dig,
            "message digest",
            "5f5c7ebe1abbb3c7036482942d5f9d49"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "ff6e1547494251a1cca6f005a6eaa2b4"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "ff418a5aed3763d8f2ddf88a29e62486"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "dfd6b45f60fe79bbbde87c6bfc6580a5"
        )
        testCollision(
            dig,
            "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15205da4ff047181a8584726a54e0661",
            "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15205da4ff047181a8584726a54e06e1"
        )
        testCollision(
            dig,
            "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15205da4ff04a5a0a8588db1b6660ce7",
            "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15205da4ff04a5a0a8588db1b6660c67"
        )
    }
}
