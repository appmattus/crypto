/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testCollision
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class RipeMDCoreTest : RipeMDTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.RipeMD)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

abstract class RipeMDTest {

    abstract fun digest(): Digest<*>

    /**
     * Test RIPEMD implementation.
     */
    @Test
    fun testRIPEMD() {
        testKat(
            { digest() },
            "",
            "9f73aa9b372a9dacfb86a6108852e2d9"
        )
        testKat(
            { digest() },
            "a",
            "486f74f790bc95ef7963cd2382b4bbc9"
        )
        testKat(
            { digest() },
            "abc",
            "3f14bad4c2f9b0ea805e5485d3d6882d"
        )
        testKat(
            { digest() },
            "message digest",
            "5f5c7ebe1abbb3c7036482942d5f9d49"
        )
        testKat(
            { digest() },
            "abcdefghijklmnopqrstuvwxyz",
            "ff6e1547494251a1cca6f005a6eaa2b4"
        )
        testKat(
            { digest() },
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "ff418a5aed3763d8f2ddf88a29e62486"
        )
        testKat(
            { digest() },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "dfd6b45f60fe79bbbde87c6bfc6580a5"
        )
        testCollision(
            { digest() },
            "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15205da4ff047181a8584726a54e0661",
            "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15205da4ff047181a8584726a54e06e1"
        )
        testCollision(
            { digest() },
            "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15205da4ff04a5a0a8588db1b6660ce7",
            "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15205da4ff04a5a0a8588db1b6660c67"
        )
    }
}
