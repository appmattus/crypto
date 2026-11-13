/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.haval

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.Haval
import com.appmattus.crypto.internal.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class HAVAL_5_128CoreTest : HAVAL_5_128Test() {
    override fun digest(): Hasher = Haval.haval5_128.newHasher()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test HAVAL-5-128 implementation.
 */
abstract class HAVAL_5_128Test {

    abstract fun digest(): Hasher

    @Test
    fun testHAVAL_5_128() {
        testKat({ digest() }, "", "184B8482A0C050DCA54B59C7F05BF5DD")
        testKat({ digest() }, "a", "F23FBE704BE8494BFA7A7FB4F8AB09E5")
        testKat({ digest() }, "HAVAL", "C97990F4FCC8FBA76AF935C405995355")
        testKat({ digest() }, "0123456789", "466FDCD81C3477CAC6A31FFA1C999CA8")
        testKat({ digest() }, "abcdefghijklmnopqrstuvwxyz", "0EFFF71D7D14344CBA1F4B25F924A693")
        testKat({ digest() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "4B27D04DDB516BDCDFEB96EB8C7C8E90")
    }
}
