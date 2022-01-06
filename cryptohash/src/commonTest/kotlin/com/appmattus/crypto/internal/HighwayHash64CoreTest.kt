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
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class HighwayHash64CoreTest : HighwayHash64Test() {

    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HighwayHash64(key))

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test HighwayHash-64 implementation.
 */
abstract class HighwayHash64Test {

    var key: LongArray = longArrayOf(0, 0, 0, 0)

    abstract fun digest(): Digest<*>

    // From https://github.com/google/highwayhash/blob/master/java/com/google/highwayhash/HighwayHashTest.java
    @Test
    fun testKey1234() {
        key = longArrayOf(1, 2, 3, 4)

        testKat(
            { digest() },
            byteArrayOf(-1),
            "7858f24d2d79b2b2"
        )

        val b = ByteArray(33) {
            (128 + it).toByte()
        }
        testKat(
            { digest() },
            b,
            "53c516cce478cad7"
        )
    }

    // From https://github.com/google/highwayhash/blob/master/highwayhash/highwayhash_test.cc
    @Test
    fun testSequence() {
        key = longArrayOf(
            0x0706050403020100L, 0x0F0E0D0C0B0A0908L,
            0x1716151413121110L, 0x1F1E1D1C1B1A1918L
        )

        val data = ByteArray(65) {
            it.toByte()
        }

        val expected = listOf(
            "907A56DE22C26E53", "7EAB43AAC7CDDD78", "B8D0569AB0B53D62",
            "5C6BEFAB8A463D80", "F205A46893007EDA", "2B8A1668E4A94541",
            "BD4CCC325BEFCA6F", "4D02AE1738F59482", "E1205108E55F3171",
            "32D2644EC77A1584", "F6E10ACDB103A90B", "C3BBF4615B415C15",
            "243CC2040063FA9C", "A89A58CE65E641FF", "24B031A348455A23",
            "40793F86A449F33B", "CFAB3489F97EB832", "19FE67D2C8C5C0E2",
            "04DD90A69C565CC2", "75D9518E2371C504", "38AD9B1141D3DD16",
            "0264432CCD8A70E0", "A9DB5A6288683390", "D7B05492003F028C",
            "205F615AEA59E51E", "EEE0C89621052884", "1BFC1A93A7284F4F",
            "512175B5B70DA91D", "F71F8976A0A2C639", "AE093FEF1F84E3E7",
            "22CA92B01161860F", "9FC7007CCF035A68", "A0C964D9ECD580FC",
            "2C90F73CA03181FC", "185CF84E5691EB9E", "4FC1F5EF2752AA9B",
            "F5B7391A5E0A33EB", "B9B84B83B4E96C9C", "5E42FE712A5CD9B4",
            "A150F2F90C3F97DC", "7FA522D75E2D637D", "181AD0CC0DFFD32B",
            "3889ED981E854028", "FB4297E8C586EE2D", "6D064A45BB28059C",
            "90563609B3EC860C", "7AA4FCE94097C666", "1326BAC06B911E08",
            "B926168D2B154F34", "9919848945B1948D", "A2A98FC534825EBE",
            "E9809095213EF0B6", "582E5483707BC0E9", "086E9414A88A6AF5",
            "EE86B98D20F6743D", "F89B7FF609B1C0A7", "4C7D9CC19E22C3E8",
            "9A97005024562A6F", "5DD41CF423E6EBEF", "DF13609C0468E227",
            "6E0DA4F64188155A", "B755BA4B50D7D4A1", "887A3484647479BD",
            "AB8EEBE9BF2139A0", "75542C5D4CD2A6FF"
        )

        for (i in 0..64) {
            testKat(
                { digest() },
                data.copyOfRange(0, i),
                expected[i]
            )
        }
    }
}
