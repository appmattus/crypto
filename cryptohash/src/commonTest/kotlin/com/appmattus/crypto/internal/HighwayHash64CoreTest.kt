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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class HighwayHash64CoreTest : HighwayHash64Test() {

    override fun digest(): Digest = CoreDigest.create(Algorithm.HighwayHash64(key))

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

    abstract fun digest(): Digest

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

    // From a port of the reference implementation (google/highwayhash, c/highwayhash.c), for messages of bytes
    // (i * 167 + 13), roughly half of which have the top bit set, at every length from 0 to 64 and the packet
    // boundaries above it, with a key whose words have the top bit set
    @Test
    fun testHighBytes() {
        key = longArrayOf(
            -0x70f1f2f3f4f5f6f8, -0x08090a0b0c0d0e10, 0x0123456789abcdef, -0x0123456789abcdf0
        )

        val lengths = (0..64).toList() + listOf(95, 96, 97, 143, 144, 145, 255, 256, 1023)

        val expected = listOf(
            "B6044C07974532A8", "39667A0CEAEDE729", "F374C946995AC210", "2CD11A42A5D81434",
            "EAC3CFA88E039EDC", "7312F97F444EE88D", "D126E418872EAB54", "3E9041B7264B259B",
            "3CE13A87DDC9ACDF", "1A635A0B7B69849E", "FEE66DA5864FF7C5", "7376E6D7EE68D4D4",
            "A347EEBF6F0CD40E", "5A6746593E3D6A2E", "5562B99DAF7151CC", "064B2612F1058562",
            "327ABC82C491CA1D", "24E8EC04A87CCC43", "F9057B35379621BC", "64AF25EF8EA709D8",
            "7010B5142F11B104", "1A91E211D85A0B9C", "5F465B0375C4F99F", "F26F3275DE170C11",
            "3B7AF2CDC9F482F9", "9C929A652E742F14", "A9D0242F1ABEB024", "964644FBE1DB2564",
            "67E510597196AEF2", "4F4DE3F5D5A1E6CF", "522DAEAD8CE1B4B3", "9756A73A1CC93857",
            "041FCF03A469939F", "DE029E48B88B34BF", "5C38CEA2BF54683C", "777E8A1D35CD1705",
            "990DA5F3E44EF0B4", "3FB52C2EEF4A08D7", "68B117080B8322D2", "BC0B18714CC78DE0",
            "6EC4ACC616CD27C7", "BA2E2BFF7E84A600", "2622762AC092057D", "DB9F1C4767E17203",
            "6BE8778B476539D8", "8A995EF68A4EA139", "6B3A6A5CC959CD16", "6378A9A6092C52BD",
            "C07BC50AC2CC511D", "176ABBFE426A8FE1", "42BAF8EC609E008E", "B176602FB1E243DB",
            "7C341D891B7EB5E0", "5B3AB3D42176DBE8", "C47888CCDF6911C2", "700AC92DF0354827",
            "5DDC874C1F681DC5", "8EDD631FE227DED0", "9177F3877D201303", "413858FAF60011D8",
            "AB70438DF06D3781", "FD521645BBC12A88", "FA4402D422C877AF", "DCC16951AB5F876C",
            "794DAA44B2D77FCE", "22A3BBF0F669F5E2", "8B71FB6C2D3C7A82", "FB762D8C0F0F43B2",
            "BEAF0DD9A7BEBE7F", "C2F0572FE850EED8", "5A4C7B2D9851CE9A", "74B0EDDFEEF1AD46",
            "E017693D4F413AC3", "120E22F7C89EA5F1"
        )

        lengths.forEachIndexed { index, length ->
            testKat(
                { digest() },
                ByteArray(length) { (it * 167 + 13).toByte() },
                expected[index]
            )
        }
    }
}
