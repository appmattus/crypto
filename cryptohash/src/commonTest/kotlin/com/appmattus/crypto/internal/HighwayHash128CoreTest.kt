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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test
import kotlin.test.assertNotNull

class HighwayHash128CoreTest : HighwayHash128Test() {

    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.HighwayHash128(key))

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test HighwayHash-128 implementation.
 */
abstract class HighwayHash128Test {

    var key: LongArray = longArrayOf(0, 0, 0, 0)

    abstract fun digest(): Digest<*>

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
            "0FED268F9D8FFEC733565E767F093E6F",
            "D6B0A8893681E7A8DC291DF9EB9CDCB4",
            "3D15AD265A16DA0478085638DC32E868",
            "0607621B295F0BEBBFE69A0FD9CEDD79",
            "26399EB46DACE49E2E922AD039319208",
            "3250BDC386D12ED8193810906C63C23A",
            "6F476AB3CB8965477CDE576F37ED1019",
            "2A401FCA697171B4BE1F03FF9F02796C",
            "A1E96D84280552E8695CF1C63BEC0AC2",
            "142A2102F31E63B21A85B98C5B5000CC",
            "51A1B70E26B6BC5B929E1F3B2DA45559",
            "88990362059A415BBED21F22C47B7D13",
            "CD1F1F5F1CAF9566A818BA8CE0F9C8D4",
            "A225564112FE6157B2E94C78B8DDB848",
            "BD492FEBD1CC0919CECD1DBC025641A2",
            "142237A52BC4AF54E0796C0B6E26BCD7",
            "414460FFD5A401AD029EA3D5019F18C8",
            "C52A4B96C51C9962ECB878B1169B5EA0",
            "D940CA8F11FBEACEF93A46D616F8D531",
            "8AC49D0AE5C0CBF53FFDBF8DF51D7C93",
            "AC6D279B852D00A87DCD3A6BA5EBAA46",
            "F11621BD93F08A563173C398163DD9D5",
            "0C4CE250F68CF89FB3123CDA411898ED",
            "15AB97ED3D9A51CE7CE274479169080E",
            "CD001E198D4845B8D0D9D98BD8AA2D77",
            "34F3D617A0493D797DD304F6397F7E16",
            "5CB56890A9F4C6B6130829166567304F",
            "30DA6F8B245BD1C06F828B7E3FD9748C",
            "E0580349204C12C093F6DA0CAC5F441C",
            "F648731BA50730455FB897114FB65976",
            "024F8354738A5206509A4918EB7E0991",
            "06E7B465E8A57C2952415E3A07F5D446",
            "1984DF66C1434AAA16FC1958F9B3E4B9",
            "111678AFE0C6C36CF958B59DE5A2849D",
            "773FBC8440FB0490C96ED5D243658536",
            "91E3DC710BB6C941EA336A0BC1EEACE9",
            "25CFE3815D7AD9D4F2E94F8C828FC59E",
            "B9FB38B83CC288F27479C4C8F850EC04",
            "1D85D5C525982B8C6E26B1C16F48DBF4",
            "8A4E55BD6060BDE72134D599058B3FD0",
            "2A958FF994778F36E8052D1AE61D6423",
            "89233AE6BE4532333ACF9C87D7E8C0B9",
            "4458F5E27EA9C8D5418FB49BCA2A5140",
            "090301837ED12A681017F69633C861E6",
            "330DD84704D49590339DF1AD3A4BA6E4",
            "569363A663F2C576363B3D95E3C95EF6",
            "ACC8D08586B907372BA0E8087D4E28E9",
            "39C27A27C86D95208DB620A45160932E",
            "8E6A4AEB671A072D6ED3561A10E47EE6",
            "0011D765B1BEC74AD80E6E656EDE842E",
            "2515D62B936AC64CCE088794D7088A7D",
            "91621552C16E23AF264F0094EB23CCEF",
            "1E21880D97263480D8654807D3A31086",
            "39D76AAF097F432DA517E1E09D074739",
            "0F17A4F337C65A142F51215F69F976D4",
            "A0FB5CDA12895E44568C3DC4D1F13CD1",
            "93C8FC00D89C46CEBAD5DA947E330E69",
            "817C07501D1A5694584D6EE72CBFAC2B",
            "91D668AF73F053BFF98E647683C1E0ED",
            "5281E1EF6B3CCF8BBC4CC3DF166083D8",
            "AAD61B6DBEAAEEB9FF969D000C16787B",
            "4325D84FC047587914B919BD905F1C2D",
            "79A176D1AA6BA6D1F1F720C5A53A2B86",
            "74BD7018022F3EF03AEA94A8AD5F4BCB",
            "98BB1F7198D4C4F2E0BC0571DE918FC8"
        )

        for (i in 0..64) {
            testKat(
                digest(),
                data.copyOfRange(0, i),
                expected[i]
            )
        }
    }
}
