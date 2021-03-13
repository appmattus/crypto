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
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class WhirlpoolCoreTest : WhirlpoolTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Whirlpool)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class WhirlpoolInstalledProviderTest {

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
        assertNull(PlatformDigest().create(Algorithm.Whirlpool))
    }
}

/**
 * Test Whirlpool implementation.
 */
abstract class WhirlpoolTest {

    abstract fun digest(): Digest<*>

    @Test
    fun testWhirlpool() {
        val dig = digest()
        testKat(
            dig,
            "",
            "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"
        )
        testKat(
            dig,
            "a",
            "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
        )
        testKat(
            dig,
            "abc",
            "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"
        )
        testKat(
            dig,
            "message digest",
            "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E"
        )
        testKat(
            dig,
            "abcdefghijklmnopqrstuvwxyz",
            "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B"
        )
        testKat(
            dig,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467"
        )
        testKat(
            dig,
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B"
        )
        testKat(
            dig,
            "abcdbcdecdefdefgefghfghighijhijk",
            "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD"
        )
        testKatMillionA(
            dig,
            "0C99005BEB57EFF50A7CF005560DDF5D29057FD86B20BFD62DECA0F1CCEA4AF51FC15490EDDC47AF32BB2B66C34FF9AD8C6008AD677F77126953B226E4ED8B01"
        )
    }

    @Test
    fun thirtyoneZeros() {
        testKat(
            digest(),
            ByteArray(31) { 0.toByte() },
            "3E3F188F8FEBBEB17A933FEAF7FE53A4858D80C915AD6A1418F0318E68D49B4E459223CD414E0FBC8A57578FD755D86E827ABEF4070FC1503E25D99E382F72BA"
        )
    }
}
