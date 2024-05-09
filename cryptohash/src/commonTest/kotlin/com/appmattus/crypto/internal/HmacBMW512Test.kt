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
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacBMW512Test {

    /**
     * Test HMAC BMW-512 implementation.
     */
    @Test
    fun testHmacBmw512() {
        testHmac(
            Algorithm.BMW512,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "Sample #1",
            "7017DB5D590A803ECDD0E87818083D657BB85636ED039BAAD3185D8CAB82E0172D1957757D6E5E2F288D43E032635E8FC4B9FAA9FD445CB1161F7786D805529F"
        )
        testHmac(
            Algorithm.BMW512,
            "303132333435363738393A3B3C3D3E3F40414243",
            "Sample #2",
            "CEF9110B1F90A24080C8CE794FD922F8669A1A0A74299DB9789D9BD9CCC8BA7E9438BD2383F14D3C9278FDB65C0A3FCFCBF2EB570C08588488F5F9AF428D8F67"
        )
        testHmac(
            Algorithm.BMW512,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.",
            "8519939233A4547258AFB322FAABDECFBE3F99B83CD0F760944B3F9B9FC0CD2DBBA98A069CC267CA80B53D9BA6D9E89C5A02173C661E5E715902D5F5B23FEA9F"
        )
        testHmac(
            Algorithm.BMW512,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance that a source with no knowledge of the key can present a purported MAC.",
            "44FCDF6C712B75BE3CA93EB2F98ECEAB23D7C5A3839C2D267CFE0A9A202E73756B8B30882D94725A82D2C705B5256154231EC14756CCF4A7132E911CA24C1AAB"
        )
    }
}
