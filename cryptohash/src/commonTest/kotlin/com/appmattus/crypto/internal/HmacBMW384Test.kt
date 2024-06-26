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

class HmacBMW384Test {

    /**
     * Test HMAC BMW-384 implementation.
     */
    @Test
    fun testHmacBmw384() {
        testHmac(
            Algorithm.BMW384,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "Sample #1",
            "E7BEAC8B685724D5B625E79E007172DF97FC85DB120DF5B752E618A676860EBB73F46E70FAA0F084937BFD6A21404913"
        )
        testHmac(
            Algorithm.BMW384,
            "303132333435363738393A3B3C3D3E3F40414243",
            "Sample #2",
            "9E7DAF3407CB1BC0CA3101F93A3D857B44815D0C7203BC66DE907C6C3DE7E322E78A9072B285C97BEED23A85521F5EE7"
        )
        testHmac(
            Algorithm.BMW384,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.",
            "515079D15A09C721C63F3E1011DC78837D1362753377F861FF34F9E884B84EA0A60ADA03AF5FC724870CCA900EC8E3B5"
        )
        testHmac(
            Algorithm.BMW384,
            "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3",
            "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance that a source with no knowledge of the key can present a purported MAC.",
            "9525578E38E7DD70CB9FECB6DC72DEC0388072FD3C63F6EC733E26466DA7EEA23A5CD49C5B566D8E730E30838F4C5563"
        )
    }
}
