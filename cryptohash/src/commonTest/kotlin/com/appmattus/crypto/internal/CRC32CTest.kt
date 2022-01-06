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

class CRC32CCoreTest : CRC32CTest() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.CRC32C)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test CRC32C implementation.
 */
abstract class CRC32CTest {

    abstract fun digest(): Digest<*>

    // From https://github.com/php/php-src/blob/master/ext/hash/tests/crc32.phpt
    @Test
    fun misc() {
        mapOf(
            "" to "00000000",
            "a" to "c1d04330",
            "ab" to "e2a22936",
            "abc" to "364b3fb7",
            "abcd" to "92c80a31",
            "abcde" to "c450d697",
            "abcdef" to "53bceff1",
            "abcdefg" to "e627f441",
            "abcdefgh" to "0a9421b7",
            "abcdefghi" to "2ddc99fc",
            "abcdefghij" to "e6599437",
            "abcdefghijklmnopqrstuvwxyz" to "9ee6ef25",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "a245d57d",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "477a6781",
            "message digest" to "02bd79d0",
            "I can't remember anything" to "5e405e93",
            "Discard medicine more than two years old." to "b2cc01fe",
            "He who has a shady past knows that nice guys finish last." to "0e28207f",
            "I wouldn't marry him with a ten foot pole." to "be93f964",
            "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" to "9e3be0c3",
            "The days of the digital watch are numbered.  -Tom Stoppard" to "f505ef04",
            "Nepal premier won't resign." to "85d3dc82",
            "For every action there is an equal and opposite government program." to "c5142380",
            "His money is twice tainted: 'taint yours and 'taint mine." to "75eb77dd",
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" to "91ebe9f7",
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek" to "f0b1168e",
            "size:  a.out:  bad magic" to "572b74e2",
            "The major problem is with sendmail.  -Mark Horton" to "8a58a6d5",
            "Give me a rock, paper and scissors and I will move the world.  CCFestoon" to "9c426c50",
            "If the enemy is within range, then so are you." to "735400a4",
            "It's well we cannot hear the screams/That we create in others' dreams." to "bec49c95",
            "You remind me of a TV show, but that's all right: I watch it anyway." to "a95a2079",
            "C is as portable as Stonehedge!!" to "de2e65c5",
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" to "297a88ed",
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" to "66ed1d8b",
            "How can you write a big system without C++?  -Paul Glick" to "dcded527",
            "1234567890123456" to "9aa4287f",
            "1234567890123456abc" to "ab2761c5",
            "12345678901234561234567890123456" to "cd486b4b",
            "12345678901234561234567890123456abc" to "c19c4a41",
            "123456789012345612345678901234561234567890123456" to "1ea5b441",
            "123456789012345612345678901234561234567890123456abc" to "36d20512",
            "1234567890123456123456789012345612345678901234561234567890123456" to "31d11ffa",
            "1234567890123456123456789012345612345678901234561234567890123456abc" to "65d5bb9e",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456" to "a0e3e317",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "8dc10a7c",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456" to "7ab04135",
            "12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "c292a38d",
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456" to "e3e558ec",
            "123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456abc" to "b6c5e13e",
        ).forEach { (input, output) ->
            testKat(
                { digest() },
                input,
                output
            )
        }
    }
}
