/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.Crc
import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.internal.testKat
import com.appmattus.crypto.internal.testKatMillionA
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Known answers for the CRC-64 variants. The "123456789" check values are the
 * [CRC catalogue](https://reveng.sourceforge.io/crc-catalogue/17plus.htm)'s, and SWISS-PROT's, which the catalogue
 * doesn't list, is from its definition; the rest are from a bit-at-a-time reference implementation of each variant's
 * parameters.
 */
class Crc64Test {

    private val pattern = ByteArray(1000) { (it * 167 + 13).toByte() }

    @Test
    fun crc64Ecma182() {
        testKat({ Crc.crc64Ecma182.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64Ecma182.newHasher() }, "a", "548f120162451c62")
        testKat({ Crc.crc64Ecma182.newHasher() }, "abc", "66501a349a0e0855")
        testKat({ Crc.crc64Ecma182.newHasher() }, "123456789", "6c40df5f0b497347")
        testKat({ Crc.crc64Ecma182.newHasher() }, "message digest", "c04d61278997ba5e")
        testKat({ Crc.crc64Ecma182.newHasher() }, "The quick brown fox jumps over the lazy dog", "41e05242ffa9883b")
        testKat({ Crc.crc64Ecma182.newHasher() }, pattern, "8bb2536df3e80074")
        testKatMillionA({ Crc.crc64Ecma182.newHasher() }, "3377cec7a585e11f")
    }

    @Test
    fun crc64Xz() {
        testKat({ Crc.crc64Xz.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64Xz.newHasher() }, "a", "330284772e652b05")
        testKat({ Crc.crc64Xz.newHasher() }, "abc", "2cd8094a1a277627")
        testKat({ Crc.crc64Xz.newHasher() }, "123456789", "995dc9bbdf1939fa")
        testKat({ Crc.crc64Xz.newHasher() }, "message digest", "5dbcc956318a9b6f")
        testKat({ Crc.crc64Xz.newHasher() }, "The quick brown fox jumps over the lazy dog", "5b5eb8c2e54aa1c4")
        testKat({ Crc.crc64Xz.newHasher() }, pattern, "6acf642f639ec036")
        testKatMillionA({ Crc.crc64Xz.newHasher() }, "7a0d29398112e1ba")
    }

    @Test
    fun crc64We() {
        testKat({ Crc.crc64We.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64We.newHasher() }, "a", "ce73f427acc0a99a")
        testKat({ Crc.crc64We.newHasher() }, "abc", "048b813af9f49702")
        testKat({ Crc.crc64We.newHasher() }, "123456789", "62ec59e3f1a4f00a")
        testKat({ Crc.crc64We.newHasher() }, "message digest", "5273f9ea7a357bf4")
        testKat({ Crc.crc64We.newHasher() }, "The quick brown fox jumps over the lazy dog", "bcd8bb366d256116")
        testKat({ Crc.crc64We.newHasher() }, pattern, "7916025a27af5498")
        testKatMillionA({ Crc.crc64We.newHasher() }, "7fba642ed2ce66d8")
    }

    @Test
    fun crc64GoIso() {
        testKat({ Crc.crc64GoIso.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64GoIso.newHasher() }, "a", "3420000000000000")
        testKat({ Crc.crc64GoIso.newHasher() }, "abc", "3776c42000000000")
        testKat({ Crc.crc64GoIso.newHasher() }, "123456789", "b90956c775a41001")
        testKat({ Crc.crc64GoIso.newHasher() }, "message digest", "863fb9c0bb55c3a2")
        testKat({ Crc.crc64GoIso.newHasher() }, "The quick brown fox jumps over the lazy dog", "4ef14e19f4c6e28e")
        testKat({ Crc.crc64GoIso.newHasher() }, pattern, "5c144259ee498a0d")
        testKatMillionA({ Crc.crc64GoIso.newHasher() }, "ce43d31b3d00b82b")
    }

    @Test
    fun crc64SwissProt() {
        testKat({ Crc.crc64SwissProt.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64SwissProt.newHasher() }, "a", "5bb0000000000000")
        testKat({ Crc.crc64SwissProt.newHasher() }, "abc", "58893bb000000000")
        testKat({ Crc.crc64SwissProt.newHasher() }, "123456789", "46a5a9388a5beffe")
        testKat({ Crc.crc64SwissProt.newHasher() }, "message digest", "79c0463f44aa6f5d")
        testKat({ Crc.crc64SwissProt.newHasher() }, "The quick brown fox jumps over the lazy dog", "b10eb1b03e5a1d71")
        testKat({ Crc.crc64SwissProt.newHasher() }, pattern, "63cb4b96db234538")
        testKatMillionA({ Crc.crc64SwissProt.newHasher() }, "3cc9fd58a5365d50")
    }

    @Test
    fun crc64Redis() {
        testKat({ Crc.crc64Redis.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64Redis.newHasher() }, "a", "5fb354025b277b14")
        testKat({ Crc.crc64Redis.newHasher() }, "abc", "4431bb39b27363a7")
        testKat({ Crc.crc64Redis.newHasher() }, "123456789", "e9c6d914c4b8d9ca")
        testKat({ Crc.crc64Redis.newHasher() }, "message digest", "644474133412d35f")
        testKat({ Crc.crc64Redis.newHasher() }, "The quick brown fox jumps over the lazy dog", "bf7ee596c3aa372b")
        testKat({ Crc.crc64Redis.newHasher() }, pattern, "4b49bfd79e6b9e94")
        testKatMillionA({ Crc.crc64Redis.newHasher() }, "8d928728881ba360")
    }

    @Test
    fun crc64Nvme() {
        testKat({ Crc.crc64Nvme.newHasher() }, "", "0000000000000000")
        testKat({ Crc.crc64Nvme.newHasher() }, "a", "8c2f8445b4cbfc3c")
        testKat({ Crc.crc64Nvme.newHasher() }, "abc", "05e5cabb3fc1faeb")
        testKat({ Crc.crc64Nvme.newHasher() }, "123456789", "ae8b14860a799888")
        testKat({ Crc.crc64Nvme.newHasher() }, "message digest", "dc4a92ab26fba23f")
        testKat({ Crc.crc64Nvme.newHasher() }, "The quick brown fox jumps over the lazy dog", "d76c54054954c143")
        testKat({ Crc.crc64Nvme.newHasher() }, pattern, "94a3966fa52d4ef7")
        testKatMillionA({ Crc.crc64Nvme.newHasher() }, "38b0ef50419e0b4c")
    }

    @Test
    fun describesEachVariant() {
        listOf(
            Crc.crc64Ecma182 to "CRC-64/ECMA-182",
            Crc.crc64Xz to "CRC-64/XZ",
            Crc.crc64We to "CRC-64/WE",
            Crc.crc64GoIso to "CRC-64/GO-ISO",
            Crc.crc64SwissProt to "CRC-64/SWISS-PROT",
            Crc.crc64Redis to "CRC-64/REDIS",
            Crc.crc64Nvme to "CRC-64/NVME"
        ).forEach { (algorithm, name) ->
            assertEquals(name, algorithm.toString())
            assertEquals(name, algorithm.newHasher().toString())
            assertEquals(8, algorithm.newHasher().digestLength)
        }
    }

    /**
     * The slicing-by-8 path of update(ByteArray, Int, Int) must match the byte-at-a-time update(Byte) path for every
     * length up to a few blocks, at unaligned offsets and split across updates
     */
    @Test
    fun slicingMatchesByteAtATime() {
        val data = Random(0).nextBytes(MAX_LENGTH + MAX_OFFSET)
        for (algorithm in all) {
            for (offset in 0..MAX_OFFSET) {
                for (length in 0..MAX_LENGTH) checkSlicing(algorithm, data, offset, length)
            }
        }
    }

    private fun checkSlicing(algorithm: HashAlgorithm, data: ByteArray, offset: Int, length: Int) {
        val expected = algorithm.newHasher().apply { for (i in offset until offset + length) update(data[i]) }.digest()
        assertContentEquals(expected, algorithm.hash(data, offset, length), "$algorithm offset=$offset length=$length")

        val split = length / 3
        val chunked = algorithm.newHasher().update(data, offset, split).update(data, offset + split, length - split).digest()
        assertContentEquals(expected, chunked, "$algorithm offset=$offset length=$length split=$split")
    }

    private val all: List<HashAlgorithm> =
        listOf(Crc.crc64Ecma182, Crc.crc64Xz, Crc.crc64We, Crc.crc64GoIso, Crc.crc64SwissProt, Crc.crc64Redis, Crc.crc64Nvme)

    private companion object {
        const val MAX_LENGTH = 100
        const val MAX_OFFSET = 7
    }
}
