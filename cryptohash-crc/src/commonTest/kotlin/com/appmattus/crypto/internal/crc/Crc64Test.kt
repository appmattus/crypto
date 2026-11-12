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

import com.appmattus.crypto.CRC
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
        testKat({ CRC.crc64Ecma182.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64Ecma182.newHasher() }, "a", "548f120162451c62")
        testKat({ CRC.crc64Ecma182.newHasher() }, "abc", "66501a349a0e0855")
        testKat({ CRC.crc64Ecma182.newHasher() }, "123456789", "6c40df5f0b497347")
        testKat({ CRC.crc64Ecma182.newHasher() }, "message digest", "c04d61278997ba5e")
        testKat({ CRC.crc64Ecma182.newHasher() }, "The quick brown fox jumps over the lazy dog", "41e05242ffa9883b")
        testKat({ CRC.crc64Ecma182.newHasher() }, pattern, "8bb2536df3e80074")
        testKatMillionA({ CRC.crc64Ecma182.newHasher() }, "3377cec7a585e11f")
    }

    @Test
    fun crc64Xz() {
        testKat({ CRC.crc64Xz.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64Xz.newHasher() }, "a", "330284772e652b05")
        testKat({ CRC.crc64Xz.newHasher() }, "abc", "2cd8094a1a277627")
        testKat({ CRC.crc64Xz.newHasher() }, "123456789", "995dc9bbdf1939fa")
        testKat({ CRC.crc64Xz.newHasher() }, "message digest", "5dbcc956318a9b6f")
        testKat({ CRC.crc64Xz.newHasher() }, "The quick brown fox jumps over the lazy dog", "5b5eb8c2e54aa1c4")
        testKat({ CRC.crc64Xz.newHasher() }, pattern, "6acf642f639ec036")
        testKatMillionA({ CRC.crc64Xz.newHasher() }, "7a0d29398112e1ba")
    }

    @Test
    fun crc64Be() {
        testKat({ CRC.crc64Be.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64Be.newHasher() }, "a", "ce73f427acc0a99a")
        testKat({ CRC.crc64Be.newHasher() }, "abc", "048b813af9f49702")
        testKat({ CRC.crc64Be.newHasher() }, "123456789", "62ec59e3f1a4f00a")
        testKat({ CRC.crc64Be.newHasher() }, "message digest", "5273f9ea7a357bf4")
        testKat({ CRC.crc64Be.newHasher() }, "The quick brown fox jumps over the lazy dog", "bcd8bb366d256116")
        testKat({ CRC.crc64Be.newHasher() }, pattern, "7916025a27af5498")
        testKatMillionA({ CRC.crc64Be.newHasher() }, "7fba642ed2ce66d8")
    }

    @Test
    fun crc64GoIso() {
        testKat({ CRC.crc64GoIso.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64GoIso.newHasher() }, "a", "3420000000000000")
        testKat({ CRC.crc64GoIso.newHasher() }, "abc", "3776c42000000000")
        testKat({ CRC.crc64GoIso.newHasher() }, "123456789", "b90956c775a41001")
        testKat({ CRC.crc64GoIso.newHasher() }, "message digest", "863fb9c0bb55c3a2")
        testKat({ CRC.crc64GoIso.newHasher() }, "The quick brown fox jumps over the lazy dog", "4ef14e19f4c6e28e")
        testKat({ CRC.crc64GoIso.newHasher() }, pattern, "5c144259ee498a0d")
        testKatMillionA({ CRC.crc64GoIso.newHasher() }, "ce43d31b3d00b82b")
    }

    @Test
    fun crc64SwissProt() {
        testKat({ CRC.crc64SwissProt.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64SwissProt.newHasher() }, "a", "5bb0000000000000")
        testKat({ CRC.crc64SwissProt.newHasher() }, "abc", "58893bb000000000")
        testKat({ CRC.crc64SwissProt.newHasher() }, "123456789", "46a5a9388a5beffe")
        testKat({ CRC.crc64SwissProt.newHasher() }, "message digest", "79c0463f44aa6f5d")
        testKat({ CRC.crc64SwissProt.newHasher() }, "The quick brown fox jumps over the lazy dog", "b10eb1b03e5a1d71")
        testKat({ CRC.crc64SwissProt.newHasher() }, pattern, "63cb4b96db234538")
        testKatMillionA({ CRC.crc64SwissProt.newHasher() }, "3cc9fd58a5365d50")
    }

    @Test
    fun crc64Jones() {
        testKat({ CRC.crc64Jones.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64Jones.newHasher() }, "a", "5fb354025b277b14")
        testKat({ CRC.crc64Jones.newHasher() }, "abc", "4431bb39b27363a7")
        testKat({ CRC.crc64Jones.newHasher() }, "123456789", "e9c6d914c4b8d9ca")
        testKat({ CRC.crc64Jones.newHasher() }, "message digest", "644474133412d35f")
        testKat({ CRC.crc64Jones.newHasher() }, "The quick brown fox jumps over the lazy dog", "bf7ee596c3aa372b")
        testKat({ CRC.crc64Jones.newHasher() }, pattern, "4b49bfd79e6b9e94")
        testKatMillionA({ CRC.crc64Jones.newHasher() }, "8d928728881ba360")
    }

    @Test
    fun crc64Nvme() {
        testKat({ CRC.crc64Nvme.newHasher() }, "", "0000000000000000")
        testKat({ CRC.crc64Nvme.newHasher() }, "a", "8c2f8445b4cbfc3c")
        testKat({ CRC.crc64Nvme.newHasher() }, "abc", "05e5cabb3fc1faeb")
        testKat({ CRC.crc64Nvme.newHasher() }, "123456789", "ae8b14860a799888")
        testKat({ CRC.crc64Nvme.newHasher() }, "message digest", "dc4a92ab26fba23f")
        testKat({ CRC.crc64Nvme.newHasher() }, "The quick brown fox jumps over the lazy dog", "d76c54054954c143")
        testKat({ CRC.crc64Nvme.newHasher() }, pattern, "94a3966fa52d4ef7")
        testKatMillionA({ CRC.crc64Nvme.newHasher() }, "38b0ef50419e0b4c")
    }

    @Test
    fun describesEachVariant() {
        listOf(
            CRC.crc64Ecma182 to "CRC-64/ECMA-182",
            CRC.crc64Xz to "CRC-64/XZ",
            CRC.crc64Be to "CRC-64/WE",
            CRC.crc64GoIso to "CRC-64/GO-ISO",
            CRC.crc64SwissProt to "CRC-64/SWISS-PROT",
            CRC.crc64Jones to "CRC-64/REDIS",
            CRC.crc64Nvme to "CRC-64/NVME"
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
                for (length in 0..MAX_LENGTH) {
                    val expected = algorithm.newHasher().apply { for (i in offset until offset + length) update(data[i]) }.digest()
                    assertContentEquals(expected, algorithm.hash(data, offset, length), "$algorithm offset=$offset length=$length")

                    val split = length / 3
                    val chunked = algorithm.newHasher().update(data, offset, split).update(data, offset + split, length - split).digest()
                    assertContentEquals(expected, chunked, "$algorithm offset=$offset length=$length split=$split")
                }
            }
        }
    }

    private val all: List<HashAlgorithm> =
        listOf(CRC.crc64Ecma182, CRC.crc64Xz, CRC.crc64Be, CRC.crc64GoIso, CRC.crc64SwissProt, CRC.crc64Jones, CRC.crc64Nvme)

    private companion object {
        const val MAX_LENGTH = 100
        const val MAX_OFFSET = 7
    }
}

