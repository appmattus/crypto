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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest

@Suppress("MagicNumber")
internal class CRC32C : Digest<CRC32C> {

    private var checksum = 0

    override fun update(input: Byte) {
        var c: Int = checksum.inv()
        c = crcTable[c xor input.toInt() and 0xff] xor (c ushr 8)
        checksum = c.inv()
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var len = length
        var pos = offset
        var c: Int = checksum.inv()
        while (--len >= 0) c = crcTable[c xor input[pos++].toInt() and 0xff] xor (c ushr 8)
        checksum = c.inv()
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)

        encodeBEInt(checksum, digest, 0)

        reset()

        return digest
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    /**
     * Completes the hash computation by performing final
     * operations such as padding.
     *
     * @param output the output buffer in which to store the digest
     *
     * @param offset offset to start from in the output buffer
     *
     * @param length number of bytes within [output] allotted for the digest. This
     * implementation does not return partial digests. The presence of this
     * parameter is solely for consistency in our API's. If the value of this
     * parameter is less than the actual digest length, the method will throw
     * an Exception.
     * This parameter is ignored if its value is greater than or equal to
     * the actual digest length.
     *
     * @return the length of the digest stored in the output buffer.
     */
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 4

    override fun reset() {
        checksum = 0
    }

    override fun copy(): CRC32C {
        return CRC32C().also {
            it.checksum = checksum
        }
    }

    override val blockLength: Int
        get() = Algorithm.CRC32C.blockLength

    override fun toString() = Algorithm.CRC32C.algorithmName

    companion object {

        /** The fast CRC table. Computed once when the CRC32 class is loaded.  */
        private val crcTable = intArrayOf(
            0x00000000, 0xf26b8303.toInt(), 0xe13b70f7.toInt(), 0x1350f3f4,
            0xc79a971f.toInt(), 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb.toInt(),
            0x8ad958cf.toInt(), 0x78b2dbcc, 0x6be22838, 0x9989ab3b.toInt(),
            0x4d43cfd0, 0xbf284cd3.toInt(), 0xac78bf27.toInt(), 0x5e133c24,
            0x105ec76f, 0xe235446c.toInt(), 0xf165b798.toInt(), 0x030e349b,
            0xd7c45070.toInt(), 0x25afd373, 0x36ff2087, 0xc494a384.toInt(),
            0x9a879fa0.toInt(), 0x68ec1ca3, 0x7bbcef57, 0x89d76c54.toInt(),
            0x5d1d08bf, 0xaf768bbc.toInt(), 0xbc267848.toInt(), 0x4e4dfb4b,
            0x20bd8ede, 0xd2d60ddd.toInt(), 0xc186fe29.toInt(), 0x33ed7d2a,
            0xe72719c1.toInt(), 0x154c9ac2, 0x061c6936, 0xf477ea35.toInt(),
            0xaa64d611.toInt(), 0x580f5512, 0x4b5fa6e6, 0xb93425e5.toInt(),
            0x6dfe410e, 0x9f95c20d.toInt(), 0x8cc531f9.toInt(), 0x7eaeb2fa,
            0x30e349b1, 0xc288cab2.toInt(), 0xd1d83946.toInt(), 0x23b3ba45,
            0xf779deae.toInt(), 0x05125dad, 0x1642ae59, 0xe4292d5a.toInt(),
            0xba3a117e.toInt(), 0x4851927d, 0x5b016189, 0xa96ae28a.toInt(),
            0x7da08661, 0x8fcb0562.toInt(), 0x9c9bf696.toInt(), 0x6ef07595,
            0x417b1dbc, 0xb3109ebf.toInt(), 0xa0406d4b.toInt(), 0x522bee48,
            0x86e18aa3.toInt(), 0x748a09a0, 0x67dafa54, 0x95b17957.toInt(),
            0xcba24573.toInt(), 0x39c9c670, 0x2a993584, 0xd8f2b687.toInt(),
            0x0c38d26c, 0xfe53516f.toInt(), 0xed03a29b.toInt(), 0x1f682198,
            0x5125dad3, 0xa34e59d0.toInt(), 0xb01eaa24.toInt(), 0x42752927,
            0x96bf4dcc.toInt(), 0x64d4cecf, 0x77843d3b, 0x85efbe38.toInt(),
            0xdbfc821c.toInt(), 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8.toInt(),
            0x1c661503, 0xee0d9600.toInt(), 0xfd5d65f4.toInt(), 0x0f36e6f7,
            0x61c69362, 0x93ad1061.toInt(), 0x80fde395.toInt(), 0x72966096,
            0xa65c047d.toInt(), 0x5437877e, 0x4767748a, 0xb50cf789.toInt(),
            0xeb1fcbad.toInt(), 0x197448ae, 0x0a24bb5a, 0xf84f3859.toInt(),
            0x2c855cb2, 0xdeeedfb1.toInt(), 0xcdbe2c45.toInt(), 0x3fd5af46,
            0x7198540d, 0x83f3d70e.toInt(), 0x90a324fa.toInt(), 0x62c8a7f9,
            0xb602c312.toInt(), 0x44694011, 0x5739b3e5, 0xa55230e6.toInt(),
            0xfb410cc2.toInt(), 0x092a8fc1, 0x1a7a7c35, 0xe811ff36.toInt(),
            0x3cdb9bdd, 0xceb018de.toInt(), 0xdde0eb2a.toInt(), 0x2f8b6829,
            0x82f63b78.toInt(), 0x709db87b, 0x63cd4b8f, 0x91a6c88c.toInt(),
            0x456cac67, 0xb7072f64.toInt(), 0xa457dc90.toInt(), 0x563c5f93,
            0x082f63b7, 0xfa44e0b4.toInt(), 0xe9141340.toInt(), 0x1b7f9043,
            0xcfb5f4a8.toInt(), 0x3dde77ab, 0x2e8e845f, 0xdce5075c.toInt(),
            0x92a8fc17.toInt(), 0x60c37f14, 0x73938ce0, 0x81f80fe3.toInt(),
            0x55326b08, 0xa759e80b.toInt(), 0xb4091bff.toInt(), 0x466298fc,
            0x1871a4d8, 0xea1a27db.toInt(), 0xf94ad42f.toInt(), 0x0b21572c,
            0xdfeb33c7.toInt(), 0x2d80b0c4, 0x3ed04330, 0xccbbc033.toInt(),
            0xa24bb5a6.toInt(), 0x502036a5, 0x4370c551, 0xb11b4652.toInt(),
            0x65d122b9, 0x97baa1ba.toInt(), 0x84ea524e.toInt(), 0x7681d14d,
            0x2892ed69, 0xdaf96e6a.toInt(), 0xc9a99d9e.toInt(), 0x3bc21e9d,
            0xef087a76.toInt(), 0x1d63f975, 0x0e330a81, 0xfc588982.toInt(),
            0xb21572c9.toInt(), 0x407ef1ca, 0x532e023e, 0xa145813d.toInt(),
            0x758fe5d6, 0x87e466d5.toInt(), 0x94b49521.toInt(), 0x66df1622,
            0x38cc2a06, 0xcaa7a905.toInt(), 0xd9f75af1.toInt(), 0x2b9cd9f2,
            0xff56bd19.toInt(), 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed.toInt(),
            0xc38d26c4.toInt(), 0x31e6a5c7, 0x22b65633, 0xd0ddd530.toInt(),
            0x0417b1db, 0xf67c32d8.toInt(), 0xe52cc12c.toInt(), 0x1747422f,
            0x49547e0b, 0xbb3ffd08.toInt(), 0xa86f0efc.toInt(), 0x5a048dff,
            0x8ecee914.toInt(), 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0.toInt(),
            0xd3d3e1ab.toInt(), 0x21b862a8, 0x32e8915c, 0xc083125f.toInt(),
            0x144976b4, 0xe622f5b7.toInt(), 0xf5720643.toInt(), 0x07198540,
            0x590ab964, 0xab613a67.toInt(), 0xb831c993.toInt(), 0x4a5a4a90,
            0x9e902e7b.toInt(), 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f.toInt(),
            0xe330a81a.toInt(), 0x115b2b19, 0x020bd8ed, 0xf0605bee.toInt(),
            0x24aa3f05, 0xd6c1bc06.toInt(), 0xc5914ff2.toInt(), 0x37faccf1,
            0x69e9f0d5, 0x9b8273d6.toInt(), 0x88d28022.toInt(), 0x7ab90321,
            0xae7367ca.toInt(), 0x5c18e4c9, 0x4f48173d, 0xbd23943e.toInt(),
            0xf36e6f75.toInt(), 0x0105ec76, 0x12551f82, 0xe03e9c81.toInt(),
            0x34f4f86a, 0xc69f7b69.toInt(), 0xd5cf889d.toInt(), 0x27a40b9e,
            0x79b737ba, 0x8bdcb4b9.toInt(), 0x988c474d.toInt(), 0x6ae7c44e,
            0xbe2da0a5.toInt(), 0x4c4623a6, 0x5f16d052, 0xad7d5351.toInt(),
        )
    }
}
