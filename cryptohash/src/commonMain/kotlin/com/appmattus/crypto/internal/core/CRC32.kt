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
internal class CRC32 : Digest<CRC32> {

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

    override fun copy(): CRC32 {
        return CRC32().also {
            it.checksum = checksum
        }
    }

    override val blockLength: Int
        get() = Algorithm.CRC32.blockLength

    override fun toString() = Algorithm.CRC32.algorithmName

    companion object {

        /** The fast CRC table. Computed once when the CRC32 class is loaded.  */
        private val crcTable = intArrayOf(
            0x00000000, 0x77073096, -0x11f19ed4, -0x66f6ae46,
            0x076dc419, 0x706af48f, -0x169c5acb, -0x619b6a5d,
            0x0edb8832, 0x79dcb8a4, -0x1f2a16e2, -0x682d2678,
            0x09b64c2b, 0x7eb17cbd, -0x1847d2f9, -0x6f40e26f,
            0x1db71064, 0x6ab020f2, -0xc468eb8, -0x7b41be22,
            0x1adad47d, 0x6ddde4eb, -0xb2b4aaf, -0x7c2c7a39,
            0x136c9856, 0x646ba8c0, -0x29d0686, -0x759a3614,
            0x14015c4f, 0x63066cd9, -0x5f0c29d, -0x72f7f20b,
            0x3b6e20c8, 0x4c69105e, -0x2a9fbe1c, -0x5d988e8e,
            0x3c03e4d1, 0x4b04d447, -0x2df27a03, -0x5af54a95,
            0x35b5a8fa, 0x42b2986c, -0x2444362a, -0x534306c0,
            0x32d86ce3, 0x45df5c75, -0x2329f231, -0x542ec2a7,
            0x26d930ac, 0x51de003a, -0x3728ae80, -0x402f9eea,
            0x21b4f4b5, 0x56b3c423, -0x30456a67, -0x47425af1,
            0x2802b89e, 0x5f058808, -0x39f3264e, -0x4ef416dc,
            0x2f6f7c87, 0x58684c11, -0x3e9ee255, -0x4999d2c3,
            0x76dc4190, 0x01db7106, -0x672ddf44, -0x102aefd6,
            0x71b18589, 0x06b6b51f, -0x60401b5b, -0x17472bcd,
            0x7807c9a2, 0x0f00f934, -0x69f65772, -0x1ef167e8,
            0x7f6a0dbb, 0x086d3d2d, -0x6e9b9369, -0x199ca3ff,
            0x6b6b51f4, 0x1c6c6162, -0x7a9acf28, -0xd9dffb2,
            0x6c0695ed, 0x1b01a57b, -0x7df70b3f, -0xaf03ba9,
            0x65b0d9c6, 0x12b7e950, -0x74414716, -0x3467784,
            0x62dd1ddf, 0x15da2d49, -0x732c830d, -0x42bb39b,
            0x4db26158, 0x3ab551ce, -0x5c43ff8c, -0x2b44cf1e,
            0x4adfa541, 0x3dd895d7, -0x5b2e3b93, -0x2c290b05,
            0x4369e96a, 0x346ed9fc, -0x529877ba, -0x259f4730,
            0x44042d73, 0x33031de5, -0x55f5b3a1, -0x22f28337,
            0x5005713c, 0x270241aa, -0x41f4eff0, -0x36f3df7a,
            0x5768b525, 0x206f85b3, -0x46992bf7, -0x319e1b61,
            0x5edef90e, 0x29d9c998, -0x4f2f67de, -0x3828574c,
            0x59b33d17, 0x2eb40d81, -0x4842a3c5, -0x3f459353,
            -0x12477ce0, -0x65404c4a, 0x03b6e20c, 0x74b1d29a,
            -0x152ab8c7, -0x622d8851, 0x04db2615, 0x73dc1683,
            -0x1c9cf4ee, -0x6b9bc47c, 0x0d6d6a3e, 0x7a6a5aa8,
            -0x1bf130f5, -0x6cf60063, 0x0a00ae27, 0x7d079eb1,
            -0xff06cbc, -0x78f75c2e, 0x1e01f268, 0x6906c2fe,
            -0x89da8a3, -0x7f9a9835, 0x196c3671, 0x6e6b06e7,
            -0x12be48a, -0x762cd420, 0x10da7a5a, 0x67dd4acc,
            -0x6462091, -0x71411007, 0x17b7be43, 0x60b08ed5,
            -0x29295c18, -0x5e2e6c82, 0x38d8c2c4, 0x4fdff252,
            -0x2e44980f, -0x5943a899, 0x3fb506dd, 0x48b2364b,
            -0x27f2d426, -0x50f5e4b4, 0x36034af6, 0x41047a60,
            -0x209f103d, -0x579820ab, 0x316e8eef, 0x4669be79,
            -0x349e4c74, -0x43997ce6, 0x256fd2a0, 0x5268e236,
            -0x33f3886b, -0x44f4b8fd, 0x220216b9, 0x5505262f,
            -0x3a45c442, -0x4d42f4d8, 0x2bb45a92, 0x5cb36a04,
            -0x3d280059, -0x4a2f30cf, 0x2cd99e8b, 0x5bdeae1d,
            -0x649b3d50, -0x139c0dda, 0x756aa39c, 0x026d930a,
            -0x63f6f957, -0x14f1c9c1, 0x72076785, 0x05005713,
            -0x6a40b57e, -0x1d4785ec, 0x7bb12bae, 0x0cb61b38,
            -0x6d2d7165, -0x1a2a41f3, 0x7cdcefb7, 0x0bdbdf21,
            -0x792c2d2c, -0xe2b1dbe, 0x68ddb3f8, 0x1fda836e,
            -0x7e41e933, -0x946d9a5, 0x6fb077e1, 0x18b74777,
            -0x77f7a51a, -0xf09590, 0x66063bca, 0x11010b5c,
            -0x709a6101, -0x79d5197, 0x616bffd3, 0x166ccf45,
            -0x5ff51d88, -0x28f22d12, 0x4e048354, 0x3903b3c2,
            -0x5898d99f, -0x2f9fe909, 0x4969474d, 0x3e6e77db,
            -0x512e95b6, -0x2629a524, 0x40df0b66, 0x37d83bf0,
            -0x564351ad, -0x2144613b, 0x47b2cf7f, 0x30b5ffe9,
            -0x42420de4, -0x35453d76, 0x53b39330, 0x24b4a3a6,
            -0x452fc9fb, -0x3228f96d, 0x54de5729, 0x23d967bf,
            -0x4c9985d2, -0x3b9eb548, 0x5d681b02, 0x2a6f2b94,
            -0x4bf441c9, -0x3cf3715f, 0x5a05df1b, 0x2d02ef8d
        )
    }
}
