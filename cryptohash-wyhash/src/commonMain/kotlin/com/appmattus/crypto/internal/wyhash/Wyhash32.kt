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

package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalHasher
import com.appmattus.crypto.internal.core.encodeBEInt

/**
 * A [Hasher] for 32-bit [wyhash](https://github.com/wangyi-fudan/wyhash), which can only hash its whole input at once
 */
internal fun wyhash32Hasher(seed: UInt): Hasher = NonIncrementalHasher("wyhash32", 4) { input ->
    ByteArray(4).apply {
        encodeBEInt(wyhash32(seed, input).toInt(), this, 0)
    }
}

/**
 * 32-bit [wyhash](https://github.com/wangyi-fudan/wyhash) of all of [input]
 */
internal fun wyhash32(seed: UInt, input: ByteBuffer): UInt {
    val len = input.size

    var p = 0
    var i = len

    var see1: UInt = len.toUInt()
    @Suppress("NAME_SHADOWING")
    var seed = seed

    var c: ULong = seed.toULong() xor 0x53c5ca59u
    c *= see1.toULong() xor 0x74743c1bu
    seed = c.toUInt()
    see1 = (c shr 32).toUInt()

    while (i > 8) {
        seed = seed xor input.decodeLEUInt(p)
        see1 = see1 xor input.decodeLEUInt(p + 4)

        c = seed.toULong() xor 0x53c5ca59u
        c *= see1.toULong() xor 0x74743c1bu
        seed = c.toUInt()
        see1 = (c shr 32).toUInt()

        i -= 8
        p += 8
    }

    if (i >= 4) {
        seed = seed xor input.decodeLEUInt(p)
        see1 = see1 xor input.decodeLEUInt(p + i - 4)
    } else if (i != 0) {
        seed = seed xor wyr24(input, p, i)
    }

    // _wymix32(&seed, &see1)
    c = seed.toULong() xor 0x53c5ca59u
    c *= see1.toULong() xor 0x74743c1bu
    seed = c.toUInt()
    see1 = (c shr 32).toUInt()

    // _wymix32(&seed, &see1)
    c = seed.toULong() xor 0x53c5ca59u
    c *= see1.toULong() xor 0x74743c1bu
    seed = c.toUInt()
    see1 = (c shr 32).toUInt()

    return seed xor see1
}

private fun wyr24(data: ByteBuffer, p: Int, k: Int): UInt {
    return (data[p].toUInt() and 0xffu shl 16) or
            (data[p + (k ushr 1)].toUInt() and 0xffu shl 8) or
            (data[p + k - 1].toUInt() and 0xffu)
}
