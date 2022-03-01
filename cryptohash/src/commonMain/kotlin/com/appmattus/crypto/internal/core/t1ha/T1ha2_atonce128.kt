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

package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.NonIncrementalDigest
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.uint.UInt128

@Suppress("ClassName")
internal class T1ha2_atonce128(private val seed: ULong = 0u) : NonIncrementalDigest<T1ha2_atonce128>() {

    private var state = T1haState256()

    private var hashResult: UInt128 = UInt128.ZERO

    override val digestLength = 16

    override val blockLength = 32

    override fun copy(): T1ha2_atonce128 {
        return copyState(T1ha2_atonce128(seed).apply {
            state = this@T1ha2_atonce128.state.copy()
            hashResult = this@T1ha2_atonce128.hashResult
        })
    }

    override fun toString() = "t1ha2_atonce128"

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(hashResult.upper.toLong(), digest, 0)
        encodeBELong(hashResult.lower.toLong(), digest, 8)

        reset()

        return digest
    }

    override fun process(input: ByteBuffer) {
        var length = input.size

        initAB(state, seed, length.toULong())
        initCD(state, seed, length.toULong())

        var offset = 0
        if (length > 32) {
            offset = t1ha2Loop(state, input, length)
            length = length and 31
        }
        hashResult = t1ha2TailABCD(state, input, offset, length)
    }
}
