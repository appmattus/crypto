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

import com.appmattus.crypto.internal.bytes.ByteArrayArray
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.encodeLELong
import com.appmattus.crypto.internal.core.sphlib.DigestEngine

@Suppress("ClassName")
internal class T1ha2_stream128(private val seedX: ULong = 0u, private val seedY: ULong = 0u) : DigestEngine<T1ha2_stream128>() {

    private var state = T1haState256()

    init {
        initAB(state, seedX, seedY)
        initCD(state, seedX, seedY)
    }

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = 32

    override fun copy(): T1ha2_stream128 {
        return copyState(T1ha2_stream128(seedX, seedY).apply {
            state = this@T1ha2_stream128.state.copy()
        })
    }

    override fun toString() = "t1ha2_stream128"

    override fun engineReset() {
        state = T1haState256()

        initAB(state, seedX, seedY)
        initCD(state, seedX, seedY)
    }

    override fun processBlock(data: ByteArray) = t1ha2Update(state, data, 0)

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val total = ((blockCount * blockLength) + flush()).toULong()

        val bits: ULong = (total shl 3) xor (1uL shl 63)
        val bytes = ByteArray(8)
        encodeLELong(bits.toLong(), bytes, 0)

        update(bytes)

        val rem = flush()

        val hash = t1ha2TailABCD(state, ByteArrayArray().apply { add(blockBuffer) }, 0, rem)

        encodeBELong(hash.upper.toLong(), output, 0)
        encodeBELong(hash.lower.toLong(), output, 8)
    }

    override fun doInit() = Unit
}
