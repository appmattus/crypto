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

package com.appmattus.crypto.internal.core.metro

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.decodeLEShort
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.sphlib.DigestEngine

internal class MetroHash128(private val seed: ULong) : DigestEngine<MetroHash128>() {

    private var v: Array<ULong> = arrayOf(
        (seed - k0) * k3,
        (seed + k1) * k2,
        (seed + k0) * k2,
        (seed - k1) * k3
    )

    private var hasBlock = false

    override val digestLength: Int
        get() = 16

    override fun copy(): MetroHash128 {
        val dest = MetroHash128(seed).apply {
            v = this@MetroHash128.v.copyOf()
            hasBlock = this@MetroHash128.hasBlock
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 32

    override fun toString() = "MetroHash128"

    override fun engineReset() {
        v = arrayOf(
            (seed - k0) * k3,
            (seed + k1) * k2,
            (seed + k0) * k2,
            (seed - k1) * k3
        )
    }

    fun ByteArray.toHexString(): String {
        return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
    }

    fun Long.toHexString(): String = ByteArray(8).also {
        encodeBELong(this, it, 0)
    }.toHexString()

    fun ULong.toHexString(): String = toLong().toHexString()

    override fun processBlock(data: ByteArray) {
        hasBlock = true

        v[0] += decodeLELong(data, 0).toULong() * k0
        v[0] = v[0].rotateRight(29) + v[2]

        v[1] += decodeLELong(data, 8).toULong() * k1
        v[1] = v[1].rotateRight(29) + v[3]

        v[2] += decodeLELong(data, 16).toULong() * k2
        v[2] = v[2].rotateRight(29) + v[0]

        v[3] += decodeLELong(data, 24).toULong() * k3
        v[3] = v[3].rotateRight(29) + v[1]
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val end = flush()

        if (hasBlock) {
            v[2] = v[2] xor ((v[0] + v[3]) * k0 + v[1]).rotateRight(21) * k1
            v[3] = v[3] xor ((v[1] + v[2]) * k1 + v[0]).rotateRight(21) * k0
            v[0] = v[0] xor ((v[0] + v[2]) * k0 + v[3]).rotateRight(21) * k1
            v[1] = v[1] xor ((v[1] + v[3]) * k1 + v[2]).rotateRight(21) * k0
        }

        var ptr = 0
        if (end - ptr >= 16) {
            v[0] += decodeLELong(blockBuffer, ptr).toULong() * k2
            ptr += 8
            v[0] = v[0].rotateRight(33) * k3

            v[1] += decodeLELong(blockBuffer, ptr).toULong() * k2
            ptr += 8
            v[1] = v[1].rotateRight(33) * k3

            v[0] = v[0] xor (v[0] * k2 + v[1]).rotateRight(45) * k1
            v[1] = v[1] xor (v[1] * k3 + v[0]).rotateRight(45) * k0
        }

        if (end - ptr >= 8) {
            v[0] += decodeLELong(blockBuffer, ptr).toULong() * k2
            ptr += 8
            v[0] = v[0].rotateRight(33) * k3
            v[0] = v[0] xor (v[0] * k2 + v[1]).rotateRight(27) * k1
        }

        if (end - ptr >= 4) {
            v[1] += decodeLEInt(blockBuffer, ptr).toULong() * k2
            ptr += 4
            v[1] = v[1].rotateRight(33) * k3
            v[1] = v[1] xor (v[1] * k3 + v[0]).rotateRight(46) * k0
        }

        if (end - ptr >= 2) {
            v[0] += blockBuffer.decodeLEShort(ptr).toULong() * k2
            ptr += 2
            v[0] = v[0].rotateRight(33) * k3
            v[0] = v[0] xor (v[0] * k2 + v[1]).rotateRight(22) * k1
        }

        if (end - ptr >= 1) {
            v[1] += (blockBuffer[ptr].toULong() and 0xffuL) * k2
            v[1] = v[1].rotateRight(33) * k3
            v[1] = v[1] xor (v[1] * k3 + v[0]).rotateRight(58) * k0
        }

        v[0] += ((v[0] * k0) + v[1]).rotateRight(13)
        v[1] += ((v[1] * k1) + v[0]).rotateRight(37)
        v[0] += ((v[0] * k2) + v[1]).rotateRight(13)
        v[1] += ((v[1] * k3) + v[0]).rotateRight(37)

        encodeBELong(v[1].toLong(), output, outputOffset)
        encodeBELong(v[0].toLong(), output, outputOffset + 8)
    }

    override fun doInit() = Unit

    companion object {
        private const val k0: ULong = 0xC83A91E1u
        private const val k1: ULong = 0x8648DBDBu
        private const val k2: ULong = 0x7BDEC03Bu
        private const val k3: ULong = 0x2F5870A5u
    }
}
