package com.appmattus.crypto.internal.core.metro

import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.decodeLEShort
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.crypto.internal.core.encodeLELong
import com.appmattus.crypto.internal.core.sphlib.DigestEngine

internal class MetroHash64(private val seed: ULong) : DigestEngine<MetroHash64>() {

    private var h = (seed + k2) * k0

    private var v: Array<ULong> = Array(4) { h }

    private var hasBlock = false

    override val digestLength: Int
        get() = 8

    override fun copy(): MetroHash64 {
        val dest = MetroHash64(seed).apply {
            h = this@MetroHash64.h
            v = this@MetroHash64.v.copyOf()
            hasBlock = this@MetroHash64.hasBlock
        }
        return copyState(dest)
    }

    override val blockLength: Int
        get() = 32

    override fun toString() = "MetroHash64"

    override fun engineReset() {
        h = (seed + k2) * k0

        v[0] = h
        v[1] = h
        v[2] = h
        v[3] = h
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
            v[2] = v[2] xor ((v[0] + v[3]) * k0 + v[1]).rotateRight(37) * k1
            v[3] = v[3] xor ((v[1] + v[2]) * k1 + v[0]).rotateRight(37) * k0
            v[0] = v[0] xor ((v[0] + v[2]) * k0 + v[3]).rotateRight(37) * k1
            v[1] = v[1] xor ((v[1] + v[3]) * k1 + v[2]).rotateRight(37) * k0
            h += v[0] xor v[1]
        }

        var ptr = 0
        if (end - ptr >= 16) {
            var v0 = h + decodeLELong(blockBuffer, ptr).toULong() * k2
            ptr += 8
            v0 = v0.rotateRight(29) * k3

            var v1 = h + decodeLELong(blockBuffer, ptr).toULong() * k2
            ptr += 8
            v1 = v1.rotateRight(29) * k3

            v0 = v0 xor (v0 * k0).rotateRight(21) + v1
            v1 = v1 xor (v1 * k3).rotateRight(21) + v0
            h += v1
        }

        if (end - ptr >= 8) {
            h += decodeLELong(blockBuffer, ptr).toULong() * k3
            ptr += 8

            h = h xor h.rotateRight(55) * k1
        }

        if (end - ptr >= 4) {
            h += decodeLEInt(blockBuffer, ptr).toULong() * k3
            ptr += 4

            h = h xor h.rotateRight(26) * k1
        }

        if (end - ptr >= 2) {
            h += blockBuffer.decodeLEShort(ptr).toULong() * k3
            ptr += 2
            h = h xor h.rotateRight(48) * k1
        }

        if (end - ptr >= 1) {
            h += (blockBuffer[ptr].toULong() and 0xffuL) * k3
            h = h xor h.rotateRight(37) * k1
        }

        h = h xor h.rotateRight(28)
        h *= k0
        h = h xor h.rotateRight(29)

        encodeLELong(h.toLong(), output, outputOffset)
    }

    override fun doInit() = Unit

    companion object {
        private const val k0: ULong = 0xD6D018F5u
        private const val k1: ULong = 0xA2AA033Bu
        private const val k2: ULong = 0x62992FC1u
        private const val k3: ULong = 0x30BC5B29u
    }
}
