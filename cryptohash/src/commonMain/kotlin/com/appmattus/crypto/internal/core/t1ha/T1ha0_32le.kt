package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.bytes.ByteBuffer
import com.appmattus.crypto.internal.core.encodeBELong

@Suppress("ClassName")
internal class T1ha0_32le(private val seed: ULong = 0u) : T1haBase<T1ha0_32le>() {

    private var hash: ULong = 0u

    override val digestLength = 8

    override val blockLength = 8

    override fun process(input: ByteBuffer, offset: Int, length: Int) {
        hash = t1ha0_32(input, seed)
    }

    override fun digest(): ByteArray {
        val digest = ByteArray(digestLength)
        encodeBELong(hash.toLong(), digest, 0)

        reset()

        return digest
    }

    override fun copy(): T1ha0_32le {
        return copyState(T1ha0_32le().apply {
            hash = this@T1ha0_32le.hash
        })
    }

    override fun toString() = "t1ha0_32le"
}
