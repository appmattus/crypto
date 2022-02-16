package com.appmattus.crypto.internal.core.farm

object FarmHashTest {
    const val k0: ULong = 0xc3a5c85c97cb3127UL
    const val kSeed0: ULong = 1234567u
    const val kSeed1: ULong = k0

    // 1048576
    const val kDataSize: Int = 1 shl 20
    const val kTestSize: Int = 300

    val data: ByteArray = ByteArray(kDataSize)

    init {
        var a: ULong = 9u
        var b: ULong = 777u
        for (i in 0 until kDataSize) {
            a += b
            b += a
            a = (a xor (a shr 41)) * k0
            b = (b xor (b shr 41)) * k0 + i.toUInt()
            val u: Byte = (b shr 37).toByte()
            data[i] = u
        }
    }
}
