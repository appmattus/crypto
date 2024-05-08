package com.appmattus.crypto.internal.core.t1ha

import kotlin.test.Test
import kotlin.test.assertEquals

class UInt64Test {

    data class UInt64(val high: UInt, val low: UInt) : Comparable<UInt64> {

        operator fun plus(x: UInt64): UInt64 = UInt64(
            high + x.high + if (low > UInt.MAX_VALUE - x.low) 1u else 0u,
            low + x.low
        )

        operator fun minus(x: UInt64): UInt64 = UInt64(
            high - x.high - if (low - x.low > low) 1u else 0u,
            low - x.low
        )

        operator fun times(multiplicand: UInt64): UInt64 {
            val top: List<UInt> = listOf(
                (high shr UShort.SIZE_BITS).toUShort().toUInt(),
                high.toUShort().toUInt(),
                (low shr UShort.SIZE_BITS).toUShort().toUInt(),
                low.toUShort().toUInt(),
            )

            val bottom: List<UInt> = listOf(
                (multiplicand.high shr UShort.SIZE_BITS).toUShort().toUInt(),
                multiplicand.high.toUShort().toUInt(),
                (multiplicand.low shr UShort.SIZE_BITS).toUShort().toUInt(),
                multiplicand.low.toUShort().toUInt(),
            )

            val products: MutableList<MutableList<UInt>> = MutableList(4) { MutableList(4) { 0u } }

            // multiply each component of the values
            for (y in 3 downTo 0) {
                for (x in 3 downTo 0) {
                    products[3 - x][y] = top[x] * bottom[y]
                }
            }

            // first row
            var fourth32: UInt = products[0][3] and 0xffffu
            var third32: UInt = (products[0][2] and 0xffffu) + (products[0][3] shr 16)
            var second32: UInt = (products[0][1] and 0xffffu) + (products[0][2] shr 16)
            var first32: UInt = (products[0][0] and 0xffffu) + (products[0][1] shr 16)

            // second row
            third32 += (products[1][3] and 0xffffu)
            second32 += (products[1][2] and 0xffffu) + (products[1][3] shr 16)
            first32 += (products[1][1] and 0xffffu) + (products[1][2] shr 16)

            // third row
            second32 += (products[2][3] and 0xffffu)
            first32 += (products[2][2] and 0xffffu) + (products[2][3] shr 16)

            // fourth row
            first32 += (products[3][3] and 0xffffu)

            // move carry to next digit
            third32 += fourth32 shr 16
            second32 += third32 shr 16
            first32 += second32 shr 16

            // remove carry from current digit
            fourth32 = fourth32 and 0xffffu
            third32 = third32 and 0xffffu
            second32 = second32 and 0xffffu
            first32 = first32 and 0xffffu

            return UInt64(first32 shl 16 or second32, third32 shl 16 or fourth32)
        }

        operator fun div(rhs: UInt64): UInt64 {
            return divmod(this, rhs).first
        }

        operator fun rem(rhs: UInt64): UInt64 {
            return divmod(this, rhs).second
        }

        @Suppress("ReturnCount")
        private fun divmod(lhs: UInt64, rhs: UInt64): Pair<UInt64, UInt64> {
            // Save some calculations /////////////////////
            if (rhs == UInt64(0u, 0u)) {
                error("Error: division or modulus by 0")
            } else if (rhs == UInt64(0u, 1u)) {
                return Pair(lhs, UInt64(0u, 0u))
            } else if (lhs == rhs) {
                return Pair(UInt64(0u, 1u), UInt64(0u, 0u))
            } else if ((lhs == UInt64(0u, 0u)) || (lhs < rhs)) {
                return Pair(UInt64(0u, 0u), lhs)
            }

            var qrFirst = UInt64(0u, 0u)
            var qrSecond = UInt64(0u, 0u)
            for (x in lhs.bits() downTo 1u) {
                qrFirst = qrFirst shl 1
                qrSecond = qrSecond shl 1

                if ((lhs shr (x - 1u).toInt()) and UInt64(0u, 1u) == UInt64(0u, 1u)) {
                    ++qrSecond
                }

                if (qrSecond >= rhs) {
                    qrSecond -= rhs
                    ++qrFirst
                }
            }

            return Pair(qrFirst, qrSecond)
        }

        private fun bits(): UByte {
            var out: UByte = 0u
            if (high != 0u) {
                out = 32u
                var up = high
                while (up != 0u) {
                    up = up shr 1
                    out++
                }
            } else {
                var low = low
                while (low != 0u) {
                    low = low shr 1
                    out++
                }
            }
            return out
        }

        operator fun inc(): UInt64 {
            return this + UInt64(0u, 1u)
        }

        operator fun dec(): UInt64 {
            return this - UInt64(0u, 1u)
        }

        infix fun shr(n: Int): UInt64 {
            if (n < 0) {
                this shl -n
            }
            val r = n % 64

            return when {
                r < 32 -> UInt64(low shl 32 - n or (high shr n), low shr n)
                r >= 32 -> UInt64(low shr n % 32, 0u)
                else -> error("unreachable")
            }
        }

        infix fun shl(n: Int): UInt64 {
            if (n < 0) {
                this shr -n
            }
            val r = n % 64

            return when {
                r < 32 -> UInt64(high shl n, low shl n or (high shr 32 - n))
                r >= 32 -> UInt64(0u, high shl n % 32)
                else -> error("unreachable")
            }
        }

        infix fun xor(other: UInt64): UInt64 {
            return UInt64(high xor other.high, low xor other.low)
        }

        infix fun and(other: UInt64): UInt64 {
            return UInt64(high and other.high, low and other.low)
        }

        infix fun or(other: UInt64): UInt64 {
            return UInt64(high or other.high, low or other.low)
        }

        fun inv(): UInt64 {
            return UInt64(high.inv(), low.inv())
        }

        override fun compareTo(other: UInt64): Int {
            val h = high.compareTo(other.high)
            if (h != 0) {
                return h
            }

            return low.compareTo(other.low)
        }
    }

    @Test
    fun test() {
        assertEquals(UInt64(0u, 5u), UInt64(0u, 2u) + UInt64(0u, 3u))
    }

    @Test
    fun test2() {
        val x = UInt64(0u, UInt.MAX_VALUE)
        val y = UInt64(0u, 3u)

        assertEquals(UInt64(1u, 2u), x + y)
    }

    @Test
    fun test3() {
        val x = UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE)
        val y = UInt64(0u, 1u)

        assertEquals(UInt64(0u, 0u), x + y)
    }

    @Test
    fun testTimes() {
        assertEquals(UInt64(0u, 6u), UInt64(0u, 2u) * UInt64(0u, 3u))
        assertEquals(UInt64(0u, UInt.MAX_VALUE), UInt64(0u, UInt.MAX_VALUE) * UInt64(0u, 1u))

        assertEquals(UInt64(0u, 0u), UInt64(0u, 0u) * UInt64(0u, 1u))
        assertEquals(UInt64(0u, 0u), UInt64(0u, 1u) * UInt64(0u, 0u))
        assertEquals(UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE), UInt64(0u, 1u) * UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE))
        assertEquals(UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE), UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE) * UInt64(0u, 1u))

        assertEquals(UInt64(0u, 1u), UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE) * UInt64(UInt.MAX_VALUE, UInt.MAX_VALUE))
    }

    @Test
    fun testDivide() {
        assertEquals(UInt64(0u, 4u), UInt64(0u, 8u) / UInt64(0u, 2u))
    }
}
