/*
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Translation to Kotlin:
 *
 * Copyright 2021-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.whirlpool

import com.appmattus.crypto.internal.core.decodeLELong

/**
 * Processes one 64-byte block of [data] into the eight-word [state], with the eight 256-entry [tables] and the round
 * constants [rc] of one of the Whirlpool variants.
 *
 * Kotlin/JS has its own implementation, as its [Long] is an object and allocates on every operation.
 */
internal expect fun whirlpoolProcessBlock(state: LongArray, data: ByteArray, tables: Array<LongArray>, rc: LongArray)

/**
 * The [Long] implementation of [whirlpoolProcessBlock], for platforms whose [Long] is a 64-bit machine integer
 */
@Suppress("JoinDeclarationAndAssignment", "LongMethod")
internal fun whirlpoolProcessBlockLong(state: LongArray, data: ByteArray, tables: Array<LongArray>, rc: LongArray) {
    val tab0 = tables[0]
    val tab1 = tables[1]
    val tab2 = tables[2]
    val tab3 = tables[3]
    val tab4 = tables[4]
    val tab5 = tables[5]
    val tab6 = tables[6]
    val tab7 = tables[7]
    var n0 = decodeLELong(data, 0)
    val sn0 = n0
    var n1 = decodeLELong(data, 8)
    val sn1 = n1
    var n2 = decodeLELong(data, 16)
    val sn2 = n2
    var n3 = decodeLELong(data, 24)
    val sn3 = n3
    var n4 = decodeLELong(data, 32)
    val sn4 = n4
    var n5 = decodeLELong(data, 40)
    val sn5 = n5
    var n6 = decodeLELong(data, 48)
    val sn6 = n6
    var n7 = decodeLELong(data, 56)
    val sn7 = n7
    var h0 = state[0]
    var h1 = state[1]
    var h2 = state[2]
    var h3 = state[3]
    var h4 = state[4]
    var h5 = state[5]
    var h6 = state[6]
    var h7 = state[7]
    var r: Int
    n0 = n0 xor h0
    n1 = n1 xor h1
    n2 = n2 xor h2
    n3 = n3 xor h3
    n4 = n4 xor h4
    n5 = n5 xor h5
    n6 = n6 xor h6
    n7 = n7 xor h7
    r = 0
    while (r < 10) {
        var t0: Long
        var t1: Long
        var t2: Long
        var t3: Long
        var t4: Long
        var t5: Long
        var t6: Long
        var t7: Long
        t0 = tab0[h0.toInt() and 0xFF] xor
                tab1[h7.toInt() shr 8 and 0xFF] xor
                tab2[h6.toInt() shr 16 and 0xFF] xor
                tab3[h5.toInt() shr 24 and 0xFF] xor
                tab4[(h4 shr 32).toInt() and 0xFF] xor
                tab5[(h3 shr 40).toInt() and 0xFF] xor
                tab6[(h2 shr 48).toInt() and 0xFF] xor
                tab7[(h1 shr 56).toInt() and 0xFF] xor
                rc[r]
        t1 = tab0[h1.toInt() and 0xFF] xor
                tab1[h0.toInt() shr 8 and 0xFF] xor
                tab2[h7.toInt() shr 16 and 0xFF] xor
                tab3[h6.toInt() shr 24 and 0xFF] xor
                tab4[(h5 shr 32).toInt() and 0xFF] xor
                tab5[(h4 shr 40).toInt() and 0xFF] xor
                tab6[(h3 shr 48).toInt() and 0xFF] xor
                tab7[(h2 shr 56).toInt() and 0xFF]
        t2 = tab0[h2.toInt() and 0xFF] xor
                tab1[h1.toInt() shr 8 and 0xFF] xor
                tab2[h0.toInt() shr 16 and 0xFF] xor
                tab3[h7.toInt() shr 24 and 0xFF] xor
                tab4[(h6 shr 32).toInt() and 0xFF] xor
                tab5[(h5 shr 40).toInt() and 0xFF] xor
                tab6[(h4 shr 48).toInt() and 0xFF] xor
                tab7[(h3 shr 56).toInt() and 0xFF]
        t3 = tab0[h3.toInt() and 0xFF] xor
                tab1[h2.toInt() shr 8 and 0xFF] xor
                tab2[h1.toInt() shr 16 and 0xFF] xor
                tab3[h0.toInt() shr 24 and 0xFF] xor
                tab4[(h7 shr 32).toInt() and 0xFF] xor
                tab5[(h6 shr 40).toInt() and 0xFF] xor
                tab6[(h5 shr 48).toInt() and 0xFF] xor
                tab7[(h4 shr 56).toInt() and 0xFF]
        t4 = tab0[h4.toInt() and 0xFF] xor
                tab1[h3.toInt() shr 8 and 0xFF] xor
                tab2[h2.toInt() shr 16 and 0xFF] xor
                tab3[h1.toInt() shr 24 and 0xFF] xor
                tab4[(h0 shr 32).toInt() and 0xFF] xor
                tab5[(h7 shr 40).toInt() and 0xFF] xor
                tab6[(h6 shr 48).toInt() and 0xFF] xor
                tab7[(h5 shr 56).toInt() and 0xFF]
        t5 = tab0[h5.toInt() and 0xFF] xor
                tab1[h4.toInt() shr 8 and 0xFF] xor
                tab2[h3.toInt() shr 16 and 0xFF] xor
                tab3[h2.toInt() shr 24 and 0xFF] xor
                tab4[(h1 shr 32).toInt() and 0xFF] xor
                tab5[(h0 shr 40).toInt() and 0xFF] xor
                tab6[(h7 shr 48).toInt() and 0xFF] xor
                tab7[(h6 shr 56).toInt() and 0xFF]
        t6 = tab0[h6.toInt() and 0xFF] xor
                tab1[h5.toInt() shr 8 and 0xFF] xor
                tab2[h4.toInt() shr 16 and 0xFF] xor
                tab3[h3.toInt() shr 24 and 0xFF] xor
                tab4[(h2 shr 32).toInt() and 0xFF] xor
                tab5[(h1 shr 40).toInt() and 0xFF] xor
                tab6[(h0 shr 48).toInt() and 0xFF] xor
                tab7[(h7 shr 56).toInt() and 0xFF]
        t7 = tab0[h7.toInt() and 0xFF] xor
                tab1[h6.toInt() shr 8 and 0xFF] xor
                tab2[h5.toInt() shr 16 and 0xFF] xor
                tab3[h4.toInt() shr 24 and 0xFF] xor
                tab4[(h3 shr 32).toInt() and 0xFF] xor
                tab5[(h2 shr 40).toInt() and 0xFF] xor
                tab6[(h1 shr 48).toInt() and 0xFF] xor
                tab7[(h0 shr 56).toInt() and 0xFF]
        h0 = t0
        h1 = t1
        h2 = t2
        h3 = t3
        h4 = t4
        h5 = t5
        h6 = t6
        h7 = t7
        t0 = tab0[n0.toInt() and 0xFF] xor
                tab1[n7.toInt() shr 8 and 0xFF] xor
                tab2[n6.toInt() shr 16 and 0xFF] xor
                tab3[n5.toInt() shr 24 and 0xFF] xor
                tab4[(n4 shr 32).toInt() and 0xFF] xor
                tab5[(n3 shr 40).toInt() and 0xFF] xor
                tab6[(n2 shr 48).toInt() and 0xFF] xor
                tab7[(n1 shr 56).toInt() and 0xFF] xor
                h0
        t1 = tab0[n1.toInt() and 0xFF] xor
                tab1[n0.toInt() shr 8 and 0xFF] xor
                tab2[n7.toInt() shr 16 and 0xFF] xor
                tab3[n6.toInt() shr 24 and 0xFF] xor
                tab4[(n5 shr 32).toInt() and 0xFF] xor
                tab5[(n4 shr 40).toInt() and 0xFF] xor
                tab6[(n3 shr 48).toInt() and 0xFF] xor
                tab7[(n2 shr 56).toInt() and 0xFF] xor
                h1
        t2 = tab0[n2.toInt() and 0xFF] xor
                tab1[n1.toInt() shr 8 and 0xFF] xor
                tab2[n0.toInt() shr 16 and 0xFF] xor
                tab3[n7.toInt() shr 24 and 0xFF] xor
                tab4[(n6 shr 32).toInt() and 0xFF] xor
                tab5[(n5 shr 40).toInt() and 0xFF] xor
                tab6[(n4 shr 48).toInt() and 0xFF] xor
                tab7[(n3 shr 56).toInt() and 0xFF] xor
                h2
        t3 = tab0[n3.toInt() and 0xFF] xor
                tab1[n2.toInt() shr 8 and 0xFF] xor
                tab2[n1.toInt() shr 16 and 0xFF] xor
                tab3[n0.toInt() shr 24 and 0xFF] xor
                tab4[(n7 shr 32).toInt() and 0xFF] xor
                tab5[(n6 shr 40).toInt() and 0xFF] xor
                tab6[(n5 shr 48).toInt() and 0xFF] xor
                tab7[(n4 shr 56).toInt() and 0xFF] xor
                h3
        t4 = tab0[n4.toInt() and 0xFF] xor
                tab1[n3.toInt() shr 8 and 0xFF] xor
                tab2[n2.toInt() shr 16 and 0xFF] xor
                tab3[n1.toInt() shr 24 and 0xFF] xor
                tab4[(n0 shr 32).toInt() and 0xFF] xor
                tab5[(n7 shr 40).toInt() and 0xFF] xor
                tab6[(n6 shr 48).toInt() and 0xFF] xor
                tab7[(n5 shr 56).toInt() and 0xFF] xor
                h4
        t5 = tab0[n5.toInt() and 0xFF] xor
                tab1[n4.toInt() shr 8 and 0xFF] xor
                tab2[n3.toInt() shr 16 and 0xFF] xor
                tab3[n2.toInt() shr 24 and 0xFF] xor
                tab4[(n1 shr 32).toInt() and 0xFF] xor
                tab5[(n0 shr 40).toInt() and 0xFF] xor
                tab6[(n7 shr 48).toInt() and 0xFF] xor
                tab7[(n6 shr 56).toInt() and 0xFF] xor
                h5
        t6 = tab0[n6.toInt() and 0xFF] xor
                tab1[n5.toInt() shr 8 and 0xFF] xor
                tab2[n4.toInt() shr 16 and 0xFF] xor
                tab3[n3.toInt() shr 24 and 0xFF] xor
                tab4[(n2 shr 32).toInt() and 0xFF] xor
                tab5[(n1 shr 40).toInt() and 0xFF] xor
                tab6[(n0 shr 48).toInt() and 0xFF] xor
                tab7[(n7 shr 56).toInt() and 0xFF] xor
                h6
        t7 = tab0[n7.toInt() and 0xFF] xor
                tab1[n6.toInt() shr 8 and 0xFF] xor
                tab2[n5.toInt() shr 16 and 0xFF] xor
                tab3[n4.toInt() shr 24 and 0xFF] xor
                tab4[(n3 shr 32).toInt() and 0xFF] xor
                tab5[(n2 shr 40).toInt() and 0xFF] xor
                tab6[(n1 shr 48).toInt() and 0xFF] xor
                tab7[(n0 shr 56).toInt() and 0xFF] xor
                h7
        n0 = t0
        n1 = t1
        n2 = t2
        n3 = t3
        n4 = t4
        n5 = t5
        n6 = t6
        n7 = t7
        r++
    }
    state[0] = state[0] xor (n0 xor sn0)
    state[1] = state[1] xor (n1 xor sn1)
    state[2] = state[2] xor (n2 xor sn2)
    state[3] = state[3] xor (n3 xor sn3)
    state[4] = state[4] xor (n4 xor sn4)
    state[5] = state[5] xor (n5 xor sn5)
    state[6] = state[6] xor (n6 xor sn6)
    state[7] = state[7] xor (n7 xor sn7)
}
