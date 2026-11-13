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

package com.appmattus.crypto.internal.t1ha

import com.appmattus.crypto.Hasher
import com.appmattus.crypto.internal.core.NonIncrementalHasher
import com.appmattus.crypto.internal.core.encodeBELong
import com.appmattus.uint.UInt128

/**
 * A [Hasher] for [t1ha2](https://github.com/erthink/t1ha) at-once with output size of 128 bits, which can only
 * hash its whole input at once
 */
@Suppress("FunctionName")
internal fun t1ha2_atonce128Hasher(seed: ULong): Hasher =
    NonIncrementalHasher("t1ha2-atonce128", 16) { input ->
        val state = T1haState256()
        var length = input.size

        initAB(state, seed, length.toULong())
        initCD(state, seed, length.toULong())

        var offset = 0
        if (length > 32) {
            offset = t1ha2Loop(state, input, length)
            length = length and 31
        }
        val hashResult = t1ha2TailABCD(state, input, offset, length)

        ByteArray(16).apply {
            encodeBELong(hashResult.upper.toLong(), this, 0)
            encodeBELong(hashResult.lower.toLong(), this, 8)
        }
    }
