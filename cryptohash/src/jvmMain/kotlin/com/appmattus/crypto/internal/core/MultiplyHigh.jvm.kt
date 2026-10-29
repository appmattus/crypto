/*
 * Copyright 2026 Appmattus Limited
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

package com.appmattus.crypto.internal.core

/**
 * HotSpot compiles [Math.multiplyHigh] to a single instruction (imul on x86-64, smulh on arm64). It treats its
 * arguments as signed, so the result is corrected for arguments with their top bit set, as Java 18's
 * `Math.unsignedMultiplyHigh` does.
 */
internal actual fun multiplyHigh(a: ULong, b: ULong): ULong {
    if (!hasMultiplyHigh) return multiplyHighPortable(a, b)
    val x = a.toLong()
    val y = b.toLong()
    return (Math.multiplyHigh(x, y) + ((x shr 63) and y) + ((y shr 63) and x)).toULong()
}

/**
 * [Math.multiplyHigh] is Java 9 and Android API 31. Being a static final, the JIT folds this check away.
 */
@Suppress("SwallowedException")
private val hasMultiplyHigh: Boolean = try {
    Math.multiplyHigh(1L, 1L)
    true
} catch (e: NoSuchMethodError) {
    false
}
