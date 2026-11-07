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

/*
 * Inline replacements for the standard library's Int and UInt rotates.
 *
 * Kotlin/JS compiles kotlin.rotateLeft to a separate stdlib function, and Hermes, which interprets bytecode rather
 * than JIT-compiling it, pays the full cost of a call each time. The stdlib exports the function, so not even
 * hermesc -O -finline inlines it. Hashes such as SHA-256 rotate hundreds of times per block, and the calls were
 * over 40% of SHA-256's time on Hermes.
 *
 * These are inline, so the compiler expands them at every call site on every platform. On the JVM and Kotlin/Native
 * the shift-or pattern compiles to the same single rotate instruction as the stdlib's.
 *
 * They're declared in this package with the stdlib's names, so they take precedence over the default imports: files
 * in this package use them automatically, and files in other packages through an explicit import. Long rotates
 * still resolve to the stdlib, whose Kotlin/JS version builds its result with a single allocation.
 *
 * Shifts use the bit count modulo 32 on every platform, so these match the stdlib for any bit count.
 */

/** Rotates left by [bitCount] bits, as [kotlin.rotateLeft] does, but expanded inline */
@Suppress("NOTHING_TO_INLINE", "MagicNumber")
internal inline fun Int.rotateLeft(bitCount: Int): Int = (this shl bitCount) or (this ushr (32 - bitCount))

/** Rotates right by [bitCount] bits, as [kotlin.rotateRight] does, but expanded inline */
@Suppress("NOTHING_TO_INLINE", "MagicNumber")
internal inline fun Int.rotateRight(bitCount: Int): Int = (this ushr bitCount) or (this shl (32 - bitCount))

/** Rotates left by [bitCount] bits, as [kotlin.rotateLeft] does, but expanded inline */
@Suppress("NOTHING_TO_INLINE")
internal inline fun UInt.rotateLeft(bitCount: Int): UInt = toInt().rotateLeft(bitCount).toUInt()

/** Rotates right by [bitCount] bits, as [kotlin.rotateRight] does, but expanded inline */
@Suppress("NOTHING_TO_INLINE")
internal inline fun UInt.rotateRight(bitCount: Int): UInt = toInt().rotateRight(bitCount).toUInt()
