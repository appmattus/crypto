/*
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

package com.appmattus.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.NSMakeRange
import platform.Foundation.NSMutableData
import platform.Foundation.replaceBytesInRange

/**
 * Represents the native platforms data type for Array like data. For Darwin we are using [NSData]
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
public actual typealias PlatformData = NSData

/**
 * Represents the native platforms mutable data type for Array like data, used as an output buffer. For Darwin we
 * are using [NSMutableData]
 */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
public actual typealias MutablePlatformData = NSMutableData

/**
 * Convert this [Digest] into a platform specific [PlatformDigest]
 */
internal actual fun <D : Digest<D>> Digest<D>.toPlatform(): PlatformDigest<D> = object : PlatformDigest<D> {
    override fun update(input: Byte) = this@toPlatform.update(input)
    override fun update(input: PlatformData) = this@toPlatform.update(input.toByteArray())
    override fun update(input: PlatformData, offset: Int, length: Int) = this@toPlatform.update(input.toByteArray(), offset, length)
    override fun digest(): PlatformData = this@toPlatform.digest().toData()
    override fun digest(input: PlatformData): PlatformData = this@toPlatform.digest(input.toByteArray()).toData()
    override fun digest(output: MutablePlatformData, offset: Int, length: Int): Int = this@toPlatform.digestInto(output, offset, length)
    override val digestLength: Int get() = this@toPlatform.digestLength
    override fun reset() = this@toPlatform.reset()
    override fun copy(): PlatformDigest<D> = this@toPlatform.copy().toPlatform()
    override val blockLength: Int get() = this@toPlatform.blockLength
    override fun toString(): String = this@toPlatform.toString()
}

/**
 * Completes the digest into [output] at [offset], writing at most [length] bytes
 */
@OptIn(ExperimentalForeignApi::class)
private fun Digest<*>.digestInto(output: NSMutableData, offset: Int, length: Int): Int {
    val size = minOf(length, digestLength)
    require(offset >= 0 && size >= 0 && offset + size <= output.length.toInt()) {
        "offset $offset and length $size out of bounds for output of length ${output.length}"
    }

    val bytes = ByteArray(size)
    val written = digest(bytes, 0, size)
    if (written > 0) {
        bytes.usePinned {
            output.replaceBytesInRange(NSMakeRange(offset.convert(), written.convert()), it.addressOf(0))
        }
    }
    return written
}
