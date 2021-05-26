/*
 * Copyright 2021 Appmattus Limited
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

import platform.Foundation.NSData

public actual typealias PlatformData = NSData

internal actual fun <D : Digest<D>> Digest<D>.toPlatform(): PlatformDigest<D> = object : PlatformDigest<D> {
    override fun update(input: Byte) = this@toPlatform.update(input)
    override fun update(input: PlatformData) = this@toPlatform.update(input.toByteArray())
    override fun update(input: PlatformData, offset: Int, length: Int) = this@toPlatform.update(input.toByteArray(), offset, length)
    override fun digest(): PlatformData = this@toPlatform.digest().toData()
    override fun digest(input: PlatformData): PlatformData = this@toPlatform.digest(input.toByteArray()).toData()
    override fun digest(output: PlatformData, offset: Int, length: Int): Int = this@toPlatform.digest(output.toByteArray(), offset, length)
    override val digestLength: Int get() = this@toPlatform.digestLength
    override fun reset() = this@toPlatform.reset()
    override fun copy(): PlatformDigest<D> = this@toPlatform.copy().toPlatform()
    override val blockLength: Int get() = this@toPlatform.blockLength
    override fun toString(): String = this@toPlatform.toString()
}
