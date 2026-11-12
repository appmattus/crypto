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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.Hasher

/**
 * A CRC32B [Hasher] backed by the platform, such as `java.util.zip` on the JVM or zlib on Apple platforms, or null
 * where there's none, so the pure Kotlin [Crc32bHasher] is used
 */
internal expect fun platformCrc32b(): Hasher?

/**
 * A CRC32C [Hasher] backed by the platform, such as `java.util.zip` on the JVM, or null where there's none, so the
 * pure Kotlin [Crc32cHasher] is used
 */
internal expect fun platformCrc32c(): Hasher?
