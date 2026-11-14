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
package com.appmattus.crypto.internal.cityhash

import com.appmattus.crypto.internal.bytes.ByteBuffer

internal actual fun naHash64Over64(s: ByteBuffer): ULong = naHash64Over64Long(s)

internal actual fun uoHash64Over64(s: ByteBuffer, seed0: ULong, seed1: ULong): ULong = uoHash64Over64Long(s, seed0, seed1)
