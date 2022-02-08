/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.core.murmur

import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class MurmurHash1Test {

    private fun digest(seed: UInt = 0u) = MurmurHash1(seed)

    @Test
    fun basic() {
        // From https://github.com/kougazhang/go-murmurhash/blob/master/test/001_test.go
        testKat({ digest(0x12345678u) }, "foo", "7BD65BCC")
        testKat({ digest(0x12345678u) }, "foofoo", "89573450")
        testKat({ digest(0x12345678u) }, "foofoofoofoofoofoofoofoo", "2FC38613")
    }

    @Test
    fun generated() {
        testKat({ digest(0u) }, "a", "872d28c5")
        testKat({ digest(123u) }, "a", "35a51670")
        testKat({ digest(0u) }, "abc", "64e49844")
        testKat({ digest(123u) }, "abc", "1cbec1bc")
        testKat({ digest(0u) }, "The quick brown fox jumps over the lazy dog", "1a251e85")
        testKat({ digest(123u) }, "The quick brown fox jumps over the lazy dog", "21e94ee0")
    }
}
