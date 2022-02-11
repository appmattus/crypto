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

class MurmurHash64BTest {

    @Test
    fun test() {
        // From https://github.com/flier/rust-fasthash/blob/master/fasthash/src/murmur2.rs
        testKat({ MurmurHash64B() }, "hello", "F510DB152543FD7F")
        testKat({ MurmurHash64B(123u) }, "hello", "1A231E3BFFA35245")
        testKat({ MurmurHash64B() }, "helloworld", "C2874AC105A1FB32")

        // From https://github.com/kougazhang/go-murmurhash/blob/master/test/001_test.go
        testKat({ MurmurHash64B(0x12345678u) }, "foo", "675CA96D81E32EDE")
        testKat({ MurmurHash64B(0x12345678u) }, "foofoo", "E46124BCCCC688BF")
        testKat({ MurmurHash64B(0x12345678u) }, "foofoofoofoofoofoofoofoo", "A2AAB6F3D6D635A1")
    }
}
