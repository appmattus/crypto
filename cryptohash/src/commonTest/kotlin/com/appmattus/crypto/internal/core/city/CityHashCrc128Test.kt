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

package com.appmattus.crypto.internal.core.city

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat

internal class CityHashCrc128Test : CityHashTest() {

    override fun baseTest(expected: Expected, bytes: ByteArray) {
        testKat({ Algorithm.CityHashCrc128().createDigest() }, bytes, expected.hashCrc128)

        testKat({ Algorithm.CityHashCrc128.Seed(kSeed0, kSeed1).createDigest() }, bytes, expected.hashCrc128WithSeed)
    }
}
