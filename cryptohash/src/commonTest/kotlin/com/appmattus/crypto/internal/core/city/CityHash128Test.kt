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
import com.appmattus.crypto.internal.core.city.CityHashTest.data
import com.appmattus.crypto.internal.core.city.CityHashTest.kSeed0
import com.appmattus.crypto.internal.core.city.CityHashTest.kSeed1
import com.appmattus.crypto.internal.core.city.CityHashTest.kTestSize
import com.appmattus.crypto.internal.core.city.CityHashTest.testData
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

internal class CityHash128Test {

    @Test
    fun baseTest() {
        for (i in 0 until kTestSize - 1) {
            val data = data.copyOfRange(i * i, i * i + i)
            testKat({ Algorithm.CityHash128().createDigest() }, data, testData[i].hash128)
            testKat({ Algorithm.CityHash128.Seed(kSeed0, kSeed1).createDigest() }, data, testData[i].hash128WithSeed)
        }

        testKat({ Algorithm.CityHash128().createDigest() }, data, testData[kTestSize - 1].hash128)
        testKat({ Algorithm.CityHash128.Seed(kSeed0, kSeed1).createDigest() }, data, testData[kTestSize - 1].hash128WithSeed)
    }
}
