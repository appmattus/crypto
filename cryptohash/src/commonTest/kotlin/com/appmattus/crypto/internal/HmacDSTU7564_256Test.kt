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

package com.appmattus.crypto.internal

// HMAC for Kupyna disabled as the results don't match with the tests in BC even though algorithm code is based on BC implementation

// import com.appmattus.crypto.Algorithm
// import com.appmattus.crypto.internal.core.sphlib.testHmac
// import kotlin.test.Test
//
// class HmacDSTU7564_256Test {
//
//    @Test
//    fun misc2() {
//        // From https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/HMacTest.java
//
//        testHmac(
//            Algorithm.Kupyna_256,
//            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
//            "Hi There",
//            "98ac67aa21eaf6e8666fb748d66cfc15d5d66f5194c87fffa647e406d3375cdb"
//        )
//    }
// }
