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

package com.appmattus.crypto.internal.ripemd

import com.appmattus.crypto.RipeMd
import com.appmattus.crypto.internal.testHmac
import kotlin.test.Test

class HmacRipeMd320Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            RipeMd.ripeMd320,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "dfca8756189fc556323fb344001a927c161f83a9d8f402d092c537346ae977113c4d02cca757a7ad"
        )
    }
}
