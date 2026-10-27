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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The largest test vectors from [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861) appendix A.4 and A.5, run on the JVM
 * only as they hash up to 24 MB
 */
class KangarooTwelveLargeTest {

    @Test
    fun kt128MatchesLargeRfc9861Vectors() {
        assertEquals("844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682", Algorithm.KT128().hash(ptn(1419857)).toHexString())
        assertEquals("3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8", Algorithm.KT128().hash(ptn(24137569)).toHexString())
    }

    @Test
    fun kt256MatchesLargeRfc9861Vectors() {
        assertEquals(
            "9473831d76a4c7bf77ace45b59f1458b1673d64bcd877a7c66b2664aa6dd149e60eab71b5c2bab858c074ded81ddce2b4022b5215935c0d4d19bf511aeeb0772",
            Algorithm.KT256().hash(ptn(1419857)).toHexString()
        )
        assertEquals(
            "0652b740d78c5e1f7c8dcc1777097382768b7ff38f9a7a20f29f413bb1b3045b31a5578f568f911e09cf44746da84224a5266e96a4a535e871324e4f9c7004da",
            Algorithm.KT256().hash(ptn(24137569)).toHexString()
        )
    }
}
