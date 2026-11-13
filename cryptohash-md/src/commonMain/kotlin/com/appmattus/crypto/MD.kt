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

package com.appmattus.crypto

import com.appmattus.crypto.internal.md.MD2Hasher
import com.appmattus.crypto.internal.md.MD4Hasher
import com.appmattus.crypto.internal.md.MD5Hasher
import com.appmattus.crypto.internal.md.MDHmacAlgorithm

/**
 * The MD family of cryptographic hashes: [MD2](https://en.wikipedia.org/wiki/MD2_(hash_function)),
 * [MD4](https://en.wikipedia.org/wiki/MD4) and [MD5](https://en.wikipedia.org/wiki/MD5)
 */
public object MD {

    /**
     * MD2, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.
     */
    public val md2: HmacAlgorithm = MDHmacAlgorithm("MD2", 16, ::MD2Hasher)

    /**
     * MD4, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.
     */
    public val md4: HmacAlgorithm = MDHmacAlgorithm("MD4", 64, ::MD4Hasher)

    /**
     * MD5, with output size of 128 bits, which also supports HMAC. It is broken, so only use it for compatibility.
     */
    public val md5: HmacAlgorithm = MDHmacAlgorithm("MD5", 64, ::MD5Hasher)
}
