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

import com.appmattus.crypto.Algorithm
import org.bouncycastle.jcajce.provider.digest.SHA3

@Suppress("ClassName")
internal class SHA3_224BcTest : SHA3_224Test() {
    override fun digest() = MessageDigestPlatform(Algorithm.SHA3_224.algorithmName, Algorithm.SHA3_224.blockLength, SHA3.Digest224())
}
