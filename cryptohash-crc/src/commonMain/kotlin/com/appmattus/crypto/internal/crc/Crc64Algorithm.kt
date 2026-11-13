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

package com.appmattus.crypto.internal.crc

import com.appmattus.crypto.HashAlgorithm
import com.appmattus.crypto.Hasher

internal class Crc64Algorithm(private val parameters: Crc64Parameters) : HashAlgorithm {
    override fun newHasher(): Hasher = Crc64Hasher(parameters)

    override fun toString(): String = parameters.name
}

private const val ECMA_182: Long = 0x42F0E1EBA9EA3693
private const val ISO: Long = 0x1B
private const val ONES: Long = -1L

internal val Crc64Ecma182Algorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/ECMA-182", ECMA_182, init = 0, reflected = false, xorOut = 0))
internal val Crc64XzAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/XZ", ECMA_182, init = ONES, reflected = true, xorOut = ONES))
internal val Crc64WeAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/WE", ECMA_182, init = ONES, reflected = false, xorOut = ONES))
internal val Crc64GoIsoAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/GO-ISO", ISO, init = ONES, reflected = true, xorOut = ONES))
internal val Crc64SwissProtAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/SWISS-PROT", ISO, init = 0, reflected = true, xorOut = 0))
internal val Crc64RedisAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/REDIS", 0xAD93D23594C935A9uL.toLong(), init = 0, reflected = true, xorOut = 0))
internal val Crc64NvmeAlgorithm =
    Crc64Algorithm(Crc64Parameters("CRC-64/NVME", 0xAD93D23594C93659uL.toLong(), init = ONES, reflected = true, xorOut = ONES))
