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

import com.appmattus.crypto.internal.crc.Crc32Algorithm
import com.appmattus.crypto.internal.crc.Crc32bAlgorithm
import com.appmattus.crypto.internal.crc.Crc32cAlgorithm
import com.appmattus.crypto.internal.crc.Crc64Ecma182Algorithm
import com.appmattus.crypto.internal.crc.Crc64GoIsoAlgorithm
import com.appmattus.crypto.internal.crc.Crc64NvmeAlgorithm
import com.appmattus.crypto.internal.crc.Crc64RedisAlgorithm
import com.appmattus.crypto.internal.crc.Crc64SwissProtAlgorithm
import com.appmattus.crypto.internal.crc.Crc64WeAlgorithm
import com.appmattus.crypto.internal.crc.Crc64XzAlgorithm

/**
 * The [Crc](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) family of checksums
 *
 * The CRC-64 variants are as defined by the [CRC catalogue](https://reveng.sourceforge.io/crc-catalogue/17plus.htm),
 * and output their CRC big-endian, so its hex is the CRC's value as the catalogue writes it.
 *
 * Where the platform has its own implementation, as the JVM has for CRC32B and CRC32C and Apple platforms have for
 * CRC32B, hashers use it. The results are identical either way.
 */
public object Crc {

    /**
     * CRC-32/BZIP2, the non-reflected CRC-32 with polynomial 0x04C11DB7, with output size of 32 bits
     */
    public val crc32: HashAlgorithm = Crc32Algorithm

    /**
     * CRC-32/ISO-HDLC, the reflected CRC-32 of zlib, gzip, PNG and Ethernet, with output size of 32 bits
     */
    public val crc32b: HashAlgorithm = Crc32bAlgorithm

    /**
     * CRC-32C/ISCSI, Castagnoli's CRC used by iSCSI, SCTP, Btrfs and ext4, with output size of 32 bits
     */
    public val crc32c: HashAlgorithm = Crc32cAlgorithm

    /**
     * CRC-64/ECMA-182, the non-reflected CRC-64 of ECMA-182 with polynomial 0x42F0E1EBA9EA3693, initial value 0 and
     * no final XOR
     */
    public val crc64Ecma182: HashAlgorithm = Crc64Ecma182Algorithm

    /**
     * CRC-64/XZ, the reflected CRC-64 with the ECMA-182 polynomial used by XZ and Go's ECMA table, with initial value
     * and final XOR of all ones
     */
    public val crc64Xz: HashAlgorithm = Crc64XzAlgorithm

    /**
     * CRC-64/WE, the non-reflected CRC-64 with the ECMA-182 polynomial, initial value and final XOR of all ones. This is
     * Linux's crc64_be as bcache uses it; crc64_be with an initial value of 0 and no final XOR is [crc64Ecma182]
     */
    public val crc64We: HashAlgorithm = Crc64WeAlgorithm

    /**
     * CRC-64/GO-ISO, the reflected CRC-64 with the ISO polynomial 0x1B used by Go's ISO table, with initial value and
     * final XOR of all ones
     */
    public val crc64GoIso: HashAlgorithm = Crc64GoIsoAlgorithm

    /**
     * The reflected CRC-64 with the ISO polynomial 0x1B as SWISS-PROT and UniProt use it, with initial value 0 and no
     * final XOR
     */
    public val crc64SwissProt: HashAlgorithm = Crc64SwissProtAlgorithm

    /**
     * CRC-64/REDIS, the reflected CRC-64 with Jones's polynomial 0xAD93D23594C935A9 used by Redis, also known as
     * CRC-64-Jones, with initial value 0 and no final XOR
     */
    public val crc64Redis: HashAlgorithm = Crc64RedisAlgorithm

    /**
     * CRC-64/NVME, the reflected CRC-64 with polynomial 0xAD93D23594C93659 of NVMe and Linux's crc64_nvme, also known
     * as the Rocksoft CRC, with initial value and final XOR of all ones
     */
    public val crc64Nvme: HashAlgorithm = Crc64NvmeAlgorithm
}
