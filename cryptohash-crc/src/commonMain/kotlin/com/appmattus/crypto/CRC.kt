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

/**
 * The [CRC](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) family of checksums
 *
 * Where the platform has its own implementation, as the JVM has for CRC32B and CRC32C and Apple platforms have for
 * CRC32B, hashers use it. The results are identical either way.
 */
public object CRC {

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
}
