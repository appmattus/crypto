/*
 * Copyright 2022-2026 Appmattus Limited
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

package com.appmattus.crypto.internal.wyhash

import com.appmattus.crypto.Wyhash
import com.appmattus.crypto.internal.testKat
import com.appmattus.crypto.internal.testKatHex
import com.appmattus.crypto.internal.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

class WyhashTest {

    @Test
    fun makeSecret() {
        Wyhash.makeSecret(0u).also { result ->
            assertEquals("95d49a959ca5a395", result[0].toHexString())
            assertEquals("b4a9716ac94da695", result[1].toHexString())
            assertEquals("5635cc6355956559", result[2].toHexString())
            assertEquals("e1e18e3a9c591da9", result[3].toHexString())
        }

        Wyhash.makeSecret(1u).also { result ->
            assertEquals("8b66d82b5ccaac2b", result[0].toHexString())
            assertEquals("f08d3cc98ecae895", result[1].toHexString())
            assertEquals("72b4c64e6a1dcc27", result[2].toHexString())
            assertEquals("1ee1c995c9c9d187", result[3].toHexString())
        }

        Wyhash.makeSecret(123u).also { result ->
            assertEquals("1b394eb263691da9", result[0].toHexString())
            assertEquals("d1d8b1d8936c0f71", result[1].toHexString())
            assertEquals("5978c32eb19ae22d", result[2].toHexString())
            assertEquals("1d2b745c8e2bb233", result[3].toHexString())
        }

        Wyhash.makeSecret(0x8b66d82b5ccaac2bu).also { result ->
            assertEquals("a674ac99aac37863", result[0].toHexString())
            assertEquals("9c55633a174ed471", result[1].toHexString())
            assertEquals("599c358d598bb169", result[2].toHexString())
            assertEquals("1ecc59f069c58e27", result[3].toHexString())
        }
    }

    @Test
    fun test() {
        testKat({ Wyhash.wyhash64(0u).newHasher() }, "", "42bc986dc5eec4d3")
        testKat({ Wyhash.wyhash64(1u).newHasher() }, "a", "84508dc903c31551")
        testKat({ Wyhash.wyhash64(2u).newHasher() }, "abc", "0bc54887cfc9ecb1")
        testKat({ Wyhash.wyhash64(3u).newHasher() }, "message digest", "6e2ff3298208a67c")
        testKat({ Wyhash.wyhash64(4u).newHasher() }, "abcdefghijklmnopqrstuvwxyz", "9a64e42e897195b9")
        testKat({ Wyhash.wyhash64(5u).newHasher() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "9199383239c32554")
        testKat({ Wyhash.wyhash64(6u).newHasher() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7c1ccf6bba30f5a5")
    }

    @Test
    fun testExtraProtection() {
        testKat({ Wyhash.wyhash64(0u, extraProtection = true).newHasher() }, "", "e6c763c9230f5746")
        testKat({ Wyhash.wyhash64(1u, extraProtection = true).newHasher() }, "a", "06c6ee1c5f92be1f")
        testKat({ Wyhash.wyhash64(2u, extraProtection = true).newHasher() }, "abc", "e81bb997cc2cc450")
        testKat({ Wyhash.wyhash64(3u, extraProtection = true).newHasher() }, "message digest", "3c56da7b192eaedb")
        testKat({ Wyhash.wyhash64(4u, extraProtection = true).newHasher() }, "abcdefghijklmnopqrstuvwxyz", "4c4de1e247ce0119")
        testKat({ Wyhash.wyhash64(5u, extraProtection = true).newHasher() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "8bc03169e6221156")
        testKat({ Wyhash.wyhash64(6u, extraProtection = true).newHasher() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7ba99b0da8266148")
    }

    @Test
    fun testComplete() {
        testKatHex({ Wyhash.wyhash64(0u).newHasher() }, "", "42bc986dc5eec4d3")
        testKatHex({ Wyhash.wyhash64(18446744073709551615u).newHasher() }, "", "33214c455b46f3a5")
        testKatHex({ Wyhash.wyhash64(0u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "79626ba92d44e663")
        testKatHex({ Wyhash.wyhash64(1u).newHasher() }, "00", "a2779e9ae8667368")
        testKatHex({ Wyhash.wyhash64(2u).newHasher() }, "0001", "244ce25b34f1a7c6")
        testKatHex({ Wyhash.wyhash64(4u).newHasher() }, "000102", "81fc2c02c9159aef")
        testKatHex({ Wyhash.wyhash64(8u).newHasher() }, "00010203", "44f85f33da44c6e7")
        testKatHex({ Wyhash.wyhash64(16u).newHasher() }, "0001020304", "e155c9864a3de3f1")
        testKatHex({ Wyhash.wyhash64(32u).newHasher() }, "000102030405", "3ca2d9c2733db2c8")
        testKatHex({ Wyhash.wyhash64(64u).newHasher() }, "00010203040506", "6406c615a5a09b26")
        testKatHex({ Wyhash.wyhash64(128u).newHasher() }, "0001020304050607", "7814c9cb30342980")
        testKatHex({ Wyhash.wyhash64(256u).newHasher() }, "0001020304050607ff", "cbcb2b2e7072f296")
        testKatHex({ Wyhash.wyhash64(512u).newHasher() }, "0001020304050607ff7f", "dddf6f7cde59816f")
        testKatHex({ Wyhash.wyhash64(1024u).newHasher() }, "0001020304050607ff7f3f", "5e629ce2c55e83e3")
        testKatHex({ Wyhash.wyhash64(2048u).newHasher() }, "0001020304050607ff7f3f1f", "84e6c652d5a4e16c")
        testKatHex({ Wyhash.wyhash64(4096u).newHasher() }, "0001020304050607ff7f3f1f0f", "d2a4af9f5e031985")
        testKatHex({ Wyhash.wyhash64(8192u).newHasher() }, "0001020304050607ff7f3f1f0f08", "76981aa077a0e10d")
        testKatHex({ Wyhash.wyhash64(16384u).newHasher() }, "0001020304050607ff7f3f1f0f0810", "b59c76028d72d860")
        testKatHex({ Wyhash.wyhash64(32768u).newHasher() }, "0001020304050607ff7f3f1f0f081020", "c2cdda05fa1d2a25")
        testKatHex({ Wyhash.wyhash64(65536u).newHasher() }, "0001020304050607ff7f3f1f0f08102040", "5d88af912c05c310")
        testKatHex({ Wyhash.wyhash64(131072u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080", "3d722b7b2705dbdc")
        testKatHex({ Wyhash.wyhash64(262144u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fe", "6f670d42d808a792")
        testKatHex({ Wyhash.wyhash64(524288u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefc", "819b33ad70be3599")
        testKatHex({ Wyhash.wyhash64(1048576u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "af36f4d170833617")
        testKatHex({ Wyhash.wyhash64(2097152u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "53834ba8b4d08764")
        testKatHex({ Wyhash.wyhash64(4194304u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "c2f76ae839bbe458")
        testKatHex({ Wyhash.wyhash64(8388608u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "26e7e435f6402ddf")
        testKatHex({ Wyhash.wyhash64(16777216u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "a129093462e20ae1")
        testKatHex({ Wyhash.wyhash64(33554432u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "1f8512e856ac95e9")
        testKatHex({ Wyhash.wyhash64(67108864u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "509fc06a19ac4e39")
        testKatHex({ Wyhash.wyhash64(134217728u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "1ae34ab5624316b3")
        testKatHex({ Wyhash.wyhash64(268435456u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "116269a0a2143350")
        testKatHex({ Wyhash.wyhash64(536870912u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "74531ad0a6128af5")
        testKatHex({ Wyhash.wyhash64(1073741824u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "3020d783f963d179")
        testKatHex({ Wyhash.wyhash64(2147483648u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "1ff6f1471aa31b3e")
        testKatHex({ Wyhash.wyhash64(4294967296u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "17f1d90e08b93798")
        testKatHex({ Wyhash.wyhash64(8589934592u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "a79df5a717db692a")
        testKatHex({ Wyhash.wyhash64(17179869184u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "14286cb3ff5b5bd6")
        testKatHex({ Wyhash.wyhash64(34359738368u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "47858c03d3ce5c3f")
        testKatHex({ Wyhash.wyhash64(68719476736u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "106a66eb344edfd5")
        testKatHex({ Wyhash.wyhash64(137438953472u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "02f4e1f68d829d40")
        testKatHex({ Wyhash.wyhash64(274877906944u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "b9f29cddf8adb200")
        testKatHex({ Wyhash.wyhash64(549755813888u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "139c2a106907be01")
        testKatHex({ Wyhash.wyhash64(1099511627776u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "e01353e4e731091f")
        testKatHex({ Wyhash.wyhash64(2199023255552u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "0d6750d38f228468")
        testKatHex({ Wyhash.wyhash64(4398046511104u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "89fc284eaf410f27")
        testKatHex({ Wyhash.wyhash64(8796093022208u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "ada4e3de8664eb50")
        testKatHex({ Wyhash.wyhash64(17592186044416u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "921be249302f6b12")
        testKatHex({ Wyhash.wyhash64(35184372088832u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "95df4335df12aab5")
        testKatHex({ Wyhash.wyhash64(70368744177664u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "dce17125d31e2565")
        testKatHex({ Wyhash.wyhash64(140737488355328u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "9e418e279447cbb3")
        testKatHex({ Wyhash.wyhash64(281474976710656u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "1c359c257d4f98eb")
        testKatHex({ Wyhash.wyhash64(562949953421312u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "415a6898b555bafc")
        testKatHex({ Wyhash.wyhash64(1125899906842624u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "97ff4e8beb8f8775")
        testKatHex({ Wyhash.wyhash64(2251799813685248u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "4e39ff63508ec0b9")
        testKatHex({ Wyhash.wyhash64(4503599627370496u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "85872d9c67326952")
        testKatHex({ Wyhash.wyhash64(9007199254740992u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "8caa922f6d6e97cd")
        testKatHex({ Wyhash.wyhash64(18014398509481984u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "60f2d599caf853f8")
        testKatHex({ Wyhash.wyhash64(36028797018963968u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "c9ddf58f0a17aab7")
        testKatHex({ Wyhash.wyhash64(72057594037927936u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "a13373e7fc79b2b0")
        testKatHex({ Wyhash.wyhash64(144115188075855872u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "a177841ef08ef444")
        testKatHex({ Wyhash.wyhash64(288230376151711744u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "f27c803a93f6124a")
        testKatHex({ Wyhash.wyhash64(576460752303423488u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "d017925b5dede066")
        testKatHex({ Wyhash.wyhash64(1152921504606846976u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "1550c97573a8eb4c")
        testKatHex({ Wyhash.wyhash64(2305843009213693952u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "1a1d8183ad86f5ad")
        testKatHex({ Wyhash.wyhash64(4611686018427387904u).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "9434f351bb784d8d")
        testKatHex({ Wyhash.wyhash64(18446744073709551614u).newHasher() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "c7a1007302baafe8")
        testKatHex({ Wyhash.wyhash64(18446744073709551612u).newHasher() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "23bc6dcde25421a9")
        testKatHex({ Wyhash.wyhash64(18446744073709551608u).newHasher() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "860008f6f54bce28")
        testKatHex({ Wyhash.wyhash64(18446744073709551600u).newHasher() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "d4f729befeb8a4d9")
        testKatHex({ Wyhash.wyhash64(18446744073709551584u).newHasher() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "37081a96a70544db")
        testKatHex({ Wyhash.wyhash64(18446744073709551552u).newHasher() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "16e65919f4fd5b23")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "4201ad78c3b952af")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "21b95574632fcc28")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "d87e231b681f5279")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "d7e3a400fc9ed86f")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "27132e58a0396d06")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "05e85623ecc5a4cd")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "ecc68b37aff6ca78")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "5548d36ac658842f")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u).newHasher() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "695b92af6ead4c57")
    }

    @Test
    fun testCompleteExtraProtection() {
        testKatHex({ Wyhash.wyhash64(0u, extraProtection = true).newHasher() }, "", "e6c763c9230f5746")
        testKatHex({ Wyhash.wyhash64(18446744073709551615u, extraProtection = true).newHasher() }, "", "a33940c615a71c10")
        testKatHex({ Wyhash.wyhash64(0u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "b1d34caa80c59210")
        testKatHex({ Wyhash.wyhash64(1u, extraProtection = true).newHasher() }, "00", "3561b6da651cafec")
        testKatHex({ Wyhash.wyhash64(2u, extraProtection = true).newHasher() }, "0001", "509ce64a4b0f1dc6")
        testKatHex({ Wyhash.wyhash64(4u, extraProtection = true).newHasher() }, "000102", "0c01513c79d827e4")
        testKatHex({ Wyhash.wyhash64(8u, extraProtection = true).newHasher() }, "00010203", "4035a6ab0728f17e")
        testKatHex({ Wyhash.wyhash64(16u, extraProtection = true).newHasher() }, "0001020304", "765b153d0e2b5a06")
        testKatHex({ Wyhash.wyhash64(32u, extraProtection = true).newHasher() }, "000102030405", "bc764c026e5e292e")
        testKatHex({ Wyhash.wyhash64(64u, extraProtection = true).newHasher() }, "00010203040506", "78247b5236aafff8")
        testKatHex({ Wyhash.wyhash64(128u, extraProtection = true).newHasher() }, "0001020304050607", "74c05f4032e49e9c")
        testKatHex({ Wyhash.wyhash64(256u, extraProtection = true).newHasher() }, "0001020304050607ff", "1a5f37eaa0aadc8f")
        testKatHex({ Wyhash.wyhash64(512u, extraProtection = true).newHasher() }, "0001020304050607ff7f", "74b0ba24ec7fcf58")
        testKatHex({ Wyhash.wyhash64(1024u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f", "00602e1220ef08c1")
        testKatHex({ Wyhash.wyhash64(2048u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f", "47f5bc2b00e69e1b")
        testKatHex({ Wyhash.wyhash64(4096u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f", "d08a9c75226f8883")
        testKatHex({ Wyhash.wyhash64(8192u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f08", "8c6155cdf530c440")
        testKatHex({ Wyhash.wyhash64(16384u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810", "b1d8e9be42176681")
        testKatHex({ Wyhash.wyhash64(32768u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f081020", "1678c7bf0e06a0bc")
        testKatHex({ Wyhash.wyhash64(65536u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f08102040", "f78014499eeb3a04")
        testKatHex({ Wyhash.wyhash64(131072u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080", "cf9c9c7cc5d2b741")
        testKatHex({ Wyhash.wyhash64(262144u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fe", "d3aebdf9754a88fd")
        testKatHex({ Wyhash.wyhash64(524288u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefc", "bebf93066e2d5d82")
        testKatHex({ Wyhash.wyhash64(1048576u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "56b6349ecfb3857f")
        testKatHex({ Wyhash.wyhash64(2097152u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "d0d571bb417e7f97")
        testKatHex({ Wyhash.wyhash64(4194304u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "6bf6e43ceb2532e6")
        testKatHex({ Wyhash.wyhash64(8388608u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "b427891c9b46f4ef")
        testKatHex({ Wyhash.wyhash64(16777216u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "5037c6ce79daa4d4")
        testKatHex({ Wyhash.wyhash64(33554432u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "1e0ab307815a8a0d")
        testKatHex({ Wyhash.wyhash64(67108864u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "6dc8de66ff1c41aa")
        testKatHex({ Wyhash.wyhash64(134217728u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "32ddaefca331accd")
        testKatHex({ Wyhash.wyhash64(268435456u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "a0585eefb366a475")
        testKatHex({ Wyhash.wyhash64(536870912u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "896739960cba0f62")
        testKatHex({ Wyhash.wyhash64(1073741824u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "31f8b9a83e02e94c")
        testKatHex({ Wyhash.wyhash64(2147483648u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "d0d47ec98d2e813e")
        testKatHex({ Wyhash.wyhash64(4294967296u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "57fe8c4af311fb12")
        testKatHex({ Wyhash.wyhash64(8589934592u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "1f05fe54fd6a163e")
        testKatHex({ Wyhash.wyhash64(17179869184u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "d3d2360521615ad3")
        testKatHex({ Wyhash.wyhash64(34359738368u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "47b772eb323310d2")
        testKatHex({ Wyhash.wyhash64(68719476736u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "3f2e3fbe3a92282c")
        testKatHex({ Wyhash.wyhash64(137438953472u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "f166b4418a25fb39")
        testKatHex({ Wyhash.wyhash64(274877906944u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "74d2122e22dace43")
        testKatHex({ Wyhash.wyhash64(549755813888u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "3e8b193e0e684e94")
        testKatHex({ Wyhash.wyhash64(1099511627776u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "268d50b370cc36ed")
        testKatHex({ Wyhash.wyhash64(2199023255552u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "42c5b360fd75b7ce")
        testKatHex({ Wyhash.wyhash64(4398046511104u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "e1358a485aa57fef")
        testKatHex({ Wyhash.wyhash64(8796093022208u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "a9b7b244c6ade8c6")
        testKatHex({ Wyhash.wyhash64(17592186044416u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "2b9a9fb521a26ca1")
        testKatHex({ Wyhash.wyhash64(35184372088832u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "2f2ca5a5a1b06988")
        testKatHex({ Wyhash.wyhash64(70368744177664u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "358661c434c736ed")
        testKatHex({ Wyhash.wyhash64(140737488355328u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "3836f4f087c59c5e")
        testKatHex({ Wyhash.wyhash64(281474976710656u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "7e37cf33d4e6f943")
        testKatHex({ Wyhash.wyhash64(562949953421312u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "806fe3e42141b3c6")
        testKatHex({ Wyhash.wyhash64(1125899906842624u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "9021a0f7f579368b")
        testKatHex({ Wyhash.wyhash64(2251799813685248u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "6cd285e991ce8271")
        testKatHex({ Wyhash.wyhash64(4503599627370496u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "7cd4367a6a3f023a")
        testKatHex({ Wyhash.wyhash64(9007199254740992u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "d909d64cb42392a9")
        testKatHex({ Wyhash.wyhash64(18014398509481984u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "14bc23f9121b0c46")
        testKatHex({ Wyhash.wyhash64(36028797018963968u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "f9ea85f53d927daa")
        testKatHex({ Wyhash.wyhash64(72057594037927936u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "31b06495ede3dcfd")
        testKatHex({ Wyhash.wyhash64(144115188075855872u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "20c9f87d4ed02006")
        testKatHex({ Wyhash.wyhash64(288230376151711744u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "0a064b1d9f9bae33")
        testKatHex({ Wyhash.wyhash64(576460752303423488u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "5bd57178ab763e3b")
        testKatHex({ Wyhash.wyhash64(1152921504606846976u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "e7f2c579284ac573")
        testKatHex({ Wyhash.wyhash64(2305843009213693952u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "869324f5ee91eed2")
        testKatHex({ Wyhash.wyhash64(4611686018427387904u, extraProtection = true).newHasher() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "1b5e59bc4c89308f")
        testKatHex({ Wyhash.wyhash64(18446744073709551614u, extraProtection = true).newHasher() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "3bfb021f444ce6ad")
        testKatHex({ Wyhash.wyhash64(18446744073709551612u, extraProtection = true).newHasher() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "66dcf15a2bdec940")
        testKatHex({ Wyhash.wyhash64(18446744073709551608u, extraProtection = true).newHasher() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "b634c0584bbe18c1")
        testKatHex({ Wyhash.wyhash64(18446744073709551600u, extraProtection = true).newHasher() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "1ae4a8b974d693f7")
        testKatHex({ Wyhash.wyhash64(18446744073709551584u, extraProtection = true).newHasher() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "8926d1126bd267d2")
        testKatHex({ Wyhash.wyhash64(18446744073709551552u, extraProtection = true).newHasher() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "c23ad76b85f1ea2c")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "a2e7c10f0ec39168")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "25f48ed64989e342")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "679ad6f1910f1791")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "ebecebe35f6cdf5a")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "baa520308890b747")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "6b1f6fedcd0a4313")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "ba5cdcaacc7ba149")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "43cc244e20b5eb50")
        testKatHex({ Wyhash.wyhash64(18446744073709551488u, extraProtection = true).newHasher() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "297ad611b4d8e9a3")
    }

    // The vectors below are from a port of the reference implementation (wangyi-fudan/wyhash at 98b44f4, the wyhash
    // final 3 version these tests' other vectors come from), for messages of bytes (i * 167 + 13), roughly half of
    // which have the top bit set, at every length from 0 to 64 and the block boundaries above it.

    @Test
    fun highBytes() = assertHighBytes(0u, false, HIGH_BYTES)

    @Test
    fun highBytesSeeded() = assertHighBytes(0x8000000000000001u, false, HIGH_BYTES_SEEDED)

    @Test
    fun highBytesExtraProtection() = assertHighBytes(0u, true, HIGH_BYTES_EXTRA_PROTECTION)

    @Test
    fun highBytesSeededExtraProtection() = assertHighBytes(0x8000000000000001u, true, HIGH_BYTES_SEEDED_EXTRA_PROTECTION)

    private fun assertHighBytes(seed: ULong, extraProtection: Boolean, expected: List<String>) {
        HIGH_BYTE_LENGTHS.forEachIndexed { index, length ->
            testKat(
                { Wyhash.wyhash64(seed, extraProtection = extraProtection).newHasher() },
                ByteArray(length) { (it * 167 + 13).toByte() },
                expected[index]
            )
        }
    }

    private companion object {
        val HIGH_BYTE_LENGTHS = (0..64).toList() + listOf(95, 96, 97, 143, 144, 145, 255, 256, 1023)

        val HIGH_BYTES = listOf(
            "42bc986dc5eec4d3", "1263dfc3c0b25894", "31433d1bd6906891", "a185a7d6c4b18b49",
            "be85dce78174b9c3", "edd55614090bde00", "e22b7267720ad96c", "39a64616ae3a3814",
            "3f4227f25b8d05a7", "a8668bf8a041a04e", "4c85d3121d9b54d1", "16749b1162afbf91",
            "92ed6647114e9151", "6e6ba7891cd8064b", "b0b7f96a2730b1ee", "1d1eecc26930538c",
            "31d8dcff410d5253", "dec6ff018d4f1651", "1b898f3058c1372e", "85b911d12ad3b29a",
            "ceb4347bcdfdcdc0", "931a08bb904974c7", "2d2ffa67d7936d2d", "67ef69907613e043",
            "f30eb222cb24c138", "0845b9d3df5bff34", "9b4462def662dd39", "47642cb065a41ad6",
            "c8d595c4e4041e7d", "25c1fd0a15aee3b4", "2268c5dfdba36ad0", "a2cede2666c1a8ff",
            "1c20836fac41ff0d", "93445f039308eace", "25fda3273e8707bd", "a74e4d4eddeafae9",
            "0356b4de5482e2d7", "ace51c7ba58ff472", "536009d9257b7d3f", "49b53c9f03125b7a",
            "493326cb529a71de", "94123c119a67e961", "8cb588f53343aa0a", "2b665709ef3b4a6b",
            "596637edc301f361", "34c24f14ac6cce33", "6b282741f9de54f6", "69084d997abc31bc",
            "1338ef6b552ffcb0", "e4220938cbd6c2d7", "a5024888f5aac166", "5c552bac3e402653",
            "303fa7f26010c88b", "b4e9856e8e9acabb", "10e9756739d5411a", "921f6529f079d53a",
            "1ba3f8d6edd774ba", "eefd1f82e3936405", "348c022d842d3192", "76937df97f31dba5",
            "723ad3271b9b0cd9", "7593b36f375a7650", "552417757ac7dbb9", "10a232ebf69493c3",
            "9efd83a0305c5576", "2add263c0ddc67af", "614aea91b5747cb0", "8de2d1464a99004a",
            "ef8eb16ce9a4d8ea", "913b0f7b95cbbb4e", "f5c4a2750862f319", "dbf47124247f0372",
            "8606ab76ca3de212", "564bfe112984a059"
        )

        val HIGH_BYTES_SEEDED = listOf(
            "4e5ff8c57558cb28", "8ce8eb2b00bce9dc", "6e7703b8488fcd0d", "fec0488f7118f7c0",
            "bd47979baed0d064", "1d75d0cdb83f9d87", "61f303eaeeade52a", "7a022504f877c2cc",
            "9a6742231e790f4c", "2cbb27963e3091ed", "d1b27c5a16807bf3", "b8f9c88793ab966a",
            "511432392ebbfbbb", "d348450bd5076de3", "33c0687a9399d079", "1ab0810fb49b5d48",
            "4e3a565812fadde7", "a00e79b831f2fc11", "7185ccb5dcbfbd46", "a19ae241559a22a4",
            "ecf241ecaf119e92", "2db1720d1b44514b", "16126efefac28222", "fce53311fc3f0ee6",
            "94dd916c1961c3bf", "a85ee1d8c204074a", "989e284777f128a9", "0ba81e18ff4b9fbf",
            "75ba28106e4a2a0a", "c6b0edaf729f453a", "3fa08096dc5ff52a", "8d298db3cace712d",
            "e6ff0126ba130713", "329028c9281ea9c8", "98309b4c26fdbef5", "bbe09909f5a8a75a",
            "d5bd7050ba0ddfa8", "46399c187c625931", "222bb6cf1e445c0a", "e38fa8cb699eed47",
            "557bf170fe8c8e0c", "98d203862895a66d", "cf4915568aa69a9c", "fd7a67b12e033534",
            "a13519ec000b3828", "9069dc2484c9dcdf", "738d302b4e4a0c1d", "dd9d0464b5949eb6",
            "2c1473a15381f568", "b366f653b23f603e", "ef9cf3710e9b3bad", "5da2478925449d96",
            "f2f9597cf6317f31", "aec5056c292abcdb", "93d143d1715dcaba", "dc7cab2c47e23e3f",
            "e473103c77af8b0d", "bdfc0aca2bfb9e0a", "a43ad6ea4d601827", "09e5c181fddc0e35",
            "3ab78dac0ef46a98", "64d446edfd031ace", "e7a2942d39520c0f", "34a61cd1ad1d31fc",
            "8e6a6aa584826bf5", "50896b4d960d423a", "59ae6ea2031d5aa5", "127010171d150cb2",
            "58b1ab379ee553dd", "6cdcf4e904e186e5", "687b0acf9fe986f2", "3e1ca647d3e81192",
            "9aa3b1cdb453bb76", "68255c9777c49024"
        )

        val HIGH_BYTES_EXTRA_PROTECTION = listOf(
            "e6c763c9230f5746", "4da65657ab0bb090", "a02049344f8ff901", "cdcbbb688f705304",
            "69c948c2f5460d94", "7ad62b3d51bb86df", "7c3f7321e55b40aa", "499e529c1ec42094",
            "fbf46bed449a9fc3", "8c0ff5a109c8f1ca", "55bd32e24298c2ca", "7dc1beddbb4a65b2",
            "15bd4da436924dcd", "771372732a98d466", "0b7b552574cf0125", "b78fc4854e55d563",
            "19f6649a2a3d2f23", "ccea423a0a54baf3", "d6f97a9b426b0917", "5e320c837fee813e",
            "52504120441deeb7", "cc163e602a075bbc", "8301102ec06a4c0d", "ae08fc658accc1e1",
            "25d8398912bc49ac", "98bcb10498b14844", "3d4fe4dd25a6e536", "be9b31de61143fae",
            "5930baa15d934bb0", "cdd22b15f765cac6", "4301881ed3edec7d", "5b8352572eacb95f",
            "798f1124c9dee2a3", "0512682effbf0dcf", "e45966994bbffc47", "cc305e6c67d7ca4d",
            "f34de962b4189893", "cf7df55670c1c7bb", "f8d4ea8b63b57a63", "18d82aa5a49abf04",
            "c3184d68e0452fa3", "57a5402ce7f9a56b", "9268f97f3397b506", "3edb1f1b3933a534",
            "93166c7a64ea12bd", "24e9473e33cd2269", "7e3eed16e60446f1", "8910e605b1b310e7",
            "7d769037d403441d", "3beaa9cceb923fca", "cf46803a6e08554f", "2162c78b79204a16",
            "280cd81fe5a8f4ba", "12e3766599c7f4d9", "e7cff4e3b736d67e", "1ce27d572ee1f3b0",
            "bea6fa572453a766", "cda71f1906266d50", "d504e82265bcc216", "7c44b7861720008e",
            "94bd6b261f571ffe", "a13061b4e1724280", "dd1e5ae7f73d70d7", "80f1ad5c7d6fbf4b",
            "358b20d96f7df3cb", "f746a37e2b78cdb4", "63acb8491b9e69e8", "71a9deaf7080318e",
            "b52d355549424516", "c4284d22c1cab2f3", "e4546bae76cffb84", "2bb0173e95a2c952",
            "9dccbc25dbe40697", "af4bf785d2e1a987"
        )

        val HIGH_BYTES_SEEDED_EXTRA_PROTECTION = listOf(
            "08365870209c0384", "6373ace8d4560f1d", "76777c0fe770caef", "b44e9e5471afe380",
            "6ad2ac2a5a5c70a9", "a02509c1aeeb7882", "f171a1c147a96c19", "506e7940c1780ac6",
            "47dd8ec66195879a", "8a028e6fe7c066c8", "ce3a06399bc483fd", "c63b026f00b9c131",
            "b74b53f951486372", "497b32defc002af3", "e6f8192266e918a9", "ca69edbd8364c5d4",
            "d0ac61e753601ae4", "7a76089463d20531", "2b227239f3c71d2a", "d04fdf0f6b968393",
            "6df83589fdb72b53", "de8fe42a0ea02e16", "ca1d7a415e2a45f8", "8364900156c7960f",
            "ef29d00096da5905", "bb0b52a13051e05c", "86d6291b2bafc63e", "2f6b21d7faa3adcc",
            "e7246ef7320defb0", "fc838683e71c8860", "deb78126b90d0e23", "5c64c780dffa4d15",
            "c1104dccffc948c5", "19df7ec203ee999d", "5a19b7d9f6b3314d", "02967d48092c0c25",
            "7b8cd89b8ee091d3", "8243aa296869c190", "0b62de0ddcd203e1", "4405eaf68758c3a6",
            "0bdb3e23b9700b8e", "67651d9f0b895b2e", "95a37c3e51ae0b1b", "8c8c2328db998514",
            "7ee13e9e1a66f11b", "f8c75c6d023b570c", "7476abd8bc419b18", "3fe34f6ea2085c61",
            "0296904f607c4292", "7f2825f52a3e05f1", "9d3734c9b2558d2a", "4d36e4b6723a2e17",
            "096d447d097c73df", "079e9c710d7f5264", "daacb014ad433106", "68759c6fc229f42e",
            "97926dec668d53c4", "ef39cbc751fae84c", "0e97e0ce19583712", "eaa87f5183a4687e",
            "b45f2f4e71f9d4db", "041fc56747e29b55", "3c6c93fa3f42522c", "07427995b6f469ea",
            "356dfb8f2d65bda0", "602d5fe98838ba79", "f53e92b6419e7f3c", "3cca32d6365955bd",
            "bf10c246bf3e2f68", "27ab19b37363332e", "cbcae363f10c036e", "f4f6826a9b172602",
            "fba2d111760ebcb8", "997c09efbefb2ebf"
        )
    }
}
