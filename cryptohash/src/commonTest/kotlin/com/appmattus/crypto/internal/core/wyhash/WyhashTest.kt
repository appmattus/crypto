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

package com.appmattus.crypto.internal.core.wyhash

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.crypto.internal.core.sphlib.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

class WyhashTest {

    @Test
    fun makeSecret() {
        Algorithm.Wyhash.makeSecret(0u).also { result ->
            assertEquals("95d49a959ca5a395", result[0].toHexString())
            assertEquals("b4a9716ac94da695", result[1].toHexString())
            assertEquals("5635cc6355956559", result[2].toHexString())
            assertEquals("e1e18e3a9c591da9", result[3].toHexString())
        }

        Algorithm.Wyhash.makeSecret(1u).also { result ->
            assertEquals("8b66d82b5ccaac2b", result[0].toHexString())
            assertEquals("f08d3cc98ecae895", result[1].toHexString())
            assertEquals("72b4c64e6a1dcc27", result[2].toHexString())
            assertEquals("1ee1c995c9c9d187", result[3].toHexString())
        }

        Algorithm.Wyhash.makeSecret(123u).also { result ->
            assertEquals("1b394eb263691da9", result[0].toHexString())
            assertEquals("d1d8b1d8936c0f71", result[1].toHexString())
            assertEquals("5978c32eb19ae22d", result[2].toHexString())
            assertEquals("1d2b745c8e2bb233", result[3].toHexString())
        }

        Algorithm.Wyhash.makeSecret(0x8b66d82b5ccaac2bu).also { result ->
            assertEquals("a674ac99aac37863", result[0].toHexString())
            assertEquals("9c55633a174ed471", result[1].toHexString())
            assertEquals("599c358d598bb169", result[2].toHexString())
            assertEquals("1ecc59f069c58e27", result[3].toHexString())
        }
    }

    @Test
    fun test() {
        testKat({ Algorithm.Wyhash(0u).createDigest() }, "", "42bc986dc5eec4d3")
        testKat({ Algorithm.Wyhash(1u).createDigest() }, "a", "84508dc903c31551")
        testKat({ Algorithm.Wyhash(2u).createDigest() }, "abc", "0bc54887cfc9ecb1")
        testKat({ Algorithm.Wyhash(3u).createDigest() }, "message digest", "6e2ff3298208a67c")
        testKat({ Algorithm.Wyhash(4u).createDigest() }, "abcdefghijklmnopqrstuvwxyz", "9a64e42e897195b9")
        testKat({ Algorithm.Wyhash(5u).createDigest() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "9199383239c32554")
        testKat({ Algorithm.Wyhash(6u).createDigest() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7c1ccf6bba30f5a5")
    }

    @Test
    fun testExtraProtection() {
        testKat({ Algorithm.Wyhash(0u, extraProtection = true).createDigest() }, "", "e6c763c9230f5746")
        testKat({ Algorithm.Wyhash(1u, extraProtection = true).createDigest() }, "a", "06c6ee1c5f92be1f")
        testKat({ Algorithm.Wyhash(2u, extraProtection = true).createDigest() }, "abc", "e81bb997cc2cc450")
        testKat({ Algorithm.Wyhash(3u, extraProtection = true).createDigest() }, "message digest", "3c56da7b192eaedb")
        testKat({ Algorithm.Wyhash(4u, extraProtection = true).createDigest() }, "abcdefghijklmnopqrstuvwxyz", "4c4de1e247ce0119")
        testKat({ Algorithm.Wyhash(5u, extraProtection = true).createDigest() }, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "8bc03169e6221156")
        testKat({ Algorithm.Wyhash(6u, extraProtection = true).createDigest() }, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7ba99b0da8266148")
    }

    @Test
    fun testComplete() {
        testKatHex({ Algorithm.Wyhash(0u).createDigest() }, "", "42bc986dc5eec4d3")
        testKatHex({ Algorithm.Wyhash(18446744073709551615u).createDigest() }, "", "33214c455b46f3a5")
        testKatHex({ Algorithm.Wyhash(0u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "79626ba92d44e663")
        testKatHex({ Algorithm.Wyhash(1u).createDigest() }, "00", "a2779e9ae8667368")
        testKatHex({ Algorithm.Wyhash(2u).createDigest() }, "0001", "244ce25b34f1a7c6")
        testKatHex({ Algorithm.Wyhash(4u).createDigest() }, "000102", "81fc2c02c9159aef")
        testKatHex({ Algorithm.Wyhash(8u).createDigest() }, "00010203", "44f85f33da44c6e7")
        testKatHex({ Algorithm.Wyhash(16u).createDigest() }, "0001020304", "e155c9864a3de3f1")
        testKatHex({ Algorithm.Wyhash(32u).createDigest() }, "000102030405", "3ca2d9c2733db2c8")
        testKatHex({ Algorithm.Wyhash(64u).createDigest() }, "00010203040506", "6406c615a5a09b26")
        testKatHex({ Algorithm.Wyhash(128u).createDigest() }, "0001020304050607", "7814c9cb30342980")
        testKatHex({ Algorithm.Wyhash(256u).createDigest() }, "0001020304050607ff", "cbcb2b2e7072f296")
        testKatHex({ Algorithm.Wyhash(512u).createDigest() }, "0001020304050607ff7f", "dddf6f7cde59816f")
        testKatHex({ Algorithm.Wyhash(1024u).createDigest() }, "0001020304050607ff7f3f", "5e629ce2c55e83e3")
        testKatHex({ Algorithm.Wyhash(2048u).createDigest() }, "0001020304050607ff7f3f1f", "84e6c652d5a4e16c")
        testKatHex({ Algorithm.Wyhash(4096u).createDigest() }, "0001020304050607ff7f3f1f0f", "d2a4af9f5e031985")
        testKatHex({ Algorithm.Wyhash(8192u).createDigest() }, "0001020304050607ff7f3f1f0f08", "76981aa077a0e10d")
        testKatHex({ Algorithm.Wyhash(16384u).createDigest() }, "0001020304050607ff7f3f1f0f0810", "b59c76028d72d860")
        testKatHex({ Algorithm.Wyhash(32768u).createDigest() }, "0001020304050607ff7f3f1f0f081020", "c2cdda05fa1d2a25")
        testKatHex({ Algorithm.Wyhash(65536u).createDigest() }, "0001020304050607ff7f3f1f0f08102040", "5d88af912c05c310")
        testKatHex({ Algorithm.Wyhash(131072u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080", "3d722b7b2705dbdc")
        testKatHex({ Algorithm.Wyhash(262144u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fe", "6f670d42d808a792")
        testKatHex({ Algorithm.Wyhash(524288u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefc", "819b33ad70be3599")
        testKatHex({ Algorithm.Wyhash(1048576u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "af36f4d170833617")
        testKatHex({ Algorithm.Wyhash(2097152u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "53834ba8b4d08764")
        testKatHex({ Algorithm.Wyhash(4194304u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "c2f76ae839bbe458")
        testKatHex({ Algorithm.Wyhash(8388608u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "26e7e435f6402ddf")
        testKatHex({ Algorithm.Wyhash(16777216u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "a129093462e20ae1")
        testKatHex({ Algorithm.Wyhash(33554432u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "1f8512e856ac95e9")
        testKatHex({ Algorithm.Wyhash(67108864u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "509fc06a19ac4e39")
        testKatHex({ Algorithm.Wyhash(134217728u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "1ae34ab5624316b3")
        testKatHex({ Algorithm.Wyhash(268435456u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "116269a0a2143350")
        testKatHex({ Algorithm.Wyhash(536870912u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "74531ad0a6128af5")
        testKatHex({ Algorithm.Wyhash(1073741824u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "3020d783f963d179")
        testKatHex({ Algorithm.Wyhash(2147483648u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "1ff6f1471aa31b3e")
        testKatHex({ Algorithm.Wyhash(4294967296u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "17f1d90e08b93798")
        testKatHex({ Algorithm.Wyhash(8589934592u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "a79df5a717db692a")
        testKatHex({ Algorithm.Wyhash(17179869184u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "14286cb3ff5b5bd6")
        testKatHex({ Algorithm.Wyhash(34359738368u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "47858c03d3ce5c3f")
        testKatHex({ Algorithm.Wyhash(68719476736u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "106a66eb344edfd5")
        testKatHex({ Algorithm.Wyhash(137438953472u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "02f4e1f68d829d40")
        testKatHex({ Algorithm.Wyhash(274877906944u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "b9f29cddf8adb200")
        testKatHex({ Algorithm.Wyhash(549755813888u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "139c2a106907be01")
        testKatHex({ Algorithm.Wyhash(1099511627776u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "e01353e4e731091f")
        testKatHex({ Algorithm.Wyhash(2199023255552u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "0d6750d38f228468")
        testKatHex({ Algorithm.Wyhash(4398046511104u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "89fc284eaf410f27")
        testKatHex({ Algorithm.Wyhash(8796093022208u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "ada4e3de8664eb50")
        testKatHex({ Algorithm.Wyhash(17592186044416u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "921be249302f6b12")
        testKatHex({ Algorithm.Wyhash(35184372088832u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "95df4335df12aab5")
        testKatHex({ Algorithm.Wyhash(70368744177664u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "dce17125d31e2565")
        testKatHex({ Algorithm.Wyhash(140737488355328u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "9e418e279447cbb3")
        testKatHex({ Algorithm.Wyhash(281474976710656u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "1c359c257d4f98eb")
        testKatHex({ Algorithm.Wyhash(562949953421312u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "415a6898b555bafc")
        testKatHex({ Algorithm.Wyhash(1125899906842624u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "97ff4e8beb8f8775")
        testKatHex({ Algorithm.Wyhash(2251799813685248u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "4e39ff63508ec0b9")
        testKatHex({ Algorithm.Wyhash(4503599627370496u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "85872d9c67326952")
        testKatHex({ Algorithm.Wyhash(9007199254740992u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "8caa922f6d6e97cd")
        testKatHex({ Algorithm.Wyhash(18014398509481984u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "60f2d599caf853f8")
        testKatHex({ Algorithm.Wyhash(36028797018963968u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "c9ddf58f0a17aab7")
        testKatHex({ Algorithm.Wyhash(72057594037927936u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "a13373e7fc79b2b0")
        testKatHex({ Algorithm.Wyhash(144115188075855872u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "a177841ef08ef444")
        testKatHex({ Algorithm.Wyhash(288230376151711744u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "f27c803a93f6124a")
        testKatHex({ Algorithm.Wyhash(576460752303423488u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "d017925b5dede066")
        testKatHex({ Algorithm.Wyhash(1152921504606846976u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "1550c97573a8eb4c")
        testKatHex({ Algorithm.Wyhash(2305843009213693952u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "1a1d8183ad86f5ad")
        testKatHex({ Algorithm.Wyhash(4611686018427387904u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "9434f351bb784d8d")
        testKatHex({ Algorithm.Wyhash(18446744073709551614u).createDigest() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "c7a1007302baafe8")
        testKatHex({ Algorithm.Wyhash(18446744073709551612u).createDigest() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "23bc6dcde25421a9")
        testKatHex({ Algorithm.Wyhash(18446744073709551608u).createDigest() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "860008f6f54bce28")
        testKatHex({ Algorithm.Wyhash(18446744073709551600u).createDigest() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "d4f729befeb8a4d9")
        testKatHex({ Algorithm.Wyhash(18446744073709551584u).createDigest() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "37081a96a70544db")
        testKatHex({ Algorithm.Wyhash(18446744073709551552u).createDigest() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "16e65919f4fd5b23")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "4201ad78c3b952af")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "21b95574632fcc28")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "d87e231b681f5279")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "d7e3a400fc9ed86f")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "27132e58a0396d06")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "05e85623ecc5a4cd")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "ecc68b37aff6ca78")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "5548d36ac658842f")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u).createDigest() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "695b92af6ead4c57")
    }

    @Test
    fun testCompleteExtraProtection() {
        testKatHex({ Algorithm.Wyhash(0u, extraProtection = true).createDigest() }, "", "e6c763c9230f5746")
        testKatHex({ Algorithm.Wyhash(18446744073709551615u, extraProtection = true).createDigest() }, "", "a33940c615a71c10")
        testKatHex({ Algorithm.Wyhash(0u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "b1d34caa80c59210")
        testKatHex({ Algorithm.Wyhash(1u, extraProtection = true).createDigest() }, "00", "3561b6da651cafec")
        testKatHex({ Algorithm.Wyhash(2u, extraProtection = true).createDigest() }, "0001", "509ce64a4b0f1dc6")
        testKatHex({ Algorithm.Wyhash(4u, extraProtection = true).createDigest() }, "000102", "0c01513c79d827e4")
        testKatHex({ Algorithm.Wyhash(8u, extraProtection = true).createDigest() }, "00010203", "4035a6ab0728f17e")
        testKatHex({ Algorithm.Wyhash(16u, extraProtection = true).createDigest() }, "0001020304", "765b153d0e2b5a06")
        testKatHex({ Algorithm.Wyhash(32u, extraProtection = true).createDigest() }, "000102030405", "bc764c026e5e292e")
        testKatHex({ Algorithm.Wyhash(64u, extraProtection = true).createDigest() }, "00010203040506", "78247b5236aafff8")
        testKatHex({ Algorithm.Wyhash(128u, extraProtection = true).createDigest() }, "0001020304050607", "74c05f4032e49e9c")
        testKatHex({ Algorithm.Wyhash(256u, extraProtection = true).createDigest() }, "0001020304050607ff", "1a5f37eaa0aadc8f")
        testKatHex({ Algorithm.Wyhash(512u, extraProtection = true).createDigest() }, "0001020304050607ff7f", "74b0ba24ec7fcf58")
        testKatHex({ Algorithm.Wyhash(1024u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f", "00602e1220ef08c1")
        testKatHex({ Algorithm.Wyhash(2048u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f", "47f5bc2b00e69e1b")
        testKatHex({ Algorithm.Wyhash(4096u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f", "d08a9c75226f8883")
        testKatHex({ Algorithm.Wyhash(8192u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f08", "8c6155cdf530c440")
        testKatHex({ Algorithm.Wyhash(16384u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810", "b1d8e9be42176681")
        testKatHex({ Algorithm.Wyhash(32768u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f081020", "1678c7bf0e06a0bc")
        testKatHex({ Algorithm.Wyhash(65536u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f08102040", "f78014499eeb3a04")
        testKatHex({ Algorithm.Wyhash(131072u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080", "cf9c9c7cc5d2b741")
        testKatHex({ Algorithm.Wyhash(262144u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fe", "d3aebdf9754a88fd")
        testKatHex({ Algorithm.Wyhash(524288u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefc", "bebf93066e2d5d82")
        testKatHex({ Algorithm.Wyhash(1048576u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "56b6349ecfb3857f")
        testKatHex({ Algorithm.Wyhash(2097152u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "d0d571bb417e7f97")
        testKatHex({ Algorithm.Wyhash(4194304u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "6bf6e43ceb2532e6")
        testKatHex({ Algorithm.Wyhash(8388608u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "b427891c9b46f4ef")
        testKatHex({ Algorithm.Wyhash(16777216u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "5037c6ce79daa4d4")
        testKatHex({ Algorithm.Wyhash(33554432u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "1e0ab307815a8a0d")
        testKatHex({ Algorithm.Wyhash(67108864u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "6dc8de66ff1c41aa")
        testKatHex({ Algorithm.Wyhash(134217728u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "32ddaefca331accd")
        testKatHex({ Algorithm.Wyhash(268435456u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "a0585eefb366a475")
        testKatHex({ Algorithm.Wyhash(536870912u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "896739960cba0f62")
        testKatHex({ Algorithm.Wyhash(1073741824u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "31f8b9a83e02e94c")
        testKatHex({ Algorithm.Wyhash(2147483648u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "d0d47ec98d2e813e")
        testKatHex({ Algorithm.Wyhash(4294967296u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "57fe8c4af311fb12")
        testKatHex({ Algorithm.Wyhash(8589934592u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "1f05fe54fd6a163e")
        testKatHex({ Algorithm.Wyhash(17179869184u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "d3d2360521615ad3")
        testKatHex({ Algorithm.Wyhash(34359738368u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "47b772eb323310d2")
        testKatHex({ Algorithm.Wyhash(68719476736u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "3f2e3fbe3a92282c")
        testKatHex({ Algorithm.Wyhash(137438953472u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "f166b4418a25fb39")
        testKatHex({ Algorithm.Wyhash(274877906944u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "74d2122e22dace43")
        testKatHex({ Algorithm.Wyhash(549755813888u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "3e8b193e0e684e94")
        testKatHex({ Algorithm.Wyhash(1099511627776u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "268d50b370cc36ed")
        testKatHex({ Algorithm.Wyhash(2199023255552u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "42c5b360fd75b7ce")
        testKatHex({ Algorithm.Wyhash(4398046511104u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "e1358a485aa57fef")
        testKatHex({ Algorithm.Wyhash(8796093022208u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "a9b7b244c6ade8c6")
        testKatHex({ Algorithm.Wyhash(17592186044416u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "2b9a9fb521a26ca1")
        testKatHex({ Algorithm.Wyhash(35184372088832u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "2f2ca5a5a1b06988")
        testKatHex({ Algorithm.Wyhash(70368744177664u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "358661c434c736ed")
        testKatHex({ Algorithm.Wyhash(140737488355328u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "3836f4f087c59c5e")
        testKatHex({ Algorithm.Wyhash(281474976710656u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "7e37cf33d4e6f943")
        testKatHex({ Algorithm.Wyhash(562949953421312u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "806fe3e42141b3c6")
        testKatHex({ Algorithm.Wyhash(1125899906842624u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "9021a0f7f579368b")
        testKatHex({ Algorithm.Wyhash(2251799813685248u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "6cd285e991ce8271")
        testKatHex({ Algorithm.Wyhash(4503599627370496u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "7cd4367a6a3f023a")
        testKatHex({ Algorithm.Wyhash(9007199254740992u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "d909d64cb42392a9")
        testKatHex({ Algorithm.Wyhash(18014398509481984u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "14bc23f9121b0c46")
        testKatHex({ Algorithm.Wyhash(36028797018963968u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "f9ea85f53d927daa")
        testKatHex({ Algorithm.Wyhash(72057594037927936u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "31b06495ede3dcfd")
        testKatHex({ Algorithm.Wyhash(144115188075855872u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "20c9f87d4ed02006")
        testKatHex({ Algorithm.Wyhash(288230376151711744u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "0a064b1d9f9bae33")
        testKatHex({ Algorithm.Wyhash(576460752303423488u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "5bd57178ab763e3b")
        testKatHex({ Algorithm.Wyhash(1152921504606846976u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "e7f2c579284ac573")
        testKatHex({ Algorithm.Wyhash(2305843009213693952u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "869324f5ee91eed2")
        testKatHex({ Algorithm.Wyhash(4611686018427387904u, extraProtection = true).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "1b5e59bc4c89308f")
        testKatHex({ Algorithm.Wyhash(18446744073709551614u, extraProtection = true).createDigest() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "3bfb021f444ce6ad")
        testKatHex({ Algorithm.Wyhash(18446744073709551612u, extraProtection = true).createDigest() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "66dcf15a2bdec940")
        testKatHex({ Algorithm.Wyhash(18446744073709551608u, extraProtection = true).createDigest() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "b634c0584bbe18c1")
        testKatHex({ Algorithm.Wyhash(18446744073709551600u, extraProtection = true).createDigest() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "1ae4a8b974d693f7")
        testKatHex({ Algorithm.Wyhash(18446744073709551584u, extraProtection = true).createDigest() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "8926d1126bd267d2")
        testKatHex({ Algorithm.Wyhash(18446744073709551552u, extraProtection = true).createDigest() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "c23ad76b85f1ea2c")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "a2e7c10f0ec39168")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "25f48ed64989e342")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "679ad6f1910f1791")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "ebecebe35f6cdf5a")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "baa520308890b747")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "6b1f6fedcd0a4313")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "ba5cdcaacc7ba149")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "43cc244e20b5eb50")
        testKatHex({ Algorithm.Wyhash(18446744073709551488u, extraProtection = true).createDigest() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "297ad611b4d8e9a3")
    }
}
