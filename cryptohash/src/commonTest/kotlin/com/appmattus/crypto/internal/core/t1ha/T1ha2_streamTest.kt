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

package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

@Suppress("ClassName")
class T1ha2_streamTest {

    @Test
    fun test() {
        testKatHex({ Algorithm.T1ha2_Stream(0u).createDigest() }, "", "3C8426E33CB41606")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551615u).createDigest() }, "", "FD74BE70EE73E617")
        testKatHex({ Algorithm.T1ha2_Stream(0u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "F43DE3CDD8A20486")
        testKatHex({ Algorithm.T1ha2_Stream(1u).createDigest() }, "00", "882FBCB37E8EA3BB")
        testKatHex({ Algorithm.T1ha2_Stream(2u).createDigest() }, "0001", "1AA2CDD34CAA3D4B")
        testKatHex({ Algorithm.T1ha2_Stream(4u).createDigest() }, "000102", "EE755B2BFAE07ED5")
        testKatHex({ Algorithm.T1ha2_Stream(8u).createDigest() }, "00010203", "D4E225250D92E213")
        testKatHex({ Algorithm.T1ha2_Stream(16u).createDigest() }, "0001020304", "A09B49083205965B")
        testKatHex({ Algorithm.T1ha2_Stream(32u).createDigest() }, "000102030405", "D47B21724EF9EC9E")
        testKatHex({ Algorithm.T1ha2_Stream(64u).createDigest() }, "00010203040506", "AC888FC3858CEE11")
        testKatHex({ Algorithm.T1ha2_Stream(128u).createDigest() }, "0001020304050607", "94F820D85736F244")
        testKatHex({ Algorithm.T1ha2_Stream(256u).createDigest() }, "0001020304050607ff", "1707951CCA920932")
        testKatHex({ Algorithm.T1ha2_Stream(512u).createDigest() }, "0001020304050607ff7f", "8E0E45603F7877F0")
        testKatHex({ Algorithm.T1ha2_Stream(1024u).createDigest() }, "0001020304050607ff7f3f", "9FD2592C0E3A7212")
        testKatHex({ Algorithm.T1ha2_Stream(2048u).createDigest() }, "0001020304050607ff7f3f1f", "9A66370F3AE3D427")
        testKatHex({ Algorithm.T1ha2_Stream(4096u).createDigest() }, "0001020304050607ff7f3f1f0f", "D33382D2161DE2B7")
        testKatHex({ Algorithm.T1ha2_Stream(8192u).createDigest() }, "0001020304050607ff7f3f1f0f08", "9A35BE079DA7115F")
        testKatHex({ Algorithm.T1ha2_Stream(16384u).createDigest() }, "0001020304050607ff7f3f1f0f0810", "73457C7FF58B4EC3")
        testKatHex({ Algorithm.T1ha2_Stream(32768u).createDigest() }, "0001020304050607ff7f3f1f0f081020", "BE8610BD53D7CE98")
        testKatHex({ Algorithm.T1ha2_Stream(65536u).createDigest() }, "0001020304050607ff7f3f1f0f08102040", "65506DFE5CCD5371")
        testKatHex({ Algorithm.T1ha2_Stream(131072u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080", "286A321AF9D5D9FA")
        testKatHex({ Algorithm.T1ha2_Stream(262144u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fe", "B81EF9A7EF3C536D")
        testKatHex({ Algorithm.T1ha2_Stream(524288u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefc", "2CFDB5E6825C6E86")
        testKatHex({ Algorithm.T1ha2_Stream(1048576u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "B2A58CBFDFDD303A")
        testKatHex({ Algorithm.T1ha2_Stream(2097152u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "D26094A42B950635")
        testKatHex({ Algorithm.T1ha2_Stream(4194304u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "A34D666A5F02AD9A")
        testKatHex({ Algorithm.T1ha2_Stream(8388608u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "0151E013EBCC72E5")
        testKatHex({ Algorithm.T1ha2_Stream(16777216u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "9254A6EA7FCB6BB5")
        testKatHex({ Algorithm.T1ha2_Stream(33554432u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "10C9361B3869DC2B")
        testKatHex({ Algorithm.T1ha2_Stream(67108864u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "D7EC55A060606276")
        testKatHex({ Algorithm.T1ha2_Stream(134217728u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "A2FF7F8BF8976FFD")
        testKatHex({ Algorithm.T1ha2_Stream(268435456u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "B5181BB6852DCC88")
        testKatHex({ Algorithm.T1ha2_Stream(536870912u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "0EE394BB6178BAFF")
        testKatHex({ Algorithm.T1ha2_Stream(1073741824u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "3A8B4B400D21B89C")
        testKatHex({ Algorithm.T1ha2_Stream(2147483648u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "EC270461970960FD")
        testKatHex({ Algorithm.T1ha2_Stream(4294967296u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "615967FAB053877E")
        testKatHex({ Algorithm.T1ha2_Stream(8589934592u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "FA51BF1CFEB4714C")
        testKatHex({ Algorithm.T1ha2_Stream(17179869184u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "29FDA8383070F375")
        testKatHex({ Algorithm.T1ha2_Stream(34359738368u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "C3B663061BC52EDA")
        testKatHex({ Algorithm.T1ha2_Stream(68719476736u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "192BBAF1F1A57923")
        testKatHex({ Algorithm.T1ha2_Stream(137438953472u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "6D193B52F93C53AF")
        testKatHex({ Algorithm.T1ha2_Stream(274877906944u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "7F6F5639FE87CA1E")
        testKatHex({ Algorithm.T1ha2_Stream(549755813888u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "69F7F9140B32EDC8")
        testKatHex({ Algorithm.T1ha2_Stream(1099511627776u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "D0F2416FB24325B6")
        testKatHex({ Algorithm.T1ha2_Stream(2199023255552u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "62C0E37FEDD49FF3")
        testKatHex({ Algorithm.T1ha2_Stream(4398046511104u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "57866A4B809D373D")
        testKatHex({ Algorithm.T1ha2_Stream(8796093022208u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "9848D24BD935E137")
        testKatHex({ Algorithm.T1ha2_Stream(17592186044416u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "DFC905B66734D50A")
        testKatHex({ Algorithm.T1ha2_Stream(35184372088832u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "9A938DD194A68529")
        testKatHex({ Algorithm.T1ha2_Stream(70368744177664u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "8276C44DF0625228")
        testKatHex({ Algorithm.T1ha2_Stream(140737488355328u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "A4B35D00AD67C0AB")
        testKatHex({ Algorithm.T1ha2_Stream(281474976710656u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "3D9CB359842DB452")
        testKatHex({ Algorithm.T1ha2_Stream(562949953421312u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "4241BFA8C23B267F")
        testKatHex({ Algorithm.T1ha2_Stream(1125899906842624u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "650FA517BEF15952")
        testKatHex({ Algorithm.T1ha2_Stream(2251799813685248u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "782DE2ABD8C7B1E1")
        testKatHex({ Algorithm.T1ha2_Stream(4503599627370496u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "4EAE456166CA3E15")
        testKatHex({ Algorithm.T1ha2_Stream(9007199254740992u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "40CDF3A02614E337")
        testKatHex({ Algorithm.T1ha2_Stream(18014398509481984u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "AD84092C46102172")
        testKatHex({ Algorithm.T1ha2_Stream(36028797018963968u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "0C68479B03F9A167")
        testKatHex({ Algorithm.T1ha2_Stream(72057594037927936u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "7E1BA046749E181C")
        testKatHex({ Algorithm.T1ha2_Stream(144115188075855872u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "3F3AB41A697382C1")
        testKatHex({ Algorithm.T1ha2_Stream(288230376151711744u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "C5E5DD6586EBFDC4")
        testKatHex({ Algorithm.T1ha2_Stream(576460752303423488u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "FF926CD4EB02555C")
        testKatHex({ Algorithm.T1ha2_Stream(1152921504606846976u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "035CFE67F89E709B")
        testKatHex({ Algorithm.T1ha2_Stream(2305843009213693952u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "89F06AB6464A1B9D")
        testKatHex({ Algorithm.T1ha2_Stream(4611686018427387904u).createDigest() }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "8EFF58F3F7DEA758")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551614u).createDigest() }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "8B54AC657902089F")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551612u).createDigest() }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "C6C4F1F9F8DA4D64")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551608u).createDigest() }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "BDB729048AAAC93A")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551600u).createDigest() }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "EA76BA628F5E5CD6")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551584u).createDigest() }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "742159B728B8A979")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551552u).createDigest() }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "6D151CD3C720E53D")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "E97FFF9368FCDC42")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "CA5B38314914FBDA")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "DD92C91D8B858EAE")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "66E5F07CF647CBF2")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "D4CF9B42F4985AFB")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "72AE17AC7D92F6B7")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "B8206B22AB0472E1")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "385876B5CFD42479")
        testKatHex({ Algorithm.T1ha2_Stream(18446744073709551488u).createDigest() }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "03294A249EBE6B26")
    }
}
