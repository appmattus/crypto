package com.appmattus.crypto.internal.core.t1ha

import com.appmattus.crypto.internal.core.sphlib.testKatHex
import kotlin.test.Test

@Suppress("ClassName")
class T1ha0_32leTest {

    @Test
    fun test() {
        testKatHex({ T1ha0_32le(0u) }, "", "0000000000000000")
        testKatHex({ T1ha0_32le(18446744073709551615u) }, "", "c92229c10faea50e")
        testKatHex({ T1ha0_32le(0u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "3df1354b0dfdc443")
        testKatHex({ T1ha0_32le(1u) }, "00", "968f016d60417bb3")
        testKatHex({ T1ha0_32le(2u) }, "0001", "85aafb50c6da770f")
        testKatHex({ T1ha0_32le(4u) }, "000102", "66cce3bb6842c7d6")
        testKatHex({ T1ha0_32le(8u) }, "00010203", "ddaa39c11537c226")
        testKatHex({ T1ha0_32le(16u) }, "0001020304", "35958d281f0c9c8c")
        testKatHex({ T1ha0_32le(32u) }, "000102030405", "8c5d64b091de608e")
        testKatHex({ T1ha0_32le(64u) }, "00010203040506", "4094df680d39786b")
        testKatHex({ T1ha0_32le(128u) }, "0001020304050607", "1014f4aa2a2edf4d")
        testKatHex({ T1ha0_32le(256u) }, "0001020304050607ff", "39d21891615aa310")
        testKatHex({ T1ha0_32le(512u) }, "0001020304050607ff7f", "7ef51f67c398c7c4")
        testKatHex({ T1ha0_32le(1024u) }, "0001020304050607ff7f3f", "06163990ddbf319d")
        testKatHex({ T1ha0_32le(2048u) }, "0001020304050607ff7f3f1f", "e229caa00c8d6f3f")
        testKatHex({ T1ha0_32le(4096u) }, "0001020304050607ff7f3f1f0f", "d2240b4b0d54e0f5")
        testKatHex({ T1ha0_32le(8192u) }, "0001020304050607ff7f3f1f0f08", "ea2e7e905ddeaf94")
        testKatHex({ T1ha0_32le(16384u) }, "0001020304050607ff7f3f1f0f0810", "8d4f8a887183a5ce")
        testKatHex({ T1ha0_32le(32768u) }, "0001020304050607ff7f3f1f0f081020", "44337f9a63c5820c")
        testKatHex({ T1ha0_32le(65536u) }, "0001020304050607ff7f3f1f0f08102040", "94938d1e86a9b797")
        testKatHex({ T1ha0_32le(131072u) }, "0001020304050607ff7f3f1f0f0810204080", "96e9caba5ca210cc")
        testKatHex({ T1ha0_32le(262144u) }, "0001020304050607ff7f3f1f0f0810204080fe", "6efbb9cc9e8f7708")
        testKatHex({ T1ha0_32le(524288u) }, "0001020304050607ff7f3f1f0f0810204080fefc", "3d12ea0282fb8bbc")
        testKatHex({ T1ha0_32le(1048576u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8", "5da781ee205a2c48")
        testKatHex({ T1ha0_32le(2097152u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0", "fa4a51a12677fe12")
        testKatHex({ T1ha0_32le(4194304u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0", "81d5f04e20660b28")
        testKatHex({ T1ha0_32le(8388608u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0", "57258d043bcd3841")
        testKatHex({ T1ha0_32le(16777216u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fd", "5c9beb62059c1ed2")
        testKatHex({ T1ha0_32le(33554432u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfb", "57a02162f9034b33")
        testKatHex({ T1ha0_32le(67108864u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7", "ba2a13e457ce19b8")
        testKatHex({ T1ha0_32le(134217728u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7ef", "e593263bf9451f3a")
        testKatHex({ T1ha0_32le(268435456u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdf", "0bc1175539606bc5")
        testKatHex({ T1ha0_32le(536870912u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf", "a3e2929e9c5f289f")
        testKatHex({ T1ha0_32le(1073741824u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55", "86bdbd06835e35f7")
        testKatHex({ T1ha0_32le(2147483648u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa", "a180950ab48baadc")
        testKatHex({ T1ha0_32le(4294967296u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b", "7812c994d9924028")
        testKatHex({ T1ha0_32le(8589934592u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b11", "308366011415f46b")
        testKatHex({ T1ha0_32le(17179869184u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113", "77fe9a9991c5f959")
        testKatHex({ T1ha0_32le(34359738368u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b111317", "925c340b70b0b1e3")
        testKatHex({ T1ha0_32le(68719476736u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d", "cd9c5ba4c41e2e10")
        testKatHex({ T1ha0_32le(137438953472u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d25", "7cc4e7758b94cd93")
        testKatHex({ T1ha0_32le(274877906944u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a", "898b235962ea4625")
        testKatHex({ T1ha0_32le(549755813888u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b", "d7e3e5bf22893286")
        testKatHex({ T1ha0_32le(1099511627776u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61", "396f4cdd33056c64")
        testKatHex({ T1ha0_32le(2199023255552u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162", "740ab2e32f17cd9f")
        testKatHex({ T1ha0_32le(4398046511104u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263", "60d12ff9cd15b321")
        testKatHex({ T1ha0_32le(8796093022208u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364", "bee3a6c9903a81d8")
        testKatHex({ T1ha0_32le(17592186044416u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465", "b47040913b33c35e")
        testKatHex({ T1ha0_32le(35184372088832u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566", "19ee8c2acc013cff")
        testKatHex({ T1ha0_32le(70368744177664u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b61626364656667", "5dec94c5783b55c4")
        testKatHex({ T1ha0_32le(140737488355328u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768", "78dc122d562c5f1d")
        testKatHex({ T1ha0_32le(281474976710656u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b616263646566676869", "6520f008da1c181e")
        testKatHex({ T1ha0_32le(562949953421312u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a", "77caf155a36ebf7c")
        testKatHex({ T1ha0_32le(1125899906842624u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b", "0a09e02bdb883ca6")
        testKatHex({ T1ha0_32le(2251799813685248u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c", "fd5d9ada7e3fb895")
        testKatHex({ T1ha0_32le(4503599627370496u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d", "c6f5fdd9eeab83b5")
        testKatHex({ T1ha0_32le(9007199254740992u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e", "84589bb29f52a92a")
        testKatHex({ T1ha0_32le(18014398509481984u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f", "9b2517f13f8e9814")
        testKatHex({ T1ha0_32le(36028797018963968u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70", "6f752af6a52e31ec")
        testKatHex({ T1ha0_32le(72057594037927936u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071", "8e717799e324ce8a")
        testKatHex({ T1ha0_32le(144115188075855872u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172", "84d90aef39262d58")
        testKatHex({ T1ha0_32le(288230376151711744u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273", "79c27b13fc28944d")
        testKatHex({ T1ha0_32le(576460752303423488u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374", "e6d6df6438e0044a")
        testKatHex({ T1ha0_32le(1152921504606846976u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475", "51b603e400d79ca4")
        testKatHex({ T1ha0_32le(2305843009213693952u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f70717273747576", "6a902b28c588b390")
        testKatHex({ T1ha0_32le(4611686018427387904u) }, "0001020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f7071727374757677", "8d7f8de9e6cb1d83")
        testKatHex({ T1ha0_32le(18446744073709551614u) }, "01020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "cf1a4dc11ca7f044")
        testKatHex({ T1ha0_32le(18446744073709551612u) }, "020304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "ef02e43c366786f1")
        testKatHex({ T1ha0_32le(18446744073709551608u) }, "0304050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "89915bcdbcfbe30f")
        testKatHex({ T1ha0_32le(18446744073709551600u) }, "04050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "5928b306f1a9cc7f")
        testKatHex({ T1ha0_32le(18446744073709551584u) }, "050607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "a8b59092996851c5")
        testKatHex({ T1ha0_32le(18446744073709551552u) }, "0607ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "22050a20427e8b25")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "07ff7f3f1f0f0810204080fefcf8f0e0c0fdfbf7efdfbf55aa0b1113171d252a2b6162636465666768696a6b6c6d6e6f707172737475767778", "6e6d64018941e7ee")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "9798c898b81ae846")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091", "80ef218cdc30124a")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3", "fce45e60d55b0284")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "4010e735d3147c35")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "eb647d999fd8dc7e")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9", "d3544dcab14fe907")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb", "b588b27d8438700c")
        testKatHex({ T1ha0_32le(18446744073709551488u) }, "0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd", "a49ebfc43e057a4c")
    }
}