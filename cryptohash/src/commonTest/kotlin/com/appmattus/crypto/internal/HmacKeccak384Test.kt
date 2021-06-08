package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacKeccak384Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak384,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "73acb07b5b1db5431758262b55e5923d362de4492229a7420302c80d4348ca1b11ecea06fb1c232f9b832aadca8cd289"
        )
    }

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/KeccakDigestTest.java

        testHmac(
            Algorithm.Keccak384,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "892dfdf5d51e4679bf320cd16d4c9dc6f749744608e003add7fba894acff87361efa4e5799be06b6461f43b60ae97048"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5af5c9a77a23a6a93d80649e562ab77f4f3552e3c5caffd93bdf8b3cfc6920e3023fc26775d9df1f3c94613146ad2c9d"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "4243c29f2201992ff96441e3b91ff81d8c601d706fbc83252684a4bc51101ca9b2c06ddd03677303c502ac5331752a3c"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "b730724d3d4090cda1be799f63acbbe389fef7792fc18676fa5453aab398664650ed029c3498bbe8056f06c658e1e693"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "d62482ef601d7847439b55236e9679388ffcd53c62cd126f39be6ea63de762e26cd5974cb9a8de401b786b5555040f6f"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "4860ea191ac34994cf88957afe5a836ef36e4cc1a66d75bf77defb7576122d75f60660e4cf731c6effac06402787e2b9"
        )
        testHmacHex(
            Algorithm.Keccak384,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "fe9357e3cfa538eb0373a2ce8f1e26ad6590afdaf266f1300522e8896d27e73f654d0631c8fa598d4bb82af6b744f4f5"
        )

        testHmac(
            Algorithm.Keccak384,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "fa9aea2bc1e181e47cbb8c3df243814d",
            16
        )
    }
}
