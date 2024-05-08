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
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacKeccak512Test {

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.Keccak512,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "22fb03b3391bc0adfc73c18e0919d9f142390e81d6cc2689716ac53ab75458a718059d58cfbb23c6a416c32b8afa84a9a7a9d852312a743bef0a55148e5a1b8a"
        )
    }

    @Test
    fun bc() {
        // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/KeccakDigestTest.java

        testHmac(
            Algorithm.Keccak512,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "8852c63be8cfc21541a4ee5e5a9a852fc2f7a9adec2ff3a13718ab4ed81aaea0b87b7eb397323548e261a64e7fc75198f6663a11b22cd957f7c8ec858a1c7755"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "c2962e5bbe1238007852f79d814dbbecd4682e6f097d37a363587c03bfa2eb0859d8d9c701e04cececfd3dd7bfd438f20b8b648e01bf8c11d26824b96cebbdcb"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "eb0ed9580e0ec11fc66cbb646b1be904eaff6da4556d9334f65ee4b2c85739157bae9027c51505e49d1bb81cfa55e6822db55262d5a252c088a29a5e95b84a66"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "b46193bb59f4f696bf702597616da91e2a4558a593f4b015e69141ba81e1e50ea580834c2b87f87baa25a3a03bfc9bb389847f2dc820beae69d30c4bb75369cb"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "d05888a6ebf8460423ea7bc85ea4ffda847b32df32291d2ce115fd187707325c7ce4f71880d91008084ce24a38795d20e6a28328a0f0712dc38253370da3ebb5"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "2c6b9748d35c4c8db0b4407dd2ed2381f133bdbd1dfaa69e30051eb6badfcca64299b88ae05fdbd3dd3dd7fe627e42e39e48b0fe8c7f1e85f2dbd52c2d753572"
        )
        testHmacHex(
            Algorithm.Keccak512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "6adc502f14e27812402fc81a807b28bf8a53c87bea7a1df6256bf66f5de1a4cb741407ad15ab8abc136846057f881969fbb159c321c904bfb557b77afb7778c8"
        )

        testHmac(
            Algorithm.Keccak512,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "04c929fead434bba190dacfa554ce3f5",
            16
        )
    }
}
