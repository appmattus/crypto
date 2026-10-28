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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Test vectors from [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861) appendix A.4 and A.5, where ptn(n) is the
 * repeating pattern 00 01 .. FA of length n. The two largest messages are covered in KangarooTwelveLargeTest.
 */
class KangarooTwelveTest {

    @Test
    fun kt128MatchesRfc9861Vectors() {
        kt128Vectors.forEach { (message, customisation, expected) ->
            testKat({ Algorithm.KT128(customisation).createDigest() }, message, expected)
        }
    }

    @Test
    fun kt256MatchesRfc9861Vectors() {
        kt256Vectors.forEach { (message, customisation, expected) ->
            testKat({ Algorithm.KT256(customisation).createDigest() }, message, expected)
        }
    }

    @Test
    fun kt128SupportsLongerOutput() {
        assertEquals(
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71",
            Algorithm.KT128(outputSizeBits = 512).hash(ByteArray(0)).toHexString()
        )
        assertEquals(
            "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d",
            Algorithm.KT128(outputSizeBits = 10032 * 8).hash(ByteArray(0)).takeLast(32).toByteArray().toHexString()
        )
    }

    @Test
    fun kt256SupportsLongerOutput() {
        assertEquals(
            "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9b0925319d8ea1e121a609821ec19efea89e6d08daee1662b69c840289f188ba860f55760b61f82114c030c97e5178449608ccd2cd2d919fc7829ff69931ac4d0",
            Algorithm.KT256(outputSizeBits = 1024).hash(ByteArray(0)).toHexString()
        )
        assertEquals(
            "ad4a1d718cf950506709a4c33396139b4449041fc79a05d68da35f1e453522e056c64fe94958e7085f2964888259b9932752f3ccd855288efee5fcbb8b563069",
            Algorithm.KT256(outputSizeBits = 10064 * 8).hash(ByteArray(0)).takeLast(64).toByteArray().toHexString()
        )
    }

    @Test
    fun nullCustomisationMatchesEmptyCustomisation() {
        assertContentEquals(Algorithm.KT128(ByteArray(0)).hash(ptn(100)), Algorithm.KT128().hash(ptn(100)))
        assertContentEquals(Algorithm.KT256(ByteArray(0)).hash(ptn(100)), Algorithm.KT256().hash(ptn(100)))
    }

    @Test
    fun invalidOutputSizeIsRejected() {
        assertFailsWith<IllegalArgumentException> { Algorithm.KT128(outputSizeBits = 0) }
        assertFailsWith<IllegalArgumentException> { Algorithm.KT256(outputSizeBits = 12) }
    }

    private companion object {
        val kt128Vectors = listOf(
            Triple(ByteArray(0), ByteArray(0), "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"),
            Triple(ptn(1), ByteArray(0), "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f"),
            Triple(ptn(17), ByteArray(0), "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888"),
            Triple(ptn(289), ByteArray(0), "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c"),
            Triple(ptn(4913), ByteArray(0), "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0"),
            Triple(ptn(83521), ByteArray(0), "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe"),
            Triple(ByteArray(0), ptn(1), "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583"),
            Triple(strtobin("ff"), ptn(41), "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"),
            Triple(strtobin("ffffff"), ptn(1681), "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74"),
            Triple(
                strtobin("ffffffffffffff"),
                ptn(68921),
                "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf"
            ),
            Triple(ptn(8191), ByteArray(0), "1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6"),
            Triple(ptn(8192), ByteArray(0), "48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3"),
            Triple(ptn(8192), ptn(8189), "3ed12f70fb05ddb58689510ab3e4d23c6c6033849aa01e1d8c220a297fedcd0b"),
            Triple(ptn(8192), ptn(8190), "6a7c1b6a5cd0d8c9ca943a4a216cc64604559a2ea45f78570a15253d67ba00ae")
        )

        val kt256Vectors = listOf(
            Triple(
                ByteArray(0),
                ByteArray(0),
                "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
            ),
            Triple(
                ptn(1),
                ByteArray(0),
                "0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0"
            ),
            Triple(
                ptn(17),
                ByteArray(0),
                "1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b"
            ),
            Triple(
                ptn(289),
                ByteArray(0),
                "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba"
            ),
            Triple(
                ptn(4913),
                ByteArray(0),
                "647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5"
            ),
            Triple(
                ptn(83521),
                ByteArray(0),
                "b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f08bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d"
            ),
            Triple(
                ByteArray(0),
                ptn(1),
                "9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b159811f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6"
            ),
            Triple(
                strtobin("ff"),
                ptn(41),
                "47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf845d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853"
            ),
            Triple(
                strtobin("ffffff"),
                ptn(1681),
                "3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172cb438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969"
            ),
            Triple(
                strtobin("ffffffffffffff"),
                ptn(68921),
                "e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724"
            ),
            Triple(
                ptn(8191),
                ByteArray(0),
                "3081434d93a4108d8d8a3305b89682cebedc7ca4ea8a3ce869fbb73cbe4a58eef6f24de38ffc170514c70e7ab2d01f03812616e863d769afb3753193ba045b20"
            ),
            Triple(
                ptn(8192),
                ByteArray(0),
                "c6ee8e2ad3200c018ac87aaa031cdac22121b412d07dc6e0dccbb53423747e9a1c18834d99df596cf0cf4b8dfafb7bf02d139d0c9035725adc1a01b7230a41fa"
            ),
            Triple(
                ptn(8192),
                ptn(8189),
                "74e47879f10a9c5d11bd2da7e194fe57e86378bf3c3f7448eff3c576a0f18c5caae0999979512090a7f348af4260d4de3c37f1ecaf8d2c2c96c1d16c64b12496"
            ),
            Triple(
                ptn(8192),
                ptn(8190),
                "f4b5908b929ffe01e0f79ec2f21243d41a396b2e7303a6af1d6399cd6c7a0a2dd7c4f607e8277f9c9b1cb4ab9ddc59d4b92d1fc7558441f1832c3279a4241b8b"
            )
        )
    }
}

internal fun ptn(length: Int) = ByteArray(length) { (it % 251).toByte() }
