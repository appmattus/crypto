package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import kotlin.test.Test

class HmacMD2Test {

    @Test
    fun testFromBc() {
        testHmac(
            Algorithm.MD2,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "dc1923ef5f161d35bef839ca8c807808"
        )
    }

    @Test
    fun testMd2Seq() {
        val expectedOutput = listOf(
            "D39AD9DDE006587A8BE949B11B9288F8",
            "FCB21B5348C95E8A8DCBEE50A80302CA",
            "2F26B6ACCD0E03FE9B21A1B0E75FF665",
            "17CF85D985D0D85F545897CD42C6EFE5",
            "1537A6943B4F5AC1272E4161225D987B",
            "83E17165D62CA6E4B9ED67DF1E599954",
            "7A3195C863DFF86A98968F254E128E61",
            "BD05057AEBFCB92FA4B07456085EC6C2",
            "23AC0D307BFC2E87760F8BDB21851DF8",
            "2CD26A2F2994106A375BEB0433575BDE",
            "1F63BFC44FDBE9A966CD90DF82265EFD",
            "72735FAADC3819CC24CFCE1D589BA311",
            "28B589C3C8078B8FFEF1C8297E33C1E6",
            "70A6DC014CAD2752931A47C0879D2371",
            "81694317A37FFBA816504974F38B4829",
            "72F26208B3051F1B938EA7E03DD8C107",
            "F945F57FE0696A4C81EC59AE69384FAB",
            "54D8DFCEE33969486956698495B4BFD0",
            "508B82F88A234E753A9E305E15A14D82",
            "527D77D2AB25131693B02F653ACBD90E",
            "4868AC540FCC3A896D5A89F7A0444D36",
            "6189807C5FDDDD68D20356ADF3B90DC2",
            "0356362F2BC4206F2B930C4282213758",
            "2F59956F19B3CAD687C66C4EC3CC916D",
            "E30CEFBDA3FA1A8EDDE3B72614ADDEDF",
            "33E0E6BFCBC9581BBCDF13F4D3F26724",
            "B11C6476F9775219A9F18B5E88857790",
            "49C7A9D7F56344BD405E53BE927E3A58",
            "99A06874B0F0CA45C9F29E05D213195F",
            "D21A60A18F061FC453AD5AC2A519071A",
            "2F735E82090144C036E3D12DEF2E0030",
            "F9539EAC81BBCD0069A31E2A3C43769D",
            "EDCAA9C85A614AB6A620B25AF955D66A"
        )

        var key = ByteArray(16) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.MD2,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
