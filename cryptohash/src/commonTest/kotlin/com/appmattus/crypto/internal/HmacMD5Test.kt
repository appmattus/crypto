package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import kotlin.test.Test

class HmacMD5Test {

    /**
     * Test HMAC MD5 implementation.
     */
    @Test
    fun testHmacMd5() {

        testHmac(
            Algorithm.MD5,
            "",
            "More text test vectors to stuff up EBCDIC machines :-)",
            "e9139d1e6ee064ef8cf514fc7dc83e86"
        )

        // From RFC 2104

        testHmac(
            Algorithm.MD5,
            "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
            "Hi There",
            "9294727A3638BB1C13F48EF8158BFC9D"
        )
        testHmac(
            Algorithm.MD5,
            "Jefe".encodeToByteArray(),
            "what do ya want for nothing?".encodeToByteArray(),
            "750C783E6AB0B503EAA86E310A5DB738"
        )
        testHmacHex(
            Algorithm.MD5,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
            "56BE34521D144C88DBB8C733F0E8B3F6"
        )

        // From https://datatracker.ietf.org/doc/html/rfc2202.html

        testHmac(
            Algorithm.MD5,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "56461ef2342edc00f9bab995",
            // truncate to 96 bits
            12
        )

        testHmac(
            Algorithm.MD5,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        )

        testHmac(
            Algorithm.MD5,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "6f630fad67cda0ee1fb1f562db3aa53e"
        )
    }

    @Test
    fun misc() {
        // From https://github.com/crypto-browserify/hash-test-vectors/blob/master/hmac.json

        testHmac(
            Algorithm.MD5,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "5ccec34ea9656392457fa1ac27f08fbc"
        )

        testHmacHex(
            Algorithm.MD5,
            "4a656665",
            "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
            "f1bbf62a07a5ea3e72072d12e9e25014"
        )

        testHmacHex(
            Algorithm.MD5,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "2ab8b9a9f7d3894d15ad8383b97044b2"
        )

        testHmacHex(
            Algorithm.MD5,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "697eaf0aca3a3aea3a75164746ffaa79"
        )

        testHmac(
            Algorithm.MD5,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "951726cea438b8e106e43b3d87a19c8e",
            // truncate to 128 bits
            16
        )

        testHmac(
            Algorithm.MD5,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "09b8ae7b15adbbb243aca3491b51512b"
        )
    }

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.MD5,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "80070713463e7749b90c2dc24911e275"
        )
    }

    @Test
    fun testMd5Seq() {
        val expectedOutput = listOf(
            "C91E40247251F39BDFE6A7B72A5857F9",
            "00FF2644D0E3699F677F58ECDF57082F",
            "1B6C2DB6819A4F023FFE21B91E284E93",
            "04B0ED3E73FBB9A94444FDFFAA530695",
            "1557A22261110DFB31ACE25936BDE45D",
            "54C5A67A9CB4544CA66BBDA1A2B8479E",
            "F803D9E43C934545AF078FFBB34BC30B",
            "32F56EA655DF36D845E430D637C85D17",
            "14BD2095F4A478C10EEBFF379DE76DD3",
            "AAF6867B3FA01DD26312B0DFD6371A2A",
            "0FA2A6FEFEBE7CE3C31A38400F8AB260",
            "54C37BE13B7333287D0E74AA9D9227F6",
            "385D75A58B0C95E5CDC059DB168BD1D2",
            "E73003103ED65C08E62D46AE1E1B771A",
            "278ED4A4EBEA1FFA5EEC874F198C0CC0",
            "F65CE9EEA7FDB90B9CC603329D3FB9A9",
            "8640836944EE0009B2CC6FDC3F5C39E1",
            "7819A99F82BABDF060AA51AE109629DB",
            "EF26336668486C76921D1DAB67ED5673",
            "13ED7BC140F1496E09AD29C644586957",
            "5FDD337CE9C4AC8D910833FCC2BD837E",
            "E9470246ABF7CF4D37FD378738D8F763",
            "384A75C33EFFA12EB69187BB80DF843B",
            "63866A5406B9EA0341032FCFD0244A4B",
            "8042F8572C8A9B88E135ACB83EF1FD39",
            "BD1BE6AF2D022F966F612569E191F0E9",
            "9F70C839533EE4C7B3CF20C6FB65C94C",
            "800A5CE92CA4FEE6F1D353F496113873",
            "C35E93E1E54C84C4389D2DE71E1B9846",
            "A130EF5F91465F5A56999F450E63F4F9",
            "5F16564E05285A099F628245DF9A3C2A",
            "A34F7E3DF06DD84CC67E8A922240D60B",
            "945E50753B6E6C920183822D5F280F10",
            "2DDD269DBCDF5C21A1C3FD540FF4ABA9",
            "212FE3E2CEF7DF74FC01CC2CC83119B8",
            "D98B2930011649F16C08BC8C0178D838",
            "E39E21026111C1EFB0C491C0FDFA841D",
            "AE46DE06C3B0D2CEC35352C95A1003F0",
            "5550EE50BF88C9DE5ADA34567FE044C7",
            "6BC486627760373EACFF508F7032BF31",
            "AE6E0B8DBCFDCCA4B3449B57647D5AE5",
            "6BE5A0F140DFC4B75439630E6F9A36EE",
            "E3E4E735BFE79397D4653A6243DF1925",
            "68C1D9E8973A3F6B92B588469D68A2A5",
            "956132D512118D5F446C8CB912B924D9",
            "DF5C2AD650B3CA7A89EBF92EE618C845",
            "14D375CF7E4294ED99135E4237414F01",
            "DB966D40B447692E2D13CC0C09C1B495",
            "53DADCF1C6B99BD403052A1CE1ED0D14",
            "DEC4A3C1DB8F6AA4515C512C9299C4DC",
            "3B3A51DD83AB1DC56A7F0CBE1C71923F",
            "03C73353B3203EF9CDB95F9DB8750AF1",
            "ED9E15FD86D66DA2D546D2BFC55041AD",
            "81B649338F9DB1C6E592427D38221C7C",
            "92E170E13BF40FF65E3B4C665F222DD5",
            "00D5E23F5F829B21D454C4445851AB53",
            "39057029AF0B3F4391A7BDC6DDCE4D07",
            "2DEACEFA698F9CCAD5198C4E17E69A93",
            "AD35FD52EA199E26948009DF3546D3A2",
            "4C42CF2CFD4D8FD9A06E3F73D02FE818",
            "4D7C893E4313FFF72103854463414277",
            "3F04E8B32AB56EAF216503E46BD7AEBE",
            "F015DDC3EEF41ECC93E944FA3577DB52",
            "31F77A50A2ED96ED8E4A3CE04B9DAA23",
            "FBF481373481756E0C88978F7E0809A2",
            "7D8D793B287C04E7D2896D76EAA5CA15",
            "DAC74AEBECC2385DD9D0C3147CCA1F78",
            "F6DDE50D37B460FF5E8B4C03A0854BD5",
            "5710D6A54A2124E06A6DADBE9BF76119",
            "19DB5D13A53E57184759F33976537AA5",
            "848DD8D32130626FBD11B0133C2A29E3",
            "4F75BE04BF2F6DD85D048DB82F19C38C",
            "4AE9436540ED24BCB5EC62977AC90789",
            "859D1A9FC2B795AD60F24A37EB9EF890",
            "CD45865317FD17B652DE9F9EBBBA16B6",
            "52313319D395F453BA2C0A0159CF180B",
            "A7B190C0EECACCA4DFC5B45DFB324718",
            "23E85CAE85B50F45F7F48EE0F22FDE85",
            "6A80DBFF139A5345235EF76586CFCBC7",
            "850E638FCE5A2F3B1D1FE9C28F05EF49",
            "797CDC3F7E271FC9A3D0566A905D1CFE",
            "030CE97A9A0B1D5403E253D883FCAF12",
            "648FFFF44E416D9DE606BA0DDB751194",
            "FE15098E0DAC65FA8EE45CAC67121CC9",
            "17C90ECD390A8B41046B4C7FA0354E4F",
            "7D149DFF5F6379B7DBF5C401DB6D2976",
            "8D055A4701DD51CB9D1AF8E2AE59BD21",
            "F3481CB07B034EB4A023D00D4FDA9A86",
            "FEB22562FFAAA9CCE5CDDA34C29E55C3",
            "A620AA447216709D8CE5C5F23474ECF8",
            "F25FCBB2BF7440C5E3C5B53092B8C828",
            "DBBAE1CF60BBCA0B05EDEA0B362F0A33",
            "E18E85BCB4633A797FAF7975CEF44B84",
            "1BE27EEC72C2EDE151978705C7C7DED2",
            "A15D36C5C5BED77699838832FC225DD8",
            "08F31E68BFBBB420742F80B20B69BE8C",
            "5E9B4B5B3228F533BA8EFC3C0B9AAD3D",
            "1239BA6D941D1D8AD2ED561BF517D4B4",
            "5233F50218E0D097EFCC68F1536F30AE",
            "340B47C78B003272EAA4B9D22C3B0542",
            "E7F11759FE8A897364C21767570885BB",
            "054BD6ACBFD5421C0290B0839C0A0ACC",
            "CC0748F7B2CC921CF5FA019F955066C9",
            "A4DF167697949B1AEDBBA3226A334BAA",
            "29893B9776BA5E750A9FCEA37B0116AE",
            "2DC25C935F006F7965FAB3256D77004D",
            "24089811FFF2189FB9AF38651F43977D",
            "0E048569D634BF652CD8EBF859C9B69A",
            "00386B569DAB73844A708BA5B48BBAA8",
            "8033E1AFFBE1218F81C8331343FBE5B5",
            "9B82008A34F3847C1204ACA89F3D57D1",
            "BE1A529F88AA05A42AFC40F663E97849",
            "5237637AA645E83B0E56A1361AB80643",
            "15BC4405E891ADAF48FA56D4356705D5",
            "0820087438832B63AADC479CFC88BDBF",
            "B1E3BA7E96605D5FF614B1BEC1F57AC1",
            "838A096D64E6C0DDB069DC89E4C3F839",
            "934BCE159F3959A933C87AB497CA8D42",
            "CA501F1DE619A570DC38FDCB8B3F7722",
            "033B27D5994A6F5D5F6800539B69E876",
            "B447FC68FEF4E3CF9290B06EB6AECAA3",
            "DD3D3F72F0F1FBCD030D839DCFEE457A",
            "EE73C4C996E0150D93B3144F20FB2C1B",
            "5AF9679D2441542391C6A903FD8C1626",
            "2BD84B87230511DAE7256B62A46AA45E",
            "EB159E5694C191F7708951EBC0AAF135",
            "60F02EFE1DAFAACF65F6664A2321B153",
            "14E5A0E90D4420E765C4324B68174F46",
            "09F1503BCD00E3A1B965B66B9609E998",
        )

        var key = ByteArray(16) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.MD5,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
