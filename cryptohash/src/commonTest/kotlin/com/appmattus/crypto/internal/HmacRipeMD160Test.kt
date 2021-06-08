package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.HMAC
import com.appmattus.crypto.internal.core.sphlib.strtobin
import com.appmattus.crypto.internal.core.sphlib.testHmac
import com.appmattus.crypto.internal.core.sphlib.testHmacHex
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import kotlin.test.Test

class HmacRipeMD160Test {

    @Test
    fun testHmacRipemd160() {
        // From https://datatracker.ietf.org/doc/html/rfc2286.html

        testHmac(
            Algorithm.RipeMD160,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "Hi There",
            "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"
        )

        testHmac(
            Algorithm.RipeMD160,
            "4a656665",
            "what do ya want for nothing?",
            "dda6c0213a485a9e24f4742064a7f033b43c4069"
        )

        testHmacHex(
            Algorithm.RipeMD160,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "b0b105360de759960ab4f35298e116e295d8e7c1"
        )

        testHmacHex(
            Algorithm.RipeMD160,
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4"
        )

        testHmac(
            Algorithm.RipeMD160,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "7619693978f91d90539ae786",
            // truncate to 96 bits
            12
        )

        testHmac(
            Algorithm.RipeMD160,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "6466ca07ac5eac29e1bd523e5ada7605b791fd8b"
        )

        testHmac(
            Algorithm.RipeMD160,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "69ea60798d71616cce5fd0871e23754cd75d5a0a"
        )

        // From https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "",
            "cf387677bfda8483e63b57e06c3b5ecd8b7fc055"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "a",
            "0d351d71b78e36dbb7391c810a0d2b6240ddbafc"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "abc",
            "f7ef288cb1bbcc6160d76507e0a3bbf712fb67d6"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "message digest",
            "f83662cc8d339c227e600fcd636c57d2571b1c34"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "abcdefghijklmnopqrstuvwxyz",
            "843d1c4eb880ac8ac0c9c95696507957d0155ddb"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "60f5ef198a2dd5745545c1f0c47aa3fb5776f881"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "e49c136a9e5627e0681b808a3b97e6a6e661ae79"
        )
        testHmac(
            Algorithm.RipeMD160,
            "00112233445566778899aabbccddeeff01234567",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "31be3cc98cee37b79b0619e3e1c2be4f1aa56e6c"
        )
        testKatMillionA(
            HMAC(Algorithm.RipeMD160.createDigest(), strtobin("00112233445566778899aabbccddeeff01234567")),
            "c2aa88c6405658dc225e485488371fb2433fa735"
        )

        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "",
            "fe69a66c7423eea9c8fa2eff8d9dafb4f17a62f5"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "a",
            "85743e899bc82dbfa36faaa7a25b7cfd372432cd"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "abc",
            "6e4afd501fa6b4a1823ca3b10bd9aa0ba97ba182"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "message digest",
            "2e066e624badb76a184c8f90fba053330e650e92"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "abcdefghijklmnopqrstuvwxyz",
            "07e942aa4e3cd7c04dedc1d46e2e8cc4c741b3d9"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "b6582318ddcfb67a53a67d676b8ad869aded629a"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "f1be3ee877703140d34f97ea1ab3a07c141333e2"
        )
        testHmac(
            Algorithm.RipeMD160,
            "0123456789abcdeffedcba987654321000112233",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "85f164703e61a63131be7e45958e0794123904f9"
        )
        testKatMillionA(
            HMAC(Algorithm.RipeMD160.createDigest(), strtobin("0123456789abcdeffedcba987654321000112233")),
            "82a504a002ba6e6c67f3cd67cedb66dc169bab7a"
        )
    }

    @Test
    fun misc() {
        // From https://github.com/crypto-browserify/hash-test-vectors/blob/master/hmac.json

        testHmacHex(
            Algorithm.RipeMD160,
            "4a656665",
            "7768617420646f2079612077616e74207768617420646f2079612077616e7420",
            "c15633df3b0940bb067d0c25f3da75c5293da6d6"
        )

        testHmac(
            Algorithm.RipeMD160,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "Test With Truncation",
            "7619693978f91d90539ae786500ff3d8",
            // truncate to 128 bits
            16
        )

        testHmac(
            Algorithm.RipeMD160,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "1ed106e5a8ef0a90efa3beb06b391e8693cd3137"
        )
    }

    @Test
    fun misc2() {
        // From https://github.com/xsc/pandect/blob/master/test/pandect/hmac_test.clj

        testHmac(
            Algorithm.RipeMD160,
            "6b6579",
            "The quick brown fox jumps over the lazy dog",
            "50278a77d4d7670561ab72e867383aef6ce50b3e"
        )
    }

    @Test
    fun testRipeMd160Seq() {
        val expectedOutput = listOf(
            "33528FDB4FD0640B4C4363CEF1DE795719EBC7EE",
            "514DF566C6204373EEE6020054AE7DDE2B0934DB",
            "CC8A5C8D2EBA02BF4474A4CC05CC2D863F1AA392",
            "27D731E218C369A32BE4B2BB29D2F1A0988BA583",
            "091245BFADF5C6635298702F233ECB3265E85460",
            "BD2C07FA2197201DCA309063881F2EAC9D925A21",
            "480886856354E6FF34B3AFAF9E63FB794BAC4521",
            "258D58532BEB5EAD28E9BCA52AA4C0444CC2467A",
            "DB7513F824B42A9E1FFC1369F22F61054A3EB7F0",
            "3A4A258F23675EE02E1AC1F72197D1A11F32DE21",
            "9315ACAAAA8DC91A9AAF8DDD4CD000AE04F70E1D",
            "57D60D77E1D78D23D3F184740D9DE392FC6C3C40",
            "950395C815A3D1A4A8BB25322333FECA15445BFB",
            "F8201A01C30F3B569B7497B5191AE16D1705085D",
            "08DEA1A0CD4BD6C9031C84FD2005F15810FF088B",
            "CF41D88EB3921FA137F0203C2CB8BC5200FDE7BE",
            "A07100AAACF5253501A6643452D07C7DE2EA824E",
            "19DE22082D1F4535A733F16262A135358D651737",
            "D50BD92902AE0127AC8DD85E9A81ADB7EF3F1E64",
            "3FA34A3C02E06DE451794AB87C4FCE6877458CDA",
            "5928329E4D830E8B2F7608A4ED46DCCFD5798425",
            "2825DBD7989A8978904A654E6AF125608B0BEBC1",
            "9C812424417D47ED7C78C7A049D4E6CB906DCF3C",
            "9518A473A902DB6BB56F7A767ABA13C8DF306D37",
            "439C444C7AB4395C4DBA32E4F8CF4F76207E5BB4",
            "9021FCB087269457ABAA8105D4DAD8DF8904A2F6",
            "8B7B686199BC73A175940686BD57F45B2329D895",
            "0F50FB7AA9425975BFBB6AD65CF96284F768BB75",
            "BAA1B7749A9CCAD7105E9ADEE499058A7BE4BA70",
            "FBD3413CE89DFFE2F0A869036F5C4265D5B14743",
            "7CDB257E051ED0EFB761A5A044ECE5B0C1F12033",
            "BB1E5D495074594534AD523987D8438CF1632425",
            "CE6D7BEAD1496190F0F0E99B0B0C9BECFB7D9173",
            "F8BE617A3256EB1C4BFC04CD386EB7FA46603926",
            "D1A1F489434C458344239A75DA4241A3A94BEBA2",
            "BEDD951DC98BD5C4138C1F8531D8288BA3C51B87",
            "9C2357E832CE87A227F6919B50A0A9D3A29B7CAF",
            "C9FCBB9A1AC48B71B2AA20AC992821531F1141EF",
            "0B58D56923F9620BCD072703FBA71EC2172EEAD2",
            "D97480E09FA6473AF9AAFA14FA9589AF65E62328",
            "4D5C56D0EB0BAD64FD0B0FB7F87D05EB551951CE",
            "B7EC2D13EDD3603D1BBC8CD29F32B43AEAF6EB4E",
            "9BD5300B02C9432F686842E7900F3D2A085C5008",
            "7E8787C8780C64009216324802958E1D845332FB",
            "1A3BC1AE95380D609571B01D8C3458B2566B74A5",
            "9672BD12EBBB12F398CEFA089BD3282A2D2892FB",
            "D5D3CAD705E2B0B6E0CBFBB0E8C22CD8EB1DC4C5",
            "408D84FE0B28A3B3CF16F60D6207A94B36219F81",
            "0B7E3D35C292D295797E3ED1F3D8BD5FD92A71BF",
            "18AC1EA3406D69CD9E9C801F471AEA3A31C69D51",
            "98E40CE293ABE4ACFADE7D81371FA92AFA69248C",
            "D95E38F2D0C5ADB478A9BFF9F8E7B10064455C31",
            "6246C69FF502D453950BFEB5DBEF68CE76D70F12",
            "9D788F02EEE675F47AB4498B1337C6D83A37F64A",
            "139387D749674D0E84F3C2BFBAFB3F0CDC4CA273",
            "09406CEDC1C37D275EBFE02CC707229244086CA2",
            "BACA138E6EB6E5BEF150083CE0EFC64FB163EBF4",
            "87CF4CC4500A691934C2C6607F3296A0BEC980F6",
            "F8E4DB4FE6879870E9F47BA29F0DA843342953CE",
            "52DDF305014F1C68A34ED514B10FAE3B1B91F383",
            "0D568164C300BB14A4571A73493C02E4165383E4",
            "E1DD806961D718F8C085CEA11A140900FE8064A4",
            "6470CBC7FE079B684D108550698B7C5D265736D4",
            "DAF83273B2F16DCC69FD55DC84835931E75FF5D8",
            "47F4D7724BF49DE885D23D84D582EA3A00E1C2DE",
            "DBD6BD40F804E38963EBD2E81CE5196F6E69AC48",
            "BD96E9391148957BE64FE6DA89CBDFF45233FBCE",
            "20975680C2E31D61D7F303215A25CFAB4479F646",
            "FFC321ED45ECC1A9FCDBC28ABAE0DA1FD27A628A",
            "99F90008F139FA442C152706E522CEB349EABB00",
            "288C57DAD9D1174F4EBA92F7815B93C0916E8157",
            "8380FD083E742776CC32971B9E088B894A6A0071",
            "B0F44C66552ECE94502597B6B100CC64561E6F1F",
            "AA0465458FA1F285F5A4530035F84F844D545A75",
            "C90EE3BAC92FA4986C850DED11D728A78BE85543",
            "3E525BBEB158B246A3F4918B6D634CE8EBE4503A",
            "7B42675AAE1D0DA5A84623E47C618744249384E5",
            "F50AC31B43BC93D1BE2A4D9C40FC4D3593F2551C",
            "A31AE398E0D6668A52DAFE37D019F7571E0F681B",
            "BF10B29B4DC7C848C5192631E59E0EED32B8D81C",
            "77B214EB3617C372C191D1D284FCED04F5AE17BF",
            "1B17DC33F5966621F4BFA93961B1A8FFEE1AC820",
            "5A07D9861EDA6D8698E12FE5250CCAD882628B44",
            "176F46FF2202307828D7F62D39330444D688FDAD",
            "59E94CFA3AC2BE8DC6098840E888306764308DE2",
            "679F243847C647FCC3F4589CF87972558350DC98",
            "DB97F5EF492C7380472E16E3B055567DAB630153",
            "359CF9515F6B2192BF0E85EDBBC81D51232210B7",
            "30B59B3CBFFC08DA7D9514AE7627460BBBDED722",
            "F31D5E2866D9726051B6E5AC9B846DB36EB705FD",
            "860A58DDB6119261646907E251D60760099CAA07",
            "22EA0278EA053175C2F12BA4ED172FB0B518F3BA",
            "EC68297334F421AB3F2EF3518684E8E1B548BF56",
            "5C1405CC33D9025DA265FF4F25942853721489E2",
            "8AEA8E9EAFBF3BA597B65BBCCEE59013C8E6AC8B",
            "ABF7CCD01374D5DDAD6EFFB19412EE772E663DE2",
            "F7F28E05FAB93A3D089BBFF56D4E462F0BEDA41A",
            "B6C4199D504E72793EEB49611E28A82DF5CD7905",
            "0B0916C89F1D9F1134E9106FEBAF4169DC49F752",
            "4F18AA0E88A01ED162D08F35300B1C3FCE1FE8B8",
            "5D4F3C473D5859C16F70C1566F9800B3DBBBC643",
            "02C1A5F34232B8900E6C7DF2BED957BCAE529784",
            "CDD46E434331D7869A27EA096CAEBF586D93CC2E",
            "492C04E69F0204F150B63022C7DBD28116458F97",
            "CDDAB90168E934E69E942B1F1EC0D0AD7BFB5B43",
            "F433642FA8091FB2517F3357DD30308B4A2AEF53",
            "537B2118792B6A419C438E58CBB6C5BA887AE257",
            "753728CB39813C27498033A07DEC03D1FA720FE9",
            "119A6C5BF3EA8F7A78DA9ED2DE7ED9AE3942964A",
            "A501EB611542A2A2CCC68AE754D2EAC17942BD8D",
            "158FB54E37C7DF54B29928B5DFA53A560DC09A5A",
            "15F5380252E23B5C37EE7E8D1F5963FBF8788577",
            "735F2C3CF7680C63F33AE2D4F3569FA8EB45EB93",
            "67AFC501C6582DF2A9DBD713F206041E5F3E1DEB",
            "7CAEFEC1C6E8232BCB90E3FE3523EE06496F36A3",
            "CC90ADFCF3F9AE777B30EAA6206A34EF54F74C02",
            "974E0E85B47CCB870A511810DDEFE81CB85B28D3",
            "516D6BA01E0186CB7D796FCD9DD169C45B63A93E",
            "A1CE534BDD6591AF4EBF61ED75636C7BFF670658",
            "1E4B241D6EADD77E046BDCCD25F70AAC969262D3",
            "7F2F1B4B77C3170A9E015DF4E8C6EDFE736DFFC3",
            "89A3BF181EF195464DBEF9576873CA2DF7D16268",
            "E1F96A7C9115E3DBF28E10D62F2D6EC89415B6D7",
            "D75C1081B3C2720D030EC5DE13093357A0EE6E51",
            "C11603CDAD8DF271093CACDFB5AA4E113A270EA5",
            "39A9E659DFFDC2ABC88ADA2B6A7445090C7EFBF7",
            "4132330C5E3344818AF5C054AD55309FF7B767A2",
            "B107A8B0C7B68581969A0F6DB95DB2F790098F1D",
            "AD090CC9A6B381C0B3D87035274FBC056012A4E6"
        )

        var key = ByteArray(20) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            testHmac(
                Algorithm.RipeMD160,
                key,
                ByteArray(index) { it.toByte() },
                output
            )

            key = strtobin(output)
        }
    }
}
