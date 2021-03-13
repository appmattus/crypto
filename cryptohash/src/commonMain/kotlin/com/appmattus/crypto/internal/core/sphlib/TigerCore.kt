/*
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Translation to Kotlin:
 *
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

package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.internal.core.decodeLELong
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * This class implements Tiger and Tiger2, which differ only by the
 * padding.
 *
 * @version $Revision: 156 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 *
 * @param fbyte   the first padding byte
 */
@Suppress("MagicNumber")
internal abstract class TigerCore<D : TigerCore<D>>(fbyte: Byte) : MDHelper<D>(true, 8, fbyte) {

    private var currentA: Long = 0
    private var currentB: Long = 0
    private var currentC: Long = 0

    override fun copyState(dest: D): D {
        dest.currentA = currentA
        dest.currentB = currentB
        dest.currentC = currentC
        return super.copyState(dest)
    }

    override val digestLength: Int
        get() = 24

    override val blockLength: Int
        get() = 64

    override fun engineReset() {
        currentA = 0x0123456789ABCDEFL
        currentB = -0x123456789abcdf0L
        currentC = -0xf695a4b3c4d1e79L
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        encodeLELong(currentA, output, outputOffset)
        encodeLELong(currentB, output, outputOffset + 8)
        encodeLELong(currentC, output, outputOffset + 16)
    }

    override fun doInit() {
        engineReset()
    }

    private fun lookupLow(x: Long): Long {
        return (T1[x.toInt() and 0xFF]
                xor T2[(x ushr 16).toInt() and 0xFF]
                xor T3[(x ushr 32).toInt() and 0xFF]
                xor T4[(x ushr 48).toInt() and 0xFF])
    }

    private fun lookupHigh(x: Long): Long {
        return (T4[(x ushr 8).toInt() and 0xFF]
                xor T3[(x ushr 24).toInt() and 0xFF]
                xor T2[(x ushr 40).toInt() and 0xFF]
                xor T1[(x ushr 56).toInt() and 0xFF])
    }

    @Suppress("LongMethod")
    override fun processBlock(data: ByteArray) {
        /*
		 * Note: we use external methods for the table lookups.
		 * Inlining those methods yields slightly better performance
		 * on Athlon XP in 32-bit mode, but not on a 64-bit Sempron.
		 * We believe that such inlining increases the footprint and
		 * may exceed cache on some architectures.
		 */
        var a = currentA
        var b = currentB
        var c = currentC
        var x0 = decodeLELong(data, 0)
        var x1 = decodeLELong(data, 8)
        var x2 = decodeLELong(data, 16)
        var x3 = decodeLELong(data, 24)
        var x4 = decodeLELong(data, 32)
        var x5 = decodeLELong(data, 40)
        var x6 = decodeLELong(data, 48)
        var x7 = decodeLELong(data, 56)
        c = c xor x0
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 5L
        a = a xor x1
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 5L
        b = b xor x2
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 5L
        c = c xor x3
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 5L
        a = a xor x4
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 5L
        b = b xor x5
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 5L
        c = c xor x6
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 5L
        a = a xor x7
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 5L
        x0 -= x7 xor -0x5a5a5a5a5a5a5a5bL
        x1 = x1 xor x0
        x2 += x1
        x3 -= x2 xor (x1.inv() shl 19)
        x4 = x4 xor x3
        x5 += x4
        x6 -= x5 xor (x4.inv() ushr 23)
        x7 = x7 xor x6
        x0 += x7
        x1 -= x0 xor (x7.inv() shl 19)
        x2 = x2 xor x1
        x3 += x2
        x4 -= x3 xor (x2.inv() ushr 23)
        x5 = x5 xor x4
        x6 += x5
        x7 -= x6 xor 0x0123456789ABCDEFL
        b = b xor x0
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 7L
        c = c xor x1
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 7L
        a = a xor x2
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 7L
        b = b xor x3
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 7L
        c = c xor x4
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 7L
        a = a xor x5
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 7L
        b = b xor x6
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 7L
        c = c xor x7
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 7L
        x0 -= x7 xor -0x5a5a5a5a5a5a5a5bL
        x1 = x1 xor x0
        x2 += x1
        x3 -= x2 xor (x1.inv() shl 19)
        x4 = x4 xor x3
        x5 += x4
        x6 -= x5 xor (x4.inv() ushr 23)
        x7 = x7 xor x6
        x0 += x7
        x1 -= x0 xor (x7.inv() shl 19)
        x2 = x2 xor x1
        x3 += x2
        x4 -= x3 xor (x2.inv() ushr 23)
        x5 = x5 xor x4
        x6 += x5
        x7 -= x6 xor 0x0123456789ABCDEFL
        a = a xor x0
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 9L
        b = b xor x1
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 9L
        c = c xor x2
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 9L
        a = a xor x3
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 9L
        b = b xor x4
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 9L
        c = c xor x5
        a -= lookupLow(c)
        b += lookupHigh(c)
        b *= 9L
        a = a xor x6
        b -= lookupLow(a)
        c += lookupHigh(a)
        c *= 9L
        b = b xor x7
        c -= lookupLow(b)
        a += lookupHigh(b)
        a *= 9L
        currentA = currentA xor a
        currentB = b - currentB
        currentC += c
    }

    companion object {
        private val T1 = longArrayOf(
            0x02AAB17CF7E90C5EL, -0x53bdb4fc1dbc5714L,
            0x72CD5BE30DD5FCD3L, 0x6D019B93F6F97F3AL,
            -0x326687002de06e6dL, 0x7573A1C9708029E2L,
            -0x4e9bcd946dd57c3dL, 0x46883EEE04915870L,
            -0x15531cfa8efc131aL, -0x3abe9647f75caca4L,
            0x4CE754918DDEC47CL, 0x0AA2F4DFDC0DF40CL,
            0x10B76F18A74DBEFAL, -0x393349dca52e5496L,
            0x13726121572FE2FFL, 0x1A488C6F199D921EL,
            0x4BC9F9F4DA0007CAL, 0x26F5E6F6E85241C7L,
            -0x7a6f862415a6b84aL, 0x4F1885C5C99E8C92L,
            -0x287189e1569079b5L, -0x71c9bd73ad4a3e83L,
            0x69CF6827373063C1L, -0x49f836c2644b3a92L,
            0x7D820E760E76B5EAL, 0x645C9CC6F07FDC42L,
            -0x40c75f87dbccbd20L, 0x5F6B343C9D2E7D04L,
            -0xd3d75149ff4f13aL, 0x6C0ED85F7254BCACL,
            0x71592281A4DB4FE5L, 0x1967FA69CE0FED9FL,
            -0x2ad6c07469aba25L, -0x378616280d589ff5L,
            -0x79fdb76dfe6ce6b2L, -0x5b06acc4d2633f4dL,
            -0x6fac7c93ea6a89edL, -0x2492307503ca840fL,
            0x18BEEA7A7A370F57L, 0x037117CA50B99066L,
            0x6AB30A9774424A35L, -0xb16d0fd1cdadb65L,
            0x7739DB07061CCAE1L, -0x270c4b63135bd5fbL,
            -0x42a941c0aec7d08dL, 0x45FAED5843B0BB28L,
            0x1C813D5C11BF1F83L, -0x750f1b4928a05e97L,
            0x33EE18A487AD9999L, 0x3C26E8EAB1C94410L,
            -0x4aefefd43f57dd07L, 0x141EEF310CE6123BL,
            -0x39a46ffa6224eacL, -0x1fea79bf3a1f19f9L,
            -0x77b1f867d93c5c31L, -0x6cf2f26adc3aca03L,
            0x35638D754E9A2B00L, 0x4085FCCF40469DD5L,
            -0x3b4e852d741dc5b4L, -0x354d0f0395c195d2L,
            0x2860971A6B943FCDL, 0x3DDE6EE212E30446L,
            0x6222F32AE01765AEL, 0x5D550BB5478308FEL,
            -0x561056725f125dd6L, -0x3cae58e9793bf259L,
            0x1105586D9C867C84L, -0x2300117a025dd7adL,
            -0x33042fd9d3a1108aL, -0x450d6b34766f2dffL,
            -0x196b9b0ad505268bL, -0x6b4fec5020ecc1ecL,
            0x06A7D1A32823C958L, 0x6F95FE5130F61119L,
            -0x26d54cb1b9d3f940L, -0x128421cc77838e2eL,
            0x79746D6E6518393EL, 0x5BA419385D713329L,
            0x7C1BA6B948A97564L, 0x31987C197BFDAC67L,
            -0x2193dc3bb4fac2feL, 0x581C49FED002D64DL,
            -0x22b8b29cc7d9ea8fL, -0x55bab93c1b8c2f9eL,
            -0x6d7031cb6baa07a0L, 0x48161BBACAAB94D9L,
            0x63912430770E6F68L, 0x6EC8A5E602C6641CL,
            -0x78d7daeacc8222d5L, 0x2CDA6B42034B701BL,
            -0x4fc2c83e7e34f693L, -0x1ef7bc7d9938e391L,
            0x2B3180C7EB51B255L, -0x206d47d0693f7444L,
            0x5C68C8C0A632F3BAL, 0x5504CC861C3D0556L,
            -0x54405b1aa04d9471L, 0x41848B0AB3BACEB4L,
            -0x4ccb5d8c55bba2ceL, -0x4359690f57a5277fL,
            0x24F6EC65B528D56CL, 0x0CE1512E90F4524AL,
            0x4E9DD79D5506D35AL, 0x258905FAC6CE9779L,
            0x2019295B3E109B33L, -0x756b8748c5fab34L,
            0x2924F2F934417EB0L, 0x3993357D536D1BC4L,
            0x38A81AC21DB6FF8BL, 0x47C4FBF17D6016BFL,
            0x1E0FAADD7667E3F5L, 0x7ABCFF62938BEB96L,
            -0x5872526b703e8637L, -0x70e06748d6ee1af3L,
            0x61E48EAE27121A91L, 0x4D62F7AD31859808L,
            -0x13145cba10a31515L, -0xa314da143697b32L,
            -0x9cc1df348089ddfL, -0x5cd320f9547d6c1cL,
            -0x67a5dfd35a11d35cL, -0x30f47bb83375704fL,
            -0x6089adbb6867a65dL, -0x572ae94e5edbffe9L,
            0x0BD7BA3EBB5DC726L, -0x1ab435aa479524c7L,
            0x1D7A3AFD6C478063L, 0x519EC608E7669EDDL,
            0x0E5715A2D149AA23L, 0x177D4571848FF194L,
            -0x114aa0cdbefeb3deL, 0x0F5E5CA13A6E2EC2L,
            -0x7fd66d848a0a3c9fL, -0x52ec60543c291bcaL,
            0x0D5DF1A94CCF402FL, 0x3E8BD948BEA5DFC8L,
            -0x5a5f2ca842c00882L, -0x5d2ed1dae08b09bbL,
            0x66FD9E525E81A082L, 0x2E0C90CE7F687A49L,
            -0x3d1743414568c43bL, 0x000001BCE509745FL,
            0x423777BBE6DAB3D6L, -0x2e99e381510f914bL,
            -0x5e87e0cab2553028L, 0x2D11284A2B16AFFCL,
            -0xe03b0980576e2e1L, 0x73ECC25DCB920ADAL,
            -0x519ef3dd3d5ed9afL, -0x691f57ef2ca94876L,
            0x5A9A381F2FE7870FL, -0x2a529d1216b1aad0L,
            -0x2dda1a17c972ebd9L, 0x65977B70C7AF4631L,
            -0x6607764d21c628b1L, 0x233F30BF54E1D143L,
            -0x65698a2c2659c369L, 0x5470554FF334F9A8L,
            0x166ACB744A4F5688L, 0x70C74CAAB2E4AEADL,
            -0xf2f6e9b90d6b2eeL, 0x57B82A89684031D1L,
            -0x1026a5a59e41f495L, 0x2FBD12E969F2F29AL,
            -0x642c8fec01006018L, 0x3F9B0404D6085A06L,
            0x4940C1F3166CFE15L, 0x09542C4DCDF3DEFBL,
            -0x4b3ade7c7a32a31dL, -0x36ca4823bb9d59bfL,
            0x3417F8A68ED3B63FL, -0x47f6a6d6a4dea4c0L,
            -0x6632510c4737a8eL, 0x018C0614F8FCB95DL,
            0x1B14ACCD1A3ACDF3L, -0x7b2b8e0dff448cd3L,
            -0x3e5ceef16a1725eaL, 0x430A7220BF1A82B8L,
            -0x4881f6f2c620def2L, 0x5EF4BD9F3CD05E9DL,
            -0x62b0092581a85bbcL, -0x25e29f1e7c2b5a08L,
            -0x4d783c7be86671b9L, -0x1c123ede44ce77aL,
            -0x3801c33367f33411L, -0x1b904a6fe76402fdL,
            0x3732FD469A4C57DCL, 0x7EF700A07CF1AD65L,
            0x59C64468A31D8859L, 0x762FB0B4D45B61F6L,
            0x155BAED099047718L, 0x68755E4C3D50BAA6L,
            -0x16deb180dd274b21L, 0x2ADDBF532EAC95F4L,
            0x32AE3909B4BD0109L, -0x7cb20ac84f71cbb0L,
            -0x5df6257bddf8d73L, -0x6196e2646101dc09L,
            0x0446D288C4AE8D7FL, 0x7B4CC524E169785BL,
            0x21D87F0135CA1385L, -0x3144bff0ec84755bL,
            0x272E2B66580796BEL, 0x3612264125C2B0DEL,
            0x057702BDAD1EFBB2L, -0x2b4544715307b417L,
            -0x6ea7cec69be43985L, -0x7423d21f7fc91fdcL,
            0x603C8156F49F68EDL, -0x82dc9082410aeefL,
            -0x68d83ba6752de180L, -0x5f75f76998f5a029L,
            -0x34b570bcf6145635L, -0x7e50a9b4f08fc95fL,
            -0x3f46655887e66543L, -0x6a60e137c03716aeL,
            -0x73afaf8886b57e47L, 0x3ACAAF8F056338F0L,
            0x07B43F50627A6778L, 0x4A44AB49F5ECCC77L,
            0x3BC3D6E4B679EE98L, -0x633f2b2e30ebef74L,
            0x4406C00B206BC8A0L, -0x7d5e77ab3728d277L,
            0x67E366B35C3C432CL, -0x46dc229eefd4c80eL,
            0x56AB2779D884271DL, -0x417c1e4f00eada51L,
            -0x4839a2bde81b657L, 0x6BDBE0E76D48E7D4L,
            0x08DF828745D9179EL, 0x22EA6A9ADD53BD34L,
            -0x1c91ebe3a9dddff6L, 0x7F805D1B8CB750EEL,
            -0x501a385a60a717c9L, -0x1d806695b04e3dc4L,
            -0x2c798204f88a0f30L, -0x2f198c21917776e6L,
            0x123AEB9EAFB86C25L, 0x30F1D5D5C145B895L,
            -0x44bcb5d2118d9619L, 0x78CB67ECF931FA38L,
            -0xcc4fc8dcdc44064L, 0x52D66336FB279C74L,
            0x505F33AC0AFB4EAAL, -0x175a32665d331e79L,
            0x534974801E2D30BBL, -0x72d2a8ee2a789270L,
            0x1F1A412891BC038EL, -0x291d18e27d1a99b8L,
            0x74036C3A497732B7L, -0x764981269c9e0a55L,
            -0x126a270e15fd5eL, -0x18d4c429eb9b2bc3L,
            -0x59cff0e8f423b7e0L, -0x143e789f12875886L
        )
        private val T2 = longArrayOf(
            -0x195941a5fa5edec8L, -0x4a5edd5a4b078368L,
            0x563C6089140B6990L, 0x4C46CB2E391F5DD5L,
            -0x26cd522436486bccL, 0x08EA70E42015AFF5L,
            -0x289a5998c1b8730fL, -0x3b048a8154d87267L,
            -0x20ee3979d291f96eL, -0x22147b0ef280c4eaL,
            0x6F2EF604A665EA04L, 0x4A8E0F0FF0E0DFB3L,
            -0x5a121107c24345afL, -0x3b0f5d5f15bc8e2L,
            -0x17c1e257a34c7bd7L, -0x2370077d45e4e31eL,
            -0x32baafa17cac17f3L, 0x18D19A00D4DB0717L,
            0x34A0CFEDA5F38101L, 0x0BE77E518887CAF2L,
            0x1E341438B3C45136L, -0x1fa8680b6f763307L,
            -0x2dc0620da6e2ecL, 0x543DDA228595C5CDL,
            0x661F81FD99052A33L, -0x78c919be24f0848aL,
            0x15227725418E5307L, -0x1da080b9e9d14d06L,
            0x48A8B2126C13D9FEL, -0x5023abe86d189116L,
            0x03D912BFC6D1898FL, 0x31B1AAFA1B83F51BL,
            -0xe53d8691bd54827L, 0x40A3A7D7FCD2EBACL,
            0x1056136D0AFBBCC5L, 0x7889E1DD9A6D0C85L,
            -0x2ccada87d5868b56L, -0x581da2f6f8753f65L,
            -0x42bec74c15391230L, -0x6df540418e146190L,
            -0x5d5a2f0ab03d9da4L, -0x3fab1c94f4ed6f5dL,
            -0x922a6009d016cd5L, 0x3537354511A8AC7DL,
            -0x357ba16e8d05232cL, -0x7b07d49fcd62df24L,
            0x79C62CE1CD672F18L, -0x74f65d522edb9bd4L,
            -0x2f3e1695e62618daL, 0x5A786A9B4BA9500CL,
            0x0E020336634C43F3L, -0x3e84b8b5149927deL,
            0x6A731AE3EC9BAAC2L, -0x7dd999851f7bfda8L,
            0x67D4567691CAECA5L, 0x1D94155C4875ADB5L,
            0x6D00FD985B813FDFL, 0x51286EFCB774CD06L,
            0x5E8834471FA744AFL, -0x8d35f51189e51d2L,
            -0x41bf1b3251171f66L, -0x1668f444aee7099bL,
            0x726E4BEB33DF1964L, 0x703B000729199762L,
            0x4631D816F5EF30A7L, -0x477f4a4aeafb5942L,
            0x641793C37ED84B6CL, 0x7B21ED77F6E97D96L,
            0x776306312EF96B73L, -0x51ad76b717900c0cL,
            0x53DBD7F286A3F8F8L, 0x16CADCE74CFC1063L,
            0x005C19BDFA52C6DDL, 0x68868F5D64D46AD3L,
            0x3A9D512CCF1E186AL, 0x367E62C2385660AEL,
            -0x1ca6181588234e29L, 0x526C0773749ABE6EL,
            0x735AE5F9D09F734BL, 0x493FC7CC8A558BA8L,
            -0x4f463eaccfbe54bbL, 0x321958BA470A59BDL,
            -0x7ad24ff4a0b93c6dL, -0x6edf64d42cc94f1bL,
            0x6E604F7D659EF19FL, -0x4665751d87d334dcL,
            -0x330ad54937eb3b39L, 0x4727D9AFBE11727BL,
            0x7E950D0C0121B34DL, 0x756F435670AD471FL,
            -0xa522bbd9ea597b7L, 0x4E87E09980B9957AL,
            0x2ACFA1DF50AEE355L, -0x2767d9c502d02aaaL,
            -0x370b6db227f3702aL, -0x306635c28ab5e8c6L,
            -0x1b88453506e40c4L, -0x12ac8e09296f3ed3L,
            -0x7ce5a3d7a1978f6cL, -0x3a2c36f5c8f75f5cL,
            0x0F7F903717D06580L, 0x19F9BB13B8FDF27FL,
            -0x4e4290e4b2afd7bdL, 0x1C761BA38FFF4012L,
            0x0D1530C4E2E21F3BL, -0x76bc319658c8d376L,
            -0x1ae7b1ee014a319aL, 0x618BDB80BD736621L,
            0x7D29BAD68B574D0BL, -0x7e449ec1da1901a5L,
            0x071C9C10BC07913FL, -0x38411486f653d269L,
            -0x3c1a72cac43a28a9L, -0x14fe876d0c709e18L,
            -0x2b10046364e33de6L, -0x668d82d90b6b0855L,
            -0x5c1f9c5d6a94c1fdL, -0x62b57465b55f63d0L,
            0x3F6AB7D500090FB4L, -0x633f0d5fa8d97540L,
            0x3DEE9D2DEDBF42D1L, 0x330F49C87960A972L,
            -0x394d8dfd78bde4bfL, 0x0AC59EC07C00369CL,
            -0x10b153b634cacbdbL, -0xbafdbb110fed628L,
            -0x7533b91a350b214aL, 0x2FFEAB63989263F7L,
            -0x70834601a285ba88L, 0x5BD8F7644E634635L,
            0x427A7315BF2DC900L, 0x17D0C4AA2125261CL,
            0x3992486C93518E50L, -0x4b34011f5d282b3dL,
            0x7C75D6202C5DDD8DL, -0x243d6a271ca4939fL,
            0x60B369D302032B19L, -0x31bd97a0231bbeceL,
            0x06F3DDB9DDF65610L, -0x715b2de24a1eb710L,
            0x20B0FCE62FCD496FL, 0x2C1B912358B0EE31L,
            -0x4d7ce847e70a5cf8L, -0x5763e1e763592d31L,
            0x0C6B18576AAADBC8L, -0x49a21556ed66051dL,
            -0x4d486b480efd819L, 0x04E4317F443B5BEBL,
            0x4B852D325939D0A6L, -0x2a51941104df8004L,
            0x309682B281C7D374L, -0x451cf65e6b3c4b8bL,
            -0x733c0684ec4b60fbL, -0x6756bdd007d6c699L,
            0x244B16B01076FF7CL, -0x740a8e399c29812L,
            0x1F0D6758EEE30DA1L, -0x3649ee2685214649L,
            -0x48502a778493a85eL, 0x6290AE846B984FE1L,
            -0x6b20b321533e5a03L, 0x058A5BD1C5483AFFL,
            0x63166CC142BA3C37L, -0x7247ad914d0890c0L,
            -0x1ef77ffc90f292b2L, -0x61fadc3668e2cee3L,
            0x45EC2824CC7CD691L, 0x575B8359E62382C9L,
            -0x561bff23b77666bL, -0x2e7dc134ba8dea98L,
            -0x250267c47df9f7d1L, -0x5582d6f7dc795735L,
            0x269FCD4403B87588L, 0x1B91F5F728BDD1E0L,
            -0x1b9960c6fbfdfe0aL, 0x7A1D7C218CF04ADEL,
            0x65623C29D79CE5CEL, 0x2368449096C00BB1L,
            -0x54640e78625afc46L, -0x43dc134e5ba7fa72L,
            -0x65a720fe44bfe134L, -0x5f8f179757a0ebc3L,
            0x4FF188307DF2239EL, 0x14D565B41A641183L,
            -0x11eccc8bad8fe9feL, -0x6af1c230c0d7a1f7L,
            0x59930254B9C80953L, 0x3BF299408930DA6DL,
            -0x56aa6bc0ac96ec79L, -0x5ea121355634787cL,
            0x29142127352BE9A0L, 0x76F0371FFF4E7AFBL,
            0x0239F450274F2228L, -0x44f8c50fe2a17975L,
            -0x4037fa8e3ef1693fL, -0x2d98f77a97ddd1ddL,
            -0x698e5c2b717f4a50L, 0x55B5D38AE193BB81L,
            0x693AE2D0A18B04B8L, 0x5C48B4ECADD5335FL,
            -0x28bc4e6b6e95e36L, 0x2577018134BE98C4L,
            -0x18867817c3ab5b53L, 0x28E11014DA33E1B9L,
            0x270CC59E226AA213L, 0x71495F756D1A5F60L,
            -0x6417ac049f501089L, -0x5238795808bbc241L,
            0x0904456173B29A82L, 0x58BC7A66C232BD5EL,
            -0xcf9aa7398c5374eL, 0x41F639C6B6C9772AL,
            0x216DEFE99FDA35DAL, 0x11640CC71C7BE615L,
            -0x6c3bc96ba9a3aad9L, -0x15fc719db98887c7L,
            -0x6540c31a5c1db97L, 0x741E768D0FD312D2L,
            0x0144B883CED652C6L, -0x3df4a5a45cc07aaeL,
            0x1AE69633C3435A9DL, -0x685d735bf7730214L,
            -0x77db5bc3e1690be0L, 0x37612FA66EEEA746L,
            0x6B4CB165F9CF0E5AL, 0x43AA1C06A0ABFB4AL,
            0x7F4DC26FF162796BL, 0x6CBACC8E54ED9B0FL,
            -0x594800102d44dac2L, 0x2E25BC95B0A29D4FL,
            -0x79295a74210ec774L, -0x2128b53a89490facL,
            -0x7fcf4243d4ba7fa3L, 0x3C81AF70E94D9289L,
            0x3EFF6DDA9E3100DBL, -0x4c723c60203377b9L,
            0x123885528D17B87EL, -0xd25f12dbf4e49beL,
            0x44CEFADCD54BF9A9L, 0x1312200E433C7EE6L,
            -0x600337b0c58738b8L, -0xf32e08ddb7a8945L,
            -0x13968bfac9c7301cL, 0x2BA7B67C0CEC4E4CL,
            -0x53d0b20c1a31cd13L, -0x34cc2ebcd915b3efL,
            -0x5b16fbb33881a744L, 0x5F513293D934FCEFL,
            0x5DC9645506E55444L, 0x50DE418F317DE40AL,
            0x388CB31A69DDE259L, 0x2DB4A83455820A86L,
            -0x6fef56e17b8ee517L, 0x4DF7F0B7B1498371L,
            -0x29d5d1543f688e87L, 0x22FAC097AA8D5C0EL
        )
        private val T3 = longArrayOf(
            -0xb6033d00e250c65L, 0x487FD5C66FF29281L,
            -0x175cf998032357c1L, 0x2C9B4BE3D2FCCE63L,
            -0x25c008b46c04443eL, 0x2FA165D2FE70BA66L,
            -0x5efc1d8668f16c2cL, -0x413213884f1ba18fL,
            -0x304be18dc67a1b69L, -0x48f555fda108afe9L,
            -0x2bdcf60fc7bf4720L, -0x7103e52fca767a87L,
            -0x69396df41d4d543bL, 0x66AF4163375A9172L,
            0x2174ABDCCA7127FBL, -0x4cc33159b58d00bfL,
            -0xfb5b6ccf7cf995bL, -0x7268f53228d7650bL,
            -0x7069171fce373da2L, -0xc013fdd8978a2b9L,
            -0x13840ceffa9e6f23L, -0xa524f5144f0eb6fL,
            -0x64af077af02a776eL, 0x4975488358B74DE8L,
            -0x5ccab0096eace39fL, 0x0702BBE481D2C6EEL,
            -0x7604dbfa82121268L, -0x53cf8aec7a6916feL,
            0x1D2D3580172772EDL, -0x148c703d71943cf3L,
            0x5854EF8F63044326L, -0x61a3adcda522c442L,
            -0x6f55ac30cda3b9ddL, -0x3e2db2aecb622f99L,
            0x2051CFEEA69EA624L, 0x13220F0A862E7E4FL,
            -0x31c6c66bfb1fb79cL, -0x263bd35b8f790349L,
            0x685AD2238A03E7CCL, 0x066484B2AB2FF1DBL,
            -0x162a28f10408614L, 0x5B13B9DD9C481854L,
            0x15F0D475ED1509ADL, 0x0BEBCD060EC79851L,
            -0x2a73986ee7c54808L, -0x2ee783afad0c111cL,
            -0x36a2ee6d1ab17d01L, -0x79115eb34653935eL,
            0x3485BEB153677D5DL, -0x22e6e287e073b6d6L,
            -0x9f79945587b1407L, 0x518F643BA2D08C74L,
            -0x77ad16a91ef783deL, -0x589734723bef5173L,
            0x38047726BFEC8E1AL, -0x5988c74b32c4ba56L,
            -0x52e996e313f221e7L, -0x392bce6c7fb9d1f9L,
            -0x3a5a7892f459e6c8L, 0x16B9FA1FA58FD840L,
            0x188AB1173CA74F18L, -0x5425d0673663fde1L,
            0x3E0580AB134AE816L, 0x5F3B05B773645ABBL,
            0x2501A2BE5575F2F6L, 0x1B2F74004E7E8BA9L,
            0x1CD7580371E8D953L, 0x7F6ED89562764E30L,
            -0x4ea6d900a690ffc3L, -0x609ad6c2573a2947L,
            0x6ECEF04DD690F84CL, 0x4782275FFF33AF88L,
            -0x1bebccf7c07df7ffL, -0x2f201bf65e5064bL,
            0x4325A3342CDB396BL, -0x7518819d4cfe4daeL,
            -0x3c90616099aa9ea6L, -0x7abaa5d26d2cd3f7L,
            -0xd382156b6b88b7bL, 0x63CFB4C133A39EBAL,
            -0x7c4fbf339143ab9eL, 0x3B9454C8FDB326B0L,
            0x56F56A9E87FFD78CL, 0x2DC2940D99F42BC6L,
            -0x670820f694f691d3L, 0x19A6E01E3AD852BFL,
            0x42A99CCBDBD4B40BL, -0x5a666750ba163aa7L,
            0x366295E807D93186L, 0x6B48181BFAA1F773L,
            0x1FEC57E2157A0A1DL, 0x4667446AF6201AD5L,
            -0x19ea1435304f0f8bL, -0x470ce0b097d6f888L,
            0x22713ED6CE22D11EL, 0x3057C1A72EC3C93BL,
            -0x34b9533c83c0e0d1L, -0x24476c02fd550af2L,
            0x331FD92E600B9FCFL, -0x5b67069eb715c52aL,
            -0x5727bd9174957c16L, -0x5f764d8b488ca324L,
            -0x78094c8ce1adb5efL, 0x118808E5CBC96749L,
            -0x66f91b384e642c6cL, -0x5012808164db5df4L,
            0x6509EADEEB3644A7L, 0x6C1EF1D3E8EF0EDEL,
            -0x463682bc1686704cL, -0x5d0d287b8bf3d75dL,
            0x7B8496476197566FL, 0x7A5BE3E6B65F069DL,
            -0x69ccf12874190f0L, -0x1119f21885f895ebL,
            0x2B4BEE4AA08B9BD0L, 0x6A56A63EC7B8894EL,
            0x02121359BA34FEF4L, 0x4CBF99F8283703FCL,
            0x398071350CAF30C8L, -0x2f5885760fe89786L,
            -0xe3e561461bdca97L, -0x738689d7d2117e67L,
            0x5D1737A5DD1F7ABDL, 0x4F53433C09A9FA80L,
            -0x574f3ac20835e27L, 0x3FD9DCBC886CCB77L,
            -0x3fbf6e8356e4b8e0L, 0x7DD00142F9D1DCDFL,
            -0x7b8903e2b0c784a8L, 0x23F8E7C5F3316503L,
            0x032A2244E7E37339L, 0x5C87A5D750F5A74BL,
            0x082B4CC43698992EL, -0x206e841347a709c4L,
            0x3270B8FC5BF86DDAL, 0x10AE72BB29B5DD76L,
            0x576AC94E7700362BL, 0x1AD112DAC61EFB8FL,
            0x691BC30EC5FAA427L, -0xdb9cee33cd8ebdL,
            0x3142368E30E53206L, 0x71380E31E02CA396L,
            -0x6a72a369f552890fL, -0x7290bcf3e925acaL,
            -0x37002ec0e4181e2eL, 0x7578AE66004DDBE1L,
            0x05833F01067BE646L, -0x44cb4a52c401a793L,
            0x095F34C9A12B97F0L, 0x247AB64525D60CA8L,
            -0x2324390cfe8b882fL, 0x4A2E14D4DECAD24DL,
            -0x424a192641f5e115L, 0x2A7E70F7794301ABL,
            -0x210bd275d8fabf03L, 0x01078EC0A34C22C1L,
            -0x1a21aee50b3e9c79L, 0x7EBB3A52BD9A330AL,
            0x77697857AA7D6435L, 0x004E831603AE4C32L,
            -0x185defdf52871ceeL, -0x62be58f3954bdf0eL,
            0x28E06C18EA1141E6L, -0x2d4d734267b094d8L,
            0x26B75F6C446E9D83L, -0x45b8a973b2be7281L,
            -0x27f4524019e7c272L, 0x0E206D7F5F166044L,
            -0x1da75bc6ee3435c2L, 0x723A1746B21DC0BCL,
            -0x383557ab0a28322dL, 0x7CAC32883D261D9CL,
            0x7690C26423BA942CL, 0x17E55524478042B8L,
            -0x1f41b889a95dc761L, 0x4D289B5E67AB2DA0L,
            0x44862B9C8FBBFD31L, -0x4b8337fb62ebec9bL,
            -0x7dd3e4c9d46e386dL, 0x4EB14655FB13DFD8L,
            0x1ECBBA0714E2A97BL, 0x6143459D5CDE5F14L,
            0x53A8FBF1D5F0AC89L, -0x6815fb27e3a1a500L,
            0x622181A8D4FDB3F3L, -0x16432cbea8d5edf8L,
            0x1411258643CCE58AL, -0x6ebb3a015b391f5cL,
            0x0D33D06565CF620FL, 0x54A48D489F219CA1L,
            -0x3bc1a153929c37dfL, -0x568d74c58d88f251L,
            -0x286cb184df207811L, -0x1caafc49e5c1791bL,
            -0x351cde0437e62afcL, 0x129A50B3AC60BFA6L,
            -0x32a197158160493dL, -0x4fe36fe66b7c4e39L,
            0x3DE93CD5C295376CL, -0x512ad120d54652edL,
            0x2E60F512C0A07884L, -0x43c2795c1c9def37L,
            0x35269D9B163951CEL, 0x0C7D6E2AD0CDB5FAL,
            0x59E86297D87F5733L, 0x298EF221898DB0E7L,
            0x55000029D1A5AA7EL, -0x743f751e4af9e4bbL,
            -0x3d3ce3d4936d8fc6L, -0x6b33a69450da10beL,
            0x0A1D73DB22540456L, 0x04B6A0F9D9C4179AL,
            -0x1002505d51c2c3a0L, -0x837f8a44b6b693cL,
            -0x633a38ebe2e32b1dL, 0x78BD1638218E5534L,
            -0x4d0eea9707afdb96L, -0x120543056afd43d7L,
            0x796CE5F2DA23051BL, -0x551ed74f236cac84L,
            0x3A493DA0EE4B29AEL, -0x4a2094d3be976a29L,
            -0x35442daedd280c9L, 0x70810B58105DC4B1L,
            -0x1ef022c80877d570L, 0x524DCAB5518A3F5CL,
            0x3C9E85878451255BL, 0x4029828119BD34E2L,
            0x74A05B6F5D3CECCBL, -0x49effdeabd1ec136L,
            0x0FF979D12F59E2ACL, 0x6037DA27E4F9CC50L,
            0x5E92975A0DF1847DL, -0x29921e6f2c19dc02L,
            0x5032D6B87B568048L, -0x65c948317dcade92L,
            -0x7fd8d585db09b4b6L, -0x6c1012747396e909L,
            0x37DDBFF44CCE1555L, 0x4B95DB5D4B99BD25L,
            -0x6d2c025e967ed040L, -0x4e5b5656f99f44aL,
            0x730C196946A4B9B2L, -0x7e1d765580b62598L,
            0x64669A0F83B1A05FL, 0x27B3FF7D9644F48BL,
            -0x33949ea372498a4dL, 0x674F20B9BCEBBE95L,
            0x6F31238275655982L, 0x5AE488713E45CF05L,
            -0x409e6066ab3deea9L, -0x15453b9fbf571517L,
            0x454C6FE9F2C0C1CDL, 0x419CF6496412691CL,
            -0x2c23c410d9a4f090L, 0x6D0E60F5C3578A9EL
        )
        private val T4 = longArrayOf(
            0x5B0E608526323C55L, 0x1A46C1A9FA1B59F5L,
            -0x561dba5e83b37006L, 0x65CA5159DB2955D7L,
            0x05DB0A76CE35AFC2L, -0x7e15388156eec2bbL,
            0x528EF88AB6AC0A0DL, -0x5f615daca6841c01L,
            0x430DDFB3AC48CD56L, -0x3b4c59850ba31b91L,
            0x4ECECFD8FBE2D05EL, 0x3EF56F10B39935F0L,
            0x0B22D6829CD619C6L, 0x17FD460A74DF2069L,
            0x6CF8CC8E8510ED40L, -0x2937db40c5913559L,
            0x61243D581A817049L, 0x048BACB6BBC163A2L,
            -0x265c753d82bb33ceL, 0x7FDDFF5BAAF410ABL,
            -0x5292b6a557fb7db5L, -0x1e5958b0d273606cL,
            -0x2b087aedca21171dL, -0x2b480779abf276dL,
            0x247C20042AA4BFDAL, 0x096EA1C517D1327CL,
            -0x2a96994bc9e5997bL, 0x277DA5C31221057DL,
            -0x6b2a676c5bc53009L, 0x64F0C51CCDC02281L,
            0x3D33BCC4FF6189DBL, -0x1ffa34e7b319950fL,
            -0xa332e2e2466416L, -0x4f47ab5801bd67f1L,
            0x7BD46A6A718D4B9FL, -0x2ef05733dd5a0274L,
            -0x2ceb7b6ad41b42cfL, -0x380568a034dbc7b9L,
            0x4886ED1E5846C407L, 0x28CDDB791EB70B04L,
            -0x3d4ff41d0a8cbe81L, 0x5C9590452180F877L,
            0x7A6BDDFFF370EB00L, -0x31af61c72926295cL,
            -0x1414f0ff9b8058feL, 0x1DCC06CF76606F06L,
            -0x1b260d745d7900f6L, -0x27a5cfa236e73d9eL,
            0x475B1D8732225F54L, 0x2D4FB51668CCB5FEL,
            -0x5986462628d445e0L, 0x53841C0D912D43A5L,
            0x3B7EAA48BF12A4E8L, 0x781E0E47F22F1DDFL,
            -0x100df319f54af68dL, 0x20D261D19DFFB742L,
            0x16A12B03062A2E39L, 0x1960EB2239650495L,
            0x251C16FED50EB8B8L, -0x653f3ccf07d9fe92L,
            -0x12ead99a6ac1898fL, 0x02D63194A6369570L,
            0x5074F08394B1C987L, 0x70BA598C90B25CE1L,
            0x794A15810B9742F6L, 0x0D5925E9FCAF8C6CL,
            0x3067716CD868744EL, -0x6ef54f8817288ce5L,
            0x6A61BBDB5AC42F61L, -0x6caec1040f7aea99L,
            -0xb6b8db4617c162bL, -0x17781e67a3f69b73L,
            0x34B1D3C675370CFDL, -0x23ca1bcc43f2daa3L,
            -0x2f5547bdcbece420L, 0x08042A50B48B7EAFL,
            -0x66683b11bb5c54cbL, -0x7d6584b6dfe86630L,
            0x263B8307B7C54441L, 0x752F95F4FD6A6CA6L,
            -0x6d8de8bfd3f7391bL, 0x2A8AB754A795D9EEL,
            -0x5bbd08aad08d6bc3L, 0x2C31334E19781208L,
            0x4FA98D7CEAEE6291L, 0x55C3862F665DB309L,
            -0x42f9efe8a2ac4e0dL, 0x46FE6CB840413F27L,
            0x3FE03792DF0CFA59L, -0x3018ffc8d147a171L,
            -0x5841d61852431ee8L, -0x1abb11a3217bce23L,
            -0x7587e4e4be0e78c2L, -0x5a36b3875f2d0f19L,
            0x39412E2877B60728L, -0x5ed9a10c503659d4L,
            -0x433d88f395daf93bL, 0x3AB66DD5DCE1CE12L,
            -0x19ab662fb598a4c9L, 0x7D8F523481BFD216L,
            0x0F6F64FCEC15F389L, 0x74EFBE618B5B13C8L,
            -0x53237d48ebd8c1e3L, -0x22bf401ffce662e9L,
            0x37E99257E7E061F8L, -0x5ad9d96fb88a556L,
            -0x744409c5b9c2a907L, -0xffec0eabc5d919cL,
            -0x57cf816078613768L, -0x33b3d85beafe8834L,
            0x1B432F2CCA1D3348L, -0x21e2e07060905fedL,
            0x606602A047A7DDD6L, -0x2dc8549b33e34d39L,
            -0x646c718dda032e2dL, -0x13b1fc8f71f00b8aL,
            -0x14d0425c2fc3ed3L, -0x51f4312d11bc7766L,
            0x22CB8923EBFB4F43L, 0x69360D013CF7396DL,
            -0x7aa1c9fd2d2b1fdeL, 0x073805BAD01F784CL,
            0x33E17A133852F546L, -0x20b78bfa753849c8L,
            -0x456d4d6398755eb6L, 0x0CE89FC76CFAADCDL,
            0x5F9D4E0908339E34L, -0xe5016d6e0a6dc47L,
            0x6E3480F60F4A265FL, -0x1140c5d54d647be4L,
            -0x1de6c757706e4b53L, 0x57DFEFF845C6D3C3L,
            0x2F006B0BF62CAAF2L, 0x62F479EF6F75EE78L,
            0x11A55AD41C8916A9L, -0xdd62d6f7b012badL,
            0x42F1C27B16B000E6L, 0x2B1F76749823C074L,
            0x4B76ECA3C2745360L, -0x73670b9c46e96e43L,
            0x14BCC93CF1ADE66AL, -0x777adec192ba7c69L,
            -0x71e8820fd8b2b8efL, -0x4b648c4aafc0d6afL,
            0x10168168C3F96B6BL, 0x0E3D963B63CAB0AEL,
            -0x7203b4a9aa5e24ecL, -0x8760eca91eb21a4L,
            0x683E68AF4E51DAC1L, -0x3657b06272b4f027L,
            0x3691E03F52A0F9D1L, 0x5ED86E46E1878E80L,
            0x3C711A0E99D07150L, 0x5A0865B20C4E9310L,
            0x56FBFC1FE4F0682EL, -0x1572a21cefa12065L,
            0x71ABFDB12379187AL, 0x2EB99DE1BEE77B9CL,
            0x21ECC0EA33CF4523L, 0x59A4D7521805C7A1L,
            0x3896F5EB56AE7C72L, -0x559c70c24e708a24L,
            -0x60c6ca7254167f72L, -0x4821056e3ff48d54L,
            0x6B5541FD62492D92L, 0x6DC6DEE8F92E4D5BL,
            0x353F57ABC4BEEA7EL, 0x735769D6DA5690CEL,
            0x0A234AA642391484L, -0x906af7fd707f263L,
            -0x471ce65d854c0debL, 0x31AD9C1151341A4DL,
            0x773C22A57BEF5805L, 0x45C7561A07968633L,
            -0x6ec2561db6241caL, -0x259ad2648759b398L,
            0x4C27A97F3BC334EFL, 0x76621220E66B17F4L,
            -0x6988bc76653282f5L, -0xc11a4351f12987eL,
            0x409F753600C879FCL, 0x06D09A39B5926DB6L,
            0x6F83AEB0317AC588L, 0x01E6CA4A86381F21L,
            0x66FF3462D19F3025L, 0x72207C24DDFD3BFBL,
            0x4AF6B6D3E2ECE2EBL, -0x6366b2413815f722L,
            0x49ACE597B09A8BC4L, -0x4c73b89930f86846L,
            0x131B9373C57C2A75L, -0x4e7dd3319e6ce1a8L,
            -0x628aaa46f645e3f4L, 0x127FAFDD937D11D2L,
            0x29DA3BADC66D92E4L, -0x5d3e2a8eab3d1344L,
            0x58C5134D82F6FE24L, 0x1C3AE3515B62274FL,
            -0x16f837d1fe347edaL, -0x712f6e6ec1c8035L,
            0x3249D8F9C80046C9L, -0x7f3064121c77049dL,
            0x1881539A116CF19EL, 0x5103F3F76BD52457L,
            0x15B7E6F5AE47F7A8L, -0x242839212b816331L,
            0x44E55C410228BB1AL, -0x49b82bdaa124b167L,
            0x5D11882BB8AAFC30L, -0xaf67444d62cded6L,
            -0x704a15eb16fd694dL, 0x677B942157DD025AL,
            -0x4a7183f5c6f534bL, -0x762c98b37c42b5ffL,
            -0x61d25b20b40c46c5L, -0x33be1cd7354b7d7L,
            0x03F38C96BA582C52L, -0x352e42428027a24eL,
            -0x444bbd3e9f7d517dL, -0x46a017945a256550L,
            -0x4dd1fb98c88e56c1L, -0x7baca736b6cead28L,
            -0x41d5b779684babe2L, -0x6a5d23d22c71969aL,
            -0x3fd3ee536dc37ad5L, 0x2388B1990DF2A87BL,
            0x7C8008FA1B4F37BEL, 0x1F70D0C84D54E503L,
            0x5490ADEC7ECE57D4L, 0x002B3C27D9063A3AL,
            0x7EAEA3848030A2BFL, -0x39fdcd9212dffc40L,
            -0x7c58d7829656bf7aL, -0x3a85a034cf0a8576L,
            -0x4a97bb1b86141887L, -0x5c8c4bf0fa234317L,
            -0x28e5879177a8f11eL, -0x7863453242170960L,
            -0x68952e433e9b5cd1L, -0x54de1da169992875L,
            -0x6fef9c551a1a3cc4L, -0x67e74cbbb7967270L,
            -0x1c9b7851c1e17545L, -0x504206ce76c4234cL,
            0x6345A0DC5FBBD519L, -0x79d701d9646b9a36L,
            0x1E5D01603F9C51ECL, 0x4DE44006A15049B7L,
            -0x40938f1a0889344fL, 0x411218F2EF552BEDL,
            -0x34f3f8f78fa5c95dL, -0x18b2eb8ab0679fbcL,
            -0x32a926bcf157d7f2L, -0x3eda6e28aca0af9bL,
            -0x37cddc0e8df5106aL, -0x3c5fc6908c9c5ae1L
        )
    }
}
