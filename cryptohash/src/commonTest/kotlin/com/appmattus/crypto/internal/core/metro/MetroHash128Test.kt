package com.appmattus.crypto.internal.core.metro

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.testKat
import kotlin.test.Test

class MetroHash128Test {

    private fun digest(seed: ULong = 0u) = Algorithm.MetroHash128(seed).createDigest()

    @Test
    fun test() {
        testKat({ digest(0u) }, "", "4606b14684c65fb60005f3ca3d41d1cb")
        testKat({ digest(1u) }, "", "f9a908797eef84017d036b44fbede600")

        testKat({ digest(0u) }, "a", "4ac6e55552310f85e84d9ea70174c318")
        testKat({ digest(1u) }, "a", "7e64261d2a8278a21b8137ac0e2bac56")

        testKat({ digest(0u) }, "test", "cd06ab4651c48a71666deac1207c7d8f")
        testKat({ digest(1u) }, "test", "73ea1c2d10574ee999405fb0038d8eeb")

        testKat({ digest(0u) }, "012345678901234567890123456789012345678901234567890123456789012", "97a27450acb248059b9feda4bfe27cc7")
        testKat({ digest(1u) }, "012345678901234567890123456789012345678901234567890123456789012", "efec147a868dd6bd7f9d1938b8cda345")

        testKat({ digest(0u) }, "hello world", "a65997de23891a0edccc401bbe2ef561")
        testKat({ digest(123u) }, "hello world", "da0960d0259487c5c6db18ba8b6cd814")

        testKat({ digest(0u) }, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "784bc057737f83b72c7b310a3c5661c1")
        testKat({ digest(1u) }, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "5b25b20b5d2800ecb42d6b87b2ddae3c")

        testKat(
            { digest(0u) },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "32c03c1447c0ba30f092c608df674067"
        )
        testKat(
            { digest(123456u) },
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "d2df040e46842872a5c78832dd13832f"
        )
    }
}
