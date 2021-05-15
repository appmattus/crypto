package com.appmattus.crypto

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

// See https://gist.github.com/noahsark769/61cfb7a8b7231e2069a9dab94cf74a62

@Suppress("EXPERIMENTAL_API_USAGE", "unused")
internal fun ByteArray.toData(): NSData = memScoped {
    NSData.create(
        bytes = allocArrayOf(this@toData),
        length = this@toData.size.toUInt()
    )
}

@Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_LITERALS", "unused")
internal fun NSData.toByteArray(): ByteArray = ByteArray(this@toByteArray.length.toInt()).apply {
    if (this@toByteArray.length > 0U) {
        usePinned {
            memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
        }
    }
}
