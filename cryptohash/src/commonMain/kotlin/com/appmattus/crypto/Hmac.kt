package com.appmattus.crypto

import com.appmattus.crypto.internal.CoreDigest
import com.appmattus.crypto.internal.core.sphlib.HMAC

/**
 * Denotes an [Algorithm] supports HMAC.
 * While any algorithm should work, this marks algorithms that have tests in place.
 */
public interface Hmac {

    /**
     * Create an HMAC [Digest] of the [Algorithm] for creating hashes
     */
    public fun createHmac(key: ByteArray, outputLength: Int? = null): Digest<*> =
        HMAC(CoreDigest.create(this as Algorithm), key, outputLength)

    /**
     * Create an HMAC [Digest] of the [Algorithm] for creating hashes
     */
    public fun createHmacPlatform(key: PlatformData, outputLength: Int? = null): PlatformDigest<*> =
        HMAC(CoreDigest.create(this as Algorithm), key.asByteArray(), outputLength).toPlatform()

    /**
     * Create an HMAC hash of [input] using the [Algorithm]
     */
    public fun hmac(key: ByteArray, input: ByteArray, outputLength: Int? = null): ByteArray =
        createHmac(key, outputLength).digest(input)

    /**
     * Create an HMAC hash of [input] using the [Algorithm]
     */
    public fun hmacPlatform(key: PlatformData, input: PlatformData, outputLength: Int? = null): PlatformData =
        createHmac(key.asByteArray(), outputLength).digest(input.asByteArray()).asPlatformData()
}
