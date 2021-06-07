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
    public fun createHmac(key: ByteArray, outputLength: Int? = null): Digest<*> = HMAC(CoreDigest.create(this as Algorithm), key, outputLength)
}
