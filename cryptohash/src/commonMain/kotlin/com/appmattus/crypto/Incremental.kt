package com.appmattus.crypto

import com.appmattus.crypto.internal.CoreDigest

/**
 * Denotes an [Algorithm] supports HMAC.
 * While any algorithm should work, this marks algorithms that have tests in place.
 */
public interface Incremental {

    /**
     * Create a [Digest] of the [Algorithm] for creating hashes
     */
    public fun createDigest(): Digest<*> = CoreDigest.create(this as Algorithm)

    /**
     * Create a [Digest] of the [Algorithm] for creating hashes
     */
    public fun createPlatformDigest(): PlatformDigest<*> = CoreDigest.create(this as Algorithm).toPlatform()
}
