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

package com.appmattus.crypto

/**
 * MACs (message authentication codes) are keyed hash functions: given a
 * secret key, they take arbitrary-sized data and output a fixed-length
 * tag that only holders of the key can compute.
 *
 * A [Mac] object starts out initialized with its key. The data is
 * processed through it using the [update]
 * methods. At any point [reset] can be called
 * to reset the MAC, keeping its key. Once all the data to be updated has
 * been updated, one of the [digest] methods should be called to complete
 * the MAC computation, or [verify] to check it against an expected tag.
 *
 * The [digest] or [verify] method can be called once for a given number
 * of updates. After either has been called, the [Mac]
 * object is reset to its initialized state.
 *
 * ```kotlin
 * val mac = ...
 *
 * mac.update(message)
 * if (mac.verify(receivedTag)) {
 *     ... the message is authentic
 * }
 * ```
 */
public interface Mac {

    /**
     * Updates the MAC using the specified byte.
     *
     * @param input the byte with which to update the MAC.
     *
     * @return this MAC, so calls can be chained
     */
    public fun update(input: Byte): Mac

    /**
     * Updates the MAC using the specified array of bytes.
     *
     * @param input the array of bytes.
     *
     * @return this MAC, so calls can be chained
     */
    public fun update(input: ByteArray): Mac

    /**
     * Updates the MAC using the specified array of bytes, starting
     * at the specified offset.
     *
     * @param input the array of bytes.
     *
     * @param offset the offset to start from in the array of bytes.
     *
     * @param length the number of bytes to use, starting at [offset]
     *
     * @return this MAC, so calls can be chained
     */
    public fun update(input: ByteArray, offset: Int, length: Int): Mac

    /**
     * Completes the MAC computation by performing final operations
     * such as padding. The MAC is reset after this call is made.
     *
     * @return the array of bytes for the resulting MAC.
     */
    public fun digest(): ByteArray

    /**
     * Performs a final update on the MAC using the specified array
     * of bytes, then completes the MAC computation. That is, this
     * method first calls [update], passing the [input] array to the
     * [update] method, then calls [digest].
     *
     * @param input the input to be updated before the MAC is
     * completed.
     *
     * @return the array of bytes for the resulting MAC.
     */
    public fun digest(input: ByteArray): ByteArray

    /**
     * Completes the MAC computation by performing final operations
     * such as padding. The MAC is reset after this call is made.
     *
     * @param output output buffer for the computed MAC
     *
     * @param offset offset into the output buffer to begin storing the MAC
     *
     * @param length number of bytes within buf allotted for the MAC
     *
     * @return the number of bytes placed into [output]
     */
    public fun digest(output: ByteArray, offset: Int, length: Int): Int

    /**
     * Completes the MAC computation, as [digest] does, and checks the result against [expected].
     * The MAC is reset after this call is made.
     *
     * The bytes are compared in constant time, so how long the check takes doesn't reveal how many leading bytes of
     * [expected] were correct. A wrong-length [expected] returns `false` without comparing.
     *
     * @param expected the MAC to check against, such as one received with a message
     *
     * @return `true` if the computed MAC equals [expected]
     */
    public fun verify(expected: ByteArray): Boolean {
        val actual = digest()
        if (actual.size != expected.size) return false
        var difference = 0
        for (i in actual.indices) difference = difference or (actual[i].toInt() xor expected[i].toInt())
        return difference == 0
    }

    /**
     * Get the natural MAC output length (in bytes).
     *
     * @return the MAC output length (in bytes)
     */
    public val digestLength: Int

    /**
     * Resets the MAC for further use, keeping its key.
     */
    public fun reset()

    /**
     * Clone the current state. The returned object evolves independently
     * of this object.
     *
     * @return the clone
     */
    public fun copy(): Mac

    /**
     *
     * Get the display name for this function (e.g. `"HMAC-SHA-256"`
     * for HMAC with SHA-256).
     */
    public override fun toString(): String
}
