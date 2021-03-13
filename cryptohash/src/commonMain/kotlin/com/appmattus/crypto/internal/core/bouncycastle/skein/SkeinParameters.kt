/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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

package com.appmattus.crypto.internal.core.bouncycastle.skein

/**
 * Parameters for the Skein hash function - a series of byte[] strings identified by integer tags.
 *
 *
 * Parameterised Skein can be used for:
 *
 *  * MAC generation, by providing a [key][SkeinParameters.Builder.setKey].
 *  * Randomised hashing, by providing a [nonce][SkeinParameters.Builder.setNonce].
 *  * A hash function for digital signatures, associating a
 * [public key][SkeinParameters.Builder.setPublicKey] with the message digest.
 *  * A key derivation function, by providing a
 * [key identifier][SkeinParameters.Builder.setKeyIdentifier].
 *  * Personalised hashing, by providing a
 * [recommended format][SkeinParameters.Builder.setPersonalisation] or
 * [arbitrary][SkeinParameters.Builder.setPersonalisation] personalisation string.
 *
 *
 * @see SkeinEngine
 *
 * @see SkeinDigest
 *
 * @see SkeinMac
 */
internal class SkeinParameters private constructor(parameters: MutableMap<Int, ByteArray?>) : CipherParameters {
    private val parameters: MutableMap<Int, ByteArray?>

    constructor() : this(mutableMapOf<Int, ByteArray?>())

    /**
     * Obtains a map of type (Integer) to value (byte[]) for the parameters tracked in this object.
     */
    fun getParameters(): MutableMap<Int, ByteArray?> {
        return parameters
    }

    /**
     * Obtains the value of the [key parameter][.PARAM_TYPE_KEY], or `null` if not
     * set.
     */
    val key: ByteArray?
        get() = parameters[PARAM_TYPE_KEY]

    /**
     * Obtains the value of the [personalisation parameter][.PARAM_TYPE_PERSONALISATION], or
     * `null` if not set.
     */
    val personalisation: ByteArray?
        get() = parameters[PARAM_TYPE_PERSONALISATION]

    /**
     * Obtains the value of the [public key parameter][.PARAM_TYPE_PUBLIC_KEY], or
     * `null` if not set.
     */
    val publicKey: ByteArray?
        get() = parameters[PARAM_TYPE_PUBLIC_KEY]

    /**
     * Obtains the value of the [key identifier parameter][.PARAM_TYPE_KEY_IDENTIFIER], or
     * `null` if not set.
     */
    val keyIdentifier: ByteArray?
        get() = parameters[PARAM_TYPE_KEY_IDENTIFIER]

    /**
     * Obtains the value of the [nonce parameter][.PARAM_TYPE_NONCE], or `null` if
     * not set.
     */
    val nonce: ByteArray?
        get() = parameters[PARAM_TYPE_NONCE]

    /**
     * A builder for [SkeinParameters].
     */
    class Builder {
        private val parameters = mutableMapOf<Int, ByteArray?>()

        constructor()
        constructor(paramsMap: MutableMap<Int, ByteArray>) {
            paramsMap.keys.forEach { key ->
                parameters[key] = paramsMap[key]
            }
        }

        constructor(params: SkeinParameters) {
            params.parameters.keys.forEach { key ->
                parameters[key] = params.parameters[key]
            }
        }

        /**
         * Sets a parameters to apply to the Skein hash function.<br></br>
         * Parameter types must be in the range 0,5..62, and cannot use the value [ ][.PARAM_TYPE_MESSAGE] (reserved for message body).
         *
         *
         * Parameters with type &lt; [.PARAM_TYPE_MESSAGE] are processed before
         * the message content, parameters with type &gt; [.PARAM_TYPE_MESSAGE]
         * are processed after the message and prior to output.
         *
         * @param type  the type of the parameter, in the range 5..62.
         * @param value the byte sequence of the parameter.
         * @return the current builder instance.
         */
        @Suppress("ThrowsCount", "ComplexCondition")
        fun set(type: Int, value: ByteArray): Builder {
            if (type != PARAM_TYPE_KEY &&
                (type < PARAM_TYPE_CONFIG || type >= PARAM_TYPE_OUTPUT || type == PARAM_TYPE_MESSAGE)
            ) {
                throw IllegalArgumentException("Parameter types must be in the range 0,5..47,49..62.")
            }
            if (type == PARAM_TYPE_CONFIG) {
                throw IllegalArgumentException(
                    "Parameter type " + PARAM_TYPE_CONFIG +
                            " is reserved for internal use."
                )
            }
            parameters[type] = value
            return this
        }

        /**
         * Sets the [.PARAM_TYPE_KEY] parameter.
         */
        fun setKey(key: ByteArray): Builder {
            return set(PARAM_TYPE_KEY, key)
        }

        /**
         * Sets the [.PARAM_TYPE_PERSONALISATION] parameter.
         */
        fun setPersonalisation(personalisation: ByteArray): Builder {
            return set(PARAM_TYPE_PERSONALISATION, personalisation)
        }

        /**
         * Implements the recommended personalisation format for Skein defined in Section 4.11 of
         * the Skein 1.3 specification.
         *
         *
         * The format is `YYYYMMDD email@address distinguisher`, encoded to a byte
         * sequence using UTF-8 encoding.
         *
         * @param date          the date the personalised application of the Skein was defined.
         * @param emailAddress  the email address of the creation of the personalised application.
         * @param distinguisher an arbitrary personalisation string distinguishing the application.
         * @return the current builder.
         */
        /*fun setPersonalisation(date: Date?, emailAddress: String?, distinguisher: String?): Builder {
            return try {
                val bout = ByteArrayOutputStream()
                val out = OutputStreamWriter(bout, "UTF-8")
                val format: DateFormat = SimpleDateFormat("YYYYMMDD")
                out.write(format.format(date))
                out.write(" ")
                out.write(emailAddress)
                out.write(" ")
                out.write(distinguisher)
                out.close()
                set(PARAM_TYPE_PERSONALISATION, bout.toByteArray())
            } catch (e: IOException) {
                throw java.lang.IllegalStateException("Byte I/O failed: $e")
            }
        }*/

        /**
         * Implements the recommended personalisation format for Skein defined in Section 4.11 of
         * the Skein 1.3 specification. You may need to use this method if the default locale
         * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible implementations.
         *
         *
         * The format is `YYYYMMDD email@address distinguisher`, encoded to a byte
         * sequence using UTF-8 encoding.
         *
         * @param date          the date the personalised application of the Skein was defined.
         * @param dateLocale    locale to be used for date interpretation.
         * @param emailAddress  the email address of the creation of the personalised application.
         * @param distinguisher an arbitrary personalisation string distinguishing the application.
         * @return the current builder.
         */
        /*fun setPersonalisation(date: Date?, dateLocale: Locale?, emailAddress: String?, distinguisher: String?): Builder {
            return try {
                val bout = ByteArrayOutputStream()
                val out = OutputStreamWriter(bout, "UTF-8")
                val format: DateFormat = SimpleDateFormat("YYYYMMDD", dateLocale)
                out.write(format.format(date))
                out.write(" ")
                out.write(emailAddress)
                out.write(" ")
                out.write(distinguisher)
                out.close()
                set(PARAM_TYPE_PERSONALISATION, bout.toByteArray())
            } catch (e: IOException) {
                throw java.lang.IllegalStateException("Byte I/O failed: $e")
            }
        }*/

        /**
         * Sets the [SkeinParameters.PARAM_TYPE_KEY_IDENTIFIER] parameter.
         */
        fun setPublicKey(publicKey: ByteArray): Builder {
            return set(PARAM_TYPE_PUBLIC_KEY, publicKey)
        }

        /**
         * Sets the [SkeinParameters.PARAM_TYPE_KEY_IDENTIFIER] parameter.
         */
        fun setKeyIdentifier(keyIdentifier: ByteArray): Builder {
            return set(PARAM_TYPE_KEY_IDENTIFIER, keyIdentifier)
        }

        /**
         * Sets the [SkeinParameters.PARAM_TYPE_NONCE] parameter.
         */
        fun setNonce(nonce: ByteArray): Builder {
            return set(PARAM_TYPE_NONCE, nonce)
        }

        /**
         * Constructs a new [SkeinParameters] instance with the parameters provided to this
         * builder.
         */
        fun build(): SkeinParameters {
            return SkeinParameters(parameters)
        }
    }

    companion object {
        /**
         * The parameter type for a secret key, supporting MAC or KDF functions: {@value
         * * #PARAM_TYPE_KEY}.
         */
        const val PARAM_TYPE_KEY = 0

        /**
         * The parameter type for the Skein configuration block: {@value #PARAM_TYPE_CONFIG}.
         */
        const val PARAM_TYPE_CONFIG = 4

        /**
         * The parameter type for a personalisation string: {@value #PARAM_TYPE_PERSONALISATION}.
         */
        const val PARAM_TYPE_PERSONALISATION = 8

        /**
         * The parameter type for a public key: {@value #PARAM_TYPE_PUBLIC_KEY}.
         */
        const val PARAM_TYPE_PUBLIC_KEY = 12

        /**
         * The parameter type for a key identifier string: {@value #PARAM_TYPE_KEY_IDENTIFIER}.
         */
        const val PARAM_TYPE_KEY_IDENTIFIER = 16

        /**
         * The parameter type for a nonce: {@value #PARAM_TYPE_NONCE}.
         */
        const val PARAM_TYPE_NONCE = 20

        /**
         * The parameter type for the message: {@value #PARAM_TYPE_MESSAGE}.
         */
        const val PARAM_TYPE_MESSAGE = 48

        /**
         * The parameter type for the output transformation: {@value #PARAM_TYPE_OUTPUT}.
         */
        const val PARAM_TYPE_OUTPUT = 63
    }

    init {
        this.parameters = parameters
    }
}
