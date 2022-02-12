/*
 * Copyright 2022 Appmattus Limited
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

package com.appmattus.crypto.internal.core.city

internal class ULongLong(var lowValue: ULong, var highValue: ULong) : Number() {

    override fun toByte() = toLong().toByte()

    override fun toChar() = toLong().toChar()

    override fun toDouble() = toLong().toDouble()

    override fun toFloat() = toLong().toFloat()

    override fun toInt() = toLong().toInt()

    override fun toLong() = lowValue.toLong()

    override fun toShort() = toLong().toShort()
}
