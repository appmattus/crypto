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
package com.appmattus.crypto.internal.core

/**
 * The low 64 bits of [a] × [b], the same as `a * b`.
 *
 * Kotlin/JS has its own implementation: its [Long] multiply is several times slower than a multiply in Int halves,
 * particularly for operands with their top bit set, which takes a slower path through negation.
 */
internal expect fun mulLow(a: ULong, b: ULong): ULong
