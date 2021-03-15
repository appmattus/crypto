/*
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

package com.appmattus.crypto.samples.cryptohash

import androidx.lifecycle.ViewModel
import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import dagger.hilt.android.lifecycle.HiltViewModel
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.syntax.simple.intent
import org.orbitmvi.orbit.syntax.simple.reduce
import org.orbitmvi.orbit.viewmodel.container
import javax.inject.Inject

@HiltViewModel
class CryptoHashViewModel @Inject constructor() : ViewModel(), ContainerHost<CryptoHashState, Unit> {

    private var currentAlgorithm: Algorithm? = null
    private var inputText: String = ""

    override val container: Container<CryptoHashState, Unit> = container(CryptoHashState(algorithms = algorithms.map { it.algorithmName })) {
        generateHash()
    }

    fun selectAlgorithm(name: String) = intent {
        currentAlgorithm = algorithms.firstOrNull { it.algorithmName == name }
        generateHash()
    }

    fun setInputText(input: String) = intent {
        inputText = input
        generateHash()
    }

    private fun generateHash() = intent {
        val digest = try {
            currentAlgorithm?.let { Digest.create(it) }?.digest(inputText.encodeToByteArray())?.toHexString() ?: "n/a"
        } catch (expected: Exception) {
            expected.message ?: expected.toString()
        }

        reduce {
            state.copy(
                hash = digest
            )
        }
    }

    companion object {
        private val algorithms = listOf(
            Algorithm.Adler32,
            Algorithm.BLAKE512,
            Algorithm.Blake2b_512,
            Algorithm.Blake2s_256,
            Algorithm.Blake3(),
            Algorithm.BMW512,
            Algorithm.CRC32,
            Algorithm.cSHAKE256(),
            Algorithm.CubeHash512,
            Algorithm.DSTU7564_512,
            Algorithm.ECHO512,
            Algorithm.Fugue512,
            Algorithm.GOST3411_2012_512,
            Algorithm.Groestl512,
            Algorithm.Hamsi512,
            Algorithm.Haraka512_256,
            Algorithm.HAVAL_3_256,
            Algorithm.JH512,
            Algorithm.Keccak512,
            Algorithm.Luffa512,
            Algorithm.MD5,
            Algorithm.PANAMA,
            Algorithm.RadioGatun64,
            Algorithm.RipeMD256,
            Algorithm.SHA_512_256,
            Algorithm.SHA3_512,
            Algorithm.Shabal512,
            Algorithm.SHAKE256,
            Algorithm.SHAvite512,
            Algorithm.SIMD512,
            Algorithm.Skein1024_512,
            Algorithm.SM3,
            Algorithm.Tiger,
            Algorithm.Whirlpool,
        )

        private fun ByteArray.toHexString(): String {
            return joinToString("") { (0xFF and it.toInt()).toString(16).padStart(2, '0') }
        }
    }
}
