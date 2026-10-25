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

package com.appmattus.crypto.sample.cryptohash

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.snapshots.Snapshot.Companion.withMutableSnapshot
import kotlinx.coroutines.test.runTest
import org.orbitmvi.orbit.test.TestSettings
import org.orbitmvi.orbit.test.testWithInternalState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CryptoHashViewModelTest {

    @Test
    fun initialStateContainsAlgorithmsAndDefaults() = runTest {
        CryptoHashViewModel().testWithInternalState(this) {
            val state = containerHost.container.stateFlow.value

            assertTrue(state.algorithms.contains("MD5"))
            assertEquals("", state.selectedAlgorithm)
            assertEquals("", state.input.text.toString())
            assertEquals("n/a", state.hash)
        }
    }

    @Test
    fun selectingAlgorithmUpdatesHashForCurrentInput() = runTest {
        CryptoHashViewModel().testWithInternalState(this) {
            containerHost.selectAlgorithm("MD5")

            val state = awaitInternalState()
            assertEquals("MD5", state.selectedAlgorithm)
            assertEquals("d41d8cd98f00b204e9800998ecf8427e", state.hash)
        }
    }

    @Test
    fun editingInputWithoutAlgorithmSelectedKeepsHashUnavailable() = runTest {
        CryptoHashViewModel().testWithInternalState(
            testScope = this,
            // Force a hash value in the initial state so we can observe it reset to `n/a`
            initialState = CryptoHashState(emptyList(), hash = "nothing"),
            settings = TestSettings(autoCheckInitialState = false)
        ) {
            val onCreateJob = runOnCreate()

            withMutableSnapshot {
                awaitInternalState().input.setTextAndPlaceCursorAtEnd("hello world")
            }

            val state = awaitInternalState()
            assertEquals("hello world", state.input.text.toString())
            assertEquals("n/a", state.hash)

            onCreateJob.cancel()
        }
    }

    @Test
    fun editingInputRecomputesHashForSelectedAlgorithm() = runTest {
        CryptoHashViewModel().testWithInternalState(this) {
            val onCreateJob = runOnCreate()

            containerHost.selectAlgorithm("MD5")
            val state = awaitInternalState()
            assertEquals("d41d8cd98f00b204e9800998ecf8427e", state.hash)

            withMutableSnapshot {
                state.input.setTextAndPlaceCursorAtEnd("hello world")
            }
            assertEquals("5eb63bbbe01eeed093cb22bb8f5acdc3", awaitInternalState().hash)

            onCreateJob.cancel()
        }
    }
}
