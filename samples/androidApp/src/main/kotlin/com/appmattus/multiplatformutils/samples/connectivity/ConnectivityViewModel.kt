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

package com.appmattus.multiplatformutils.samples.connectivity

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.appmattus.connectivity.Connectivity
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.collect
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.syntax.simple.intent
import org.orbitmvi.orbit.syntax.simple.reduce
import org.orbitmvi.orbit.viewmodel.container

@HiltViewModel
class ConnectivityViewModel @Inject constructor(
    private val connectivity: Connectivity,
    savedStateHandle: SavedStateHandle
) : ViewModel(), ContainerHost<ConnectivityState, Unit> {

    override val container: Container<ConnectivityState, Unit> = container(ConnectivityState(), savedStateHandle) {
        loadConnectivity()
    }

    private fun loadConnectivity() = intent(registerIdling = false) {
        connectivity.connectivityStatus.collect {
            reduce {
                 state.copy(connectivityStatus = it)
            }
        }
    }
}
