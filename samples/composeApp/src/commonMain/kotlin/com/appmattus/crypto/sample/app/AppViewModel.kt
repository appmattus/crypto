package com.appmattus.crypto.sample.app

import androidx.lifecycle.ViewModel
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.viewmodel.container

class AppViewModel(
) : ViewModel(), ContainerHost<AppState, Nothing> {

    override val container: Container<AppState, Nothing> = container(
        AppState()
    )

    fun openCryptoHash() = intent {
        reduce {
            state.copy(backStack = state.backStack + AppRoute.CryptoHash)
        }
    }

    fun navigateBack() = intent {
        if (state.backStack.size > 1) {
            reduce {
                state.copy(backStack = state.backStack.dropLast(1))
            }
        }
    }
}
