package com.appmattus.crypto.sample.app

sealed interface AppRoute {
    data object Home : AppRoute
    data object CryptoHash : AppRoute
}
