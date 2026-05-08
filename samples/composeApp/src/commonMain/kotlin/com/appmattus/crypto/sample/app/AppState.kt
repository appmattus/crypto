package com.appmattus.crypto.sample.app

data class AppState(
    val backStack: List<AppRoute> = listOf(AppRoute.Home)
)
