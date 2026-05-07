@file:Suppress("Filename")

package com.appmattus.crypto.sample

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "Crypto Sample",
    ) {
        App()
    }
}
