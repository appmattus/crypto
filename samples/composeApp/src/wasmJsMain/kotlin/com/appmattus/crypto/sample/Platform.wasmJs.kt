@file:Suppress("MatchingDeclarationName")

package com.appmattus.crypto.sample

class WasmPlatform : Platform {
    override val name: String = "Web with Kotlin/Wasm"
}

actual fun getPlatform(): Platform = WasmPlatform()
