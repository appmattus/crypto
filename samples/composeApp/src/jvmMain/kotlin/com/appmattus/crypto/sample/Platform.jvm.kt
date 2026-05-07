@file:Suppress("MatchingDeclarationName")

package com.appmattus.crypto.sample

class JVMPlatform : Platform {
    override val name: String = "Java ${System.getProperty("java.version")}"
}

actual fun getPlatform(): Platform = JVMPlatform()
