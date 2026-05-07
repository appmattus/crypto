package com.appmattus.crypto.sample

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform
