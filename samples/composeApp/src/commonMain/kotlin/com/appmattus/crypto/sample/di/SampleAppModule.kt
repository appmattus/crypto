package com.appmattus.crypto.sample.di

import com.appmattus.crypto.sample.app.AppViewModel
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module

val sampleAppModule = module {
    factoryOf(::AppViewModel)
}
