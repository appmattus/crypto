package com.appmattus.crypto.sample.di

import com.appmattus.crypto.sample.app.AppViewModel
import com.appmattus.crypto.sample.app.SampleHashPreview
import org.koin.core.module.dsl.factoryOf
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

val sampleAppModule = module {
    singleOf(::SampleHashPreview)
    factoryOf(::AppViewModel)
}
