/*
 * Copyright 2021-2026 Appmattus Limited
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

plugins {
    alias(libs.plugins.android.application)
    id("kotlin-parcelize")
    id("com.google.devtools.ksp")
    id("androidx.navigation.safeargs.kotlin")
}

apply(plugin = "dagger.hilt.android.plugin")

dependencies {
    implementation(project(":samples:shared"))

    implementation(libs.kotlinX.coroutinesCore)
    implementation(libs.kotlinX.coroutinesAndroid)

    // Architecture
    implementation(libs.androidX.fragment)
    implementation(libs.androidX.lifecycleRuntime)
    implementation(libs.androidX.lifecycleViewmodel)
    implementation(libs.androidX.navigationFragment)
    implementation(libs.androidX.navigationUi)
    implementation(libs.orbitCore)
    implementation(libs.orbitViewmodel)

    // UI
    implementation(libs.google.material)
    implementation(libs.androidX.appCompat)
    implementation(libs.androidX.constraintLayout)
    implementation(libs.androidX.vectorDrawable)
    implementation(libs.groupie)
    implementation(libs.groupieViewbinding)

    // Memory leak detection and fixes
    debugImplementation(libs.leakcanary.leakcanary)
    implementation(libs.leakcanary.plumber)

    // Dependency Injection
    implementation(libs.google.dagger.hiltAndroid)
    ksp(libs.google.dagger.hiltCompiler)

    coreLibraryDesugaring(libs.desugar)
}

android {
    namespace = "com.appmattus.crypto.samples"

    compileSdk = 34
    defaultConfig {
        applicationId = "com.appmattus.crypto.samples"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        vectorDrawables.useSupportLibrary = true
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
    }

    buildFeatures {
        viewBinding = true
    }

    sourceSets.all {
        java.srcDir("src/$name/kotlin")
    }
}

kotlin {
    jvmToolchain(11)
}
