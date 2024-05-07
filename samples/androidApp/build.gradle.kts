/*
 * Copyright 2023 Appmattus Limited
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
    id("com.android.application")
    kotlin("android")
    id("kotlin-parcelize")
    kotlin("kapt")
    id("androidx.navigation.safeargs.kotlin")
}

apply(plugin = "dagger.hilt.android.plugin")

dependencies {
    implementation(project(":samples:shared"))

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${libs.versions.coroutines.get()}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:${libs.versions.coroutines.get()}")

    // Architecture
    implementation(libs.androidX.fragment)
    implementation(libs.androidX.lifecycleRuntime)
    implementation(libs.androidX.lifecycleViewmodel)
    implementation(libs.androidX.navigationFragment)
    implementation(libs.androidX.navigationUi)
    implementation(libs.orbitViewmodel)

    // UI
    implementation("com.google.android.material:material:${libs.versions.google.material.get()}")
    implementation(libs.androidX.appCompat)
    implementation(libs.androidX.constraintLayout)
    implementation(libs.androidX.vectorDrawable)
    implementation(libs.groupie)
    implementation(libs.groupieViewbinding)

    // Memory leak detection and fixes
    debugImplementation("com.squareup.leakcanary:leakcanary-android:${libs.versions.leakCanary.get()}")
    implementation("com.squareup.leakcanary:plumber-android:${libs.versions.leakCanary.get()}")

    // Dependency Injection
    implementation("com.google.dagger:hilt-android:${libs.versions.google.dagger.get()}")
    kapt("com.google.dagger:hilt-compiler:${libs.versions.google.dagger.get()}")

    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:${libs.versions.desugar.get()}")
}

android {
    compileSdk = 33
    defaultConfig {
        applicationId = "com.appmattus.crypto.samples"
        minSdk = 21
        targetSdk = 33
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

        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_1_8.toString()
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    sourceSets.all {
        java.srcDir("src/$name/kotlin")
    }
}
