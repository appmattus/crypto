/*
 * Copyright 2021 Appmattus Limited
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

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    alias(libs.plugins.android.library)
    id("kotlin-parcelize")
}

kotlin {
    androidTarget()
    ios {
        binaries {
            framework {
                export(project(":cryptohash"))
                baseName = "shared"
            }
        }
    }
    @Suppress("UnusedPrivateMember")
    sourceSets {
        commonMain {
            dependencies {
                api(project(":cryptohash"))
            }
        }
    }
}

android {
    namespace = "com.appmattus.crypto.shared"

    compileSdk = 34
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
    defaultConfig {
        minSdk = 21
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }
}

val hostOs = System.getProperty("os.name")

val xcFrameworkPath = "${layout.buildDirectory}/xcode-frameworks/${project.name}.xcframework"

if (hostOs == "Mac OS X") {
    tasks.create<Delete>("deleteXcFramework") { delete = setOf(xcFrameworkPath) }
}

val buildXcFramework by tasks.registering {
    dependsOn("deleteXcFramework")
    group = "build"
    val mode = "Release"
    val frameworks = arrayOf("iosArm64", "iosX64")
        .map { kotlin.targets.getByName<KotlinNativeTarget>(it).binaries.getFramework(mode) }
    inputs.property("mode", mode)
    dependsOn(frameworks.map { it.linkTask })
    doLast { buildXcFramework(frameworks) }
}

fun Task.buildXcFramework(frameworks: List<org.jetbrains.kotlin.gradle.plugin.mpp.Framework>) {
    val buildArgs: () -> List<String> = {
        val arguments = mutableListOf("-create-xcframework")
        frameworks.forEach {
            arguments += "-framework"
            arguments += "${it.outputDirectory}/${project.name}.framework"
        }
        arguments += "-output"
        arguments += xcFrameworkPath
        arguments
    }
    exec {
        executable = "xcodebuild"
        args = buildArgs()
    }
}

if (hostOs == "Mac OS X") {
    tasks.getByName("build").dependsOn(buildXcFramework)
}
