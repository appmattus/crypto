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
    id("com.android.library")
    id("kotlin-parcelize")
}

kotlin {
    android()
    ios {
        binaries {
            framework {
                export(project(":cryptohash"))
                baseName = "shared"
            }
        }
    }
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":cryptohash"))
            }
        }
        val commonTest by getting
        val androidMain by getting
        val androidTest by getting
        val iosMain by getting
        val iosTest by getting
    }
}

android {
    compileSdk = 31
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
    defaultConfig {
        minSdk = 21
        targetSdk = 31
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> { kotlinOptions.jvmTarget = "1.8" }

val hostOs = System.getProperty("os.name")

val xcFrameworkPath = "$buildDir/xcode-frameworks/${project.name}.xcframework"

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
