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

import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("multiplatform")
    id("com.vanniktech.maven.publish")
    id("org.jetbrains.dokka")
}

// val hostOs = System.getProperty("os.name")
// val isLinux = hostOs == "Linux"
// val isWindows = hostOs.startsWith("Windows")
// val isMacOs = hostOs == "Mac OS X"

val hostOs: String = System.getProperty("os.name")

kotlin {
    explicitApi()

    jvm()

    // Darwin
    iosArm64()
    iosX64()
    iosSimulatorArm64()
    tvosArm64()
    tvosX64()
    watchosArm32()
    watchosArm64()
    watchosX64()
    macosArm64()
    macosX64()

    /* Disabled - Unit test failures, Blake, CubeHash, Haval, Luffa, SHA3, SHAKE, Tiger, cShake, HMac
       js {
           browser()
           nodejs()
           binaries.executable()
       }
     */

    // Linux
    linuxX64()
    linuxArm32Hfp()
    linuxArm64()
    linuxMips32()
    linuxMipsel32()

    // Windows
    mingwX64()
    mingwX86()

    @Suppress("UnusedPrivateMember")
    sourceSets {
        val commonMain by getting
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val jvmMain by getting
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation(libs.bouncyCastle)
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${libs.versions.coroutines.get()}")
            }
        }

        /* Disabled - See reason above
        val jsMain by getting
        val jsTest by getting {
            dependencies {
                implementation(kotlin("test-js"))
            }
        }*/

        val nativeMain by creating {
            dependsOn(commonMain)
        }
        val nativeTest by creating {
            dependsOn(commonTest)
        }

        val nativeAltTest by creating {
            dependsOn(nativeTest)
        }

        // Darwin
        val nativeDarwin64Main by creating {
            dependsOn(commonMain)
        }
        val nativeDarwin64Test by creating {
            dependsOn(commonTest)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${libs.versions.coroutines.get()}")
            }
        }
        val nativeDarwin32Main by creating {
            dependsOn(commonMain)
        }
        val nativeDarwin32Test by creating {
            dependsOn(commonTest)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${libs.versions.coroutines.get()}")
            }
        }
        // ios
        val iosArm64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val iosArm64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        val iosX64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val iosX64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        val iosSimulatorArm64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val iosSimulatorArm64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        // tvos
        val tvosArm64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val tvosArm64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        val tvosX64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val tvosX64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        // watchos
        val watchosArm32Main by getting {
            dependsOn(nativeDarwin32Main)
        }
        val watchosArm32Test by getting {
            dependsOn(nativeDarwin32Test)
        }
        val watchosArm64Main by getting {
            dependsOn(nativeDarwin32Main)
        }
        val watchosArm64Test by getting {
            dependsOn(nativeDarwin32Test)
        }
        val watchosX64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val watchosX64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        val macosArm64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val macosArm64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
        val macosX64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val macosX64Test by getting {
            dependsOn(nativeDarwin64Test)
        }

        // Linux
        val linuxX64Main by getting {
            dependsOn(nativeMain)
        }
        val linuxX64Test by getting {
            dependsOn(nativeAltTest)
        }
        val linuxArm32HfpMain by getting {
            dependsOn(nativeMain)
        }
        val linuxArm32HfpTest by getting {
            dependsOn(nativeAltTest)
        }
        val linuxArm64Main by getting {
            dependsOn(nativeMain)
        }
        val linuxArm64Test by getting {
            dependsOn(nativeAltTest)
        }
        val linuxMips32Main by getting {
            dependsOn(nativeMain)
        }
        val linuxMips32Test by getting {
            dependsOn(nativeAltTest)
        }
        val linuxMipsel32Main by getting {
            dependsOn(nativeMain)
        }
        val linuxMipsel32Test by getting {
            dependsOn(nativeAltTest)
        }

        // Windows
        val mingwX64Main by getting {
            dependsOn(nativeMain)
        }
        val mingwX64Test by getting {
            dependsOn(nativeAltTest)
        }
        val mingwX86Main by getting {
            dependsOn(nativeMain)
        }
        val mingwX86Test by getting {
            dependsOn(nativeAltTest)
        }
    }
}

tasks.withType<KotlinCompile> { kotlinOptions.jvmTarget = JavaVersion.VERSION_1_8.toString() }

tasks.withType<Test>().configureEach {
    jvmArgs(
        "--add-opens=java.base/java.util.zip=ALL-UNNAMED",
    )
}

tasks.withType<AbstractPublishToMaven>()
    .matching { it.publication.name in listOf("jvm", "js", "kotlinMultiplatform") }
    .configureEach { onlyIf { hostOs == "Linux" } }
