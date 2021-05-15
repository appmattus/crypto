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

kotlin {
    jvm()

    // Darwin
    iosArm64()
    iosX64()
    tvosArm64()
    tvosX64()
    watchosArm32()
    watchosArm64()
    watchosX64()
    macosX64()

    /* Disabled - Unit test failures, Blake, CubeHash, Haval, Luffa, SHA3, SHAKE, Tiger, cShake, HMac
    js {
        browser()
        nodejs()
        binaries.executable()
    }
    */

    /*
    mingwX64()
    mingwX86()
    linuxX64()
    linuxArm32Hfp()
    linuxArm64()
    linuxMips32()
    linuxMipsel32()
    */

    sourceSets {
        val commonMain by getting
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val jvmMain by getting {
            dependencies {
                compileOnly("org.bouncycastle:bcprov-jdk15to18:1.68")
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("org.bouncycastle:bcprov-jdk15to18:1.68")
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

        // Darwin
        val nativeDarwin64Main by creating {
            dependsOn(nativeMain)
        }
        val nativeDarwin64Test by creating {
            dependsOn(nativeTest)
        }
        val nativeDarwin32Main by creating {
            dependsOn(nativeMain)
        }
        val nativeDarwin32Test by creating {
            dependsOn(nativeTest)
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
        val macosX64Main by getting {
            dependsOn(nativeDarwin64Main)
        }
        val macosX64Test by getting {
            dependsOn(nativeDarwin64Test)
        }
    }
}

tasks.withType<KotlinCompile> { kotlinOptions.jvmTarget = JavaVersion.VERSION_1_8.toString() }
