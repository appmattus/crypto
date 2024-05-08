/*
 * Copyright 2023-2024 Appmattus Limited
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
    jvmToolchain(11)

    explicitApi()

    jvm()

    /* Disabled - Unit test failures, Blake, CubeHash, Haval, Luffa, SHA3, SHAKE, Tiger, cShake, HMac
       js {
           browser()
           nodejs()
           binaries.executable()
       }
     */

    // Tier 1
    // Apple macOS hosts only:
    macosX64() // Running tests
    macosArm64() // Running tests
    iosSimulatorArm64() // Running tests
    iosX64() // Running tests

    // Tier 2
    linuxX64() // Running tests
    linuxArm64()
    // Apple macOS hosts only:
    watchosSimulatorArm64() // Running tests
    watchosX64() // Running tests
    watchosArm32()
    watchosArm64()
    tvosSimulatorArm64() // Running tests
    tvosX64() // Running tests
    tvosArm64()
    iosArm64()

    // Tier 3
    androidNativeArm32()
    androidNativeArm64()
    androidNativeX86()
    androidNativeX64()
    mingwX64() // Running tests
    // Apple macOS hosts only:
    watchosDeviceArm64()

    // Apply the default hierarchy again. It'll create, for example, the iosMain source set:
    applyDefaultHierarchyTemplate()

    @Suppress("UnusedPrivateMember")
    sourceSets {
        val androidAndLinuxAndMingwMain by creating {
            dependsOn(commonMain.get())
        }
        val androidAndLinuxAndMingwTest by creating {
            dependsOn(commonTest.get())
        }
        val apple64Main by creating {
            dependsOn(appleMain.get())
        }
        val apple32Main by creating {
            dependsOn(appleMain.get())
        }

        linuxMain.get().dependsOn(androidAndLinuxAndMingwMain)
        mingwMain.get().dependsOn(androidAndLinuxAndMingwMain)
        androidNativeMain.get().dependsOn(androidAndLinuxAndMingwMain)
        linuxTest.get().dependsOn(androidAndLinuxAndMingwTest)
        mingwTest.get().dependsOn(androidAndLinuxAndMingwTest)
        androidNativeTest.get().dependsOn(androidAndLinuxAndMingwTest)

        val macosX64Main by getting { dependsOn(apple64Main) }
        val macosArm64Main by getting { dependsOn(apple64Main) }
        val iosSimulatorArm64Main by getting { dependsOn(apple64Main) }
        val iosX64Main by getting { dependsOn(apple64Main) }
        val watchosSimulatorArm64Main by getting { dependsOn(apple64Main) }
        val watchosX64Main by getting { dependsOn(apple64Main) }
        val watchosArm32Main by getting { dependsOn(apple32Main) }
        val watchosArm64Main by getting { dependsOn(apple32Main) }
        val tvosSimulatorArm64Main by getting { dependsOn(apple64Main) }
        val tvosX64Main by getting { dependsOn(apple64Main) }
        val tvosArm64Main by getting { dependsOn(apple64Main) }
        val iosArm64Main by getting { dependsOn(apple64Main) }
        val watchosDeviceArm64Main by getting { dependsOn(apple64Main) }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(kotlin("test-common"))
            implementation(kotlin("test-annotations-common"))
        }

        jvmTest.dependencies {
            implementation(kotlin("test-junit"))
            implementation(libs.bouncyCastle)
            implementation(libs.kotlinX.coroutinesCore)
        }

        appleTest.dependencies {
            implementation(libs.kotlinX.coroutinesCore)
        }

        /* Disabled - See reason above
           jsTest.dependencies {
               implementation(kotlin("test-js"))
           }
         */
    }
}

tasks.withType<Test>().configureEach {
    jvmArgs(
        "--add-opens=java.base/java.util.zip=ALL-UNNAMED",
    )
}

tasks.withType<AbstractPublishToMaven>()
    .matching { it.publication.name in listOf("jvm", "js", "kotlinMultiplatform") }
    .configureEach { onlyIf { hostOs == "Linux" } }
