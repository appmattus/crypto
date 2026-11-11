/*
 * Copyright 2026 Appmattus Limited
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

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

/**
 * The Kotlin Multiplatform setup every library module shares: the JVM toolchain, explicit API mode, every target the
 * library supports and the source set hierarchy between them.
 *
 * Shared source sets, beyond the default hierarchy:
 * - byteArrayMain: platforms that use ByteArray as PlatformData, i.e. everything other than Darwin
 * - portableMain: platforms without their own hash implementations to delegate to
 * - nativeLongMain: portable platforms whose Long is a 64-bit machine integer, i.e. everything other than Kotlin/JS
 * - apple64Main and apple32Main: Apple targets by pointer width
 * - androidAndLinuxAndMingwTest: tests shared by those platforms
 */
class KmpLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        target.pluginManager.apply("org.jetbrains.kotlin.multiplatform")

        target.extensions.configure<KotlinMultiplatformExtension> {
            jvmToolchain(JVM_TOOLCHAIN)

            explicitApi()

            configureTargets()
            configureSourceSets()
        }
    }

    @OptIn(ExperimentalWasmDsl::class)
    private fun KotlinMultiplatformExtension.configureTargets() {
        jvm()

        js {
            browser()
            nodejs {
                testTask {
                    // Mocha's default 2s per-test timeout is too short for the larger known-answer tests on CI.
                    // Browser tests get the same setting from karma.config.d.
                    useMocha { timeout = "60s" }
                }
            }
        }

        wasmJs {
            browser()
            nodejs()
        }
        wasmWasi {
            nodejs()
        }

        // Tier 1
        // Apple macOS hosts only:
        macosArm64() // Running tests
        iosSimulatorArm64() // Running tests
        iosX64() // Running tests

        // Tier 2
        linuxX64() // Running tests
        linuxArm64()
        // Apple macOS hosts only:
        watchosSimulatorArm64() // Running tests
        watchosArm32()
        watchosArm64()
        tvosSimulatorArm64() // Running tests
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
    }

    private fun KotlinMultiplatformExtension.configureSourceSets() {
        sourceSets.apply {
            val commonMain = getByName("commonMain")
            val commonTest = getByName("commonTest")
            val appleMain = getByName("appleMain")

            val byteArrayMain = create("byteArrayMain") { dependsOn(commonMain) }
            val portableMain = create("portableMain") { dependsOn(byteArrayMain) }
            val nativeLongMain = create("nativeLongMain") { dependsOn(portableMain) }
            val androidAndLinuxAndMingwTest = create("androidAndLinuxAndMingwTest") { dependsOn(commonTest) }
            val apple64Main = create("apple64Main") { dependsOn(appleMain) }
            val apple32Main = create("apple32Main") { dependsOn(appleMain) }

            getByName("jvmMain").dependsOn(byteArrayMain)
            getByName("jsMain").dependsOn(portableMain)
            listOf("wasmJsMain", "wasmWasiMain", "linuxMain", "mingwMain", "androidNativeMain").forEach {
                getByName(it).dependsOn(nativeLongMain)
            }
            listOf("linuxTest", "mingwTest", "androidNativeTest").forEach {
                getByName(it).dependsOn(androidAndLinuxAndMingwTest)
            }

            listOf(
                "macosArm64Main",
                "iosSimulatorArm64Main",
                "iosX64Main",
                "watchosSimulatorArm64Main",
                "tvosSimulatorArm64Main",
                "tvosArm64Main",
                "iosArm64Main",
                "watchosDeviceArm64Main"
            ).forEach { getByName(it).dependsOn(apple64Main) }
            listOf("watchosArm32Main", "watchosArm64Main").forEach { getByName(it).dependsOn(apple32Main) }

            commonTest.dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
            getByName("jvmTest").dependencies {
                implementation(kotlin("test-junit"))
            }
            getByName("jsTest").dependencies {
                implementation(kotlin("test-js"))
            }
        }
    }

    private companion object {
        const val JVM_TOOLCHAIN = 11
    }
}
