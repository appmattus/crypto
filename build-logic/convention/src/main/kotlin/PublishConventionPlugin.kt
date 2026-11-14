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
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

/**
 * Publishing for a library module: Maven Central through gradle-maven-publish-plugin, configured from the root and
 * module gradle.properties (POM_ARTIFACT_ID, POM_NAME and so on), with Dokka for the javadoc artifacts.
 *
 * Also validates the published binary API against the dumps in each module's api directory: checkKotlinAbi fails when
 * the public API changes, and updateKotlinAbi records an intended change.
 */
class PublishConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        target.pluginManager.apply("com.vanniktech.maven.publish")
        target.pluginManager.apply("org.jetbrains.dokka")

        target.pluginManager.withPlugin("org.jetbrains.kotlin.multiplatform") {
            target.extensions.configure<KotlinMultiplatformExtension> {
                @OptIn(ExperimentalAbiValidation::class)
                abiValidation {
                    // Shared between the cryptohash modules only, so free to change
                    filters {
                        exclude {
                            annotatedWith.add("com.appmattus.crypto.InternalCryptohash")
                        }
                    }
                }
            }
        }
    }
}
