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

// Runs the JS unit tests on Hermes, the JavaScript engine React Native uses, with ./gradlew :cryptohash:jsHermesTest.
//
// - The hermes CLI is built from source at hermesVersion, the Hermes React Native 0.88.1 pins in sdks/.hermesv1version.
//   Hermes publishes prebuilt binaries only for the hermesc compiler, not the CLI. The build needs git, CMake, Ninja, a
//   C++ compiler and the ICU development files (libicu-dev on Debian/Ubuntu), and is reused until hermesVersion changes.
// - Pass -Phermes.path=/path/to/hermes to use an existing hermes binary instead.
// - The JS test executable's modules are UMD, which register themselves on globalThis when there's no module loader, so
//   they're joined in dependency order between test-shim.js, which provides describe/it, and test-run.js, which runs
//   the tests.

val hermesVersion = "260318099.0.5"
val hermesPath: Provider<String> = providers.gradleProperty("hermes.path")
val isWindows = org.gradle.internal.os.OperatingSystem.current().isWindows

val hermesDir = layout.buildDirectory.dir("hermes/$hermesVersion")
val hermesSourceDir = hermesDir.map { it.dir("src") }
val hermesBuildDir = hermesDir.map { it.dir("build") }
val hermesBinary = hermesBuildDir.map { it.file(if (isWindows) "bin/hermes.exe" else "bin/hermes") }

val hermesSource = tasks.register<Exec>("hermesSource") {
    description = "Clones the Hermes source at version $hermesVersion"
    onlyIf { !hermesPath.isPresent }
    inputs.property("version", hermesVersion)
    outputs.dir(hermesSourceDir)
    doFirst { hermesSourceDir.get().asFile.deleteRecursively() }
    commandLine(
        "git", "clone", "--quiet", "--depth", "1", "--branch", "hermes-v$hermesVersion",
        "https://github.com/meta/hermes.git", hermesSourceDir.get().asFile.path
    )
}

val hermesConfigure = tasks.register<Exec>("hermesConfigure") {
    description = "Configures the Hermes CLI build with CMake"
    onlyIf { !hermesPath.isPresent }
    dependsOn(hermesSource)
    inputs.property("version", hermesVersion)
    outputs.file(hermesBuildDir.map { it.file("build.ninja") })
    commandLine(
        "cmake", "-S", hermesSourceDir.get().asFile.path, "-B", hermesBuildDir.get().asFile.path, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DHERMES_ENABLE_DEBUGGER=OFF"
    )
}

val buildHermes = tasks.register<Exec>("buildHermes") {
    description = "Builds the Hermes CLI from source"
    onlyIf { !hermesPath.isPresent }
    dependsOn(hermesConfigure)
    inputs.property("version", hermesVersion)
    outputs.file(hermesBinary)
    commandLine("cmake", "--build", hermesBuildDir.get().asFile.path, "--target", "hermes")
}

val jsTestExecutableDir = layout.buildDirectory.dir("compileSync/js/test/testDevelopmentExecutable/kotlin")
val hermesBundle = layout.buildDirectory.file("hermes/test-bundle.js")

val jsHermesBundle = tasks.register("jsHermesBundle") {
    description = "Joins the JS test executable's modules into one script for the Hermes CLI"
    dependsOn("jsTestTestDevelopmentExecutableCompileSync")
    val shim = layout.projectDirectory.file("hermes/test-shim.js")
    val runner = layout.projectDirectory.file("hermes/test-run.js")
    inputs.dir(jsTestExecutableDir)
    inputs.files(shim, runner)
    outputs.file(hermesBundle)

    doLast {
        val modules = jsTestExecutableDir.get().asFile.listFiles { file -> file.extension == "js" }!!.associateBy { it.name }

        // Each UMD module lists its dependencies in its AMD define call, for example define(['exports', './a.js'], ...)
        val define = Regex("""define\(\[([^\]]*)\]""")
        fun dependencies(file: File): List<String> = define.find(file.readText())?.groupValues?.get(1)
            ?.split(',')?.map { it.trim().trim('\'', '"').removePrefix("./") }?.filter { it in modules }
            ?: emptyList()

        val ordered = LinkedHashSet<String>()
        fun visit(name: String, path: List<String>) {
            check(name !in path) { "Circular module dependency: ${(path + name).joinToString(" -> ")}" }
            if (name in ordered) return
            dependencies(modules.getValue(name)).forEach { visit(it, path + name) }
            ordered += name
        }
        modules.keys.sorted().forEach { visit(it, emptyList()) }

        hermesBundle.get().asFile.apply {
            parentFile.mkdirs()
            writeText(shim.asFile.readText())
            ordered.forEach { appendText("\n// ---- $it ----\n" + modules.getValue(it).readText()) }
            appendText("\n" + runner.asFile.readText())
        }
        logger.lifecycle("Hermes bundle: ${ordered.joinToString(", ")}")
    }
}

tasks.register<Exec>("jsHermesTest") {
    description = "Runs the JS unit tests on the Hermes JavaScript engine"
    group = "verification"
    dependsOn(buildHermes, jsHermesBundle)
    inputs.file(hermesBundle)
    executable = hermesPath.orElse(hermesBinary.map { it.asFile.path }).get()
    // -w hides compile-time warnings about globals such as print, which only exist at run time
    args("-w", hermesBundle.get().asFile.path)
}
