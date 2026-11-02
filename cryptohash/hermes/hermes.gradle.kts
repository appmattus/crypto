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
// - The Hermes CLI comes from the hermes-engine-cli npm package.
// - The JS test executable's modules are UMD, which register themselves on globalThis when there's no module loader, so
//   they're joined in dependency order between test-shim.js, which provides describe/it and console, and test-run.js,
//   which runs the tests.
// - That CLI can't parse class syntax, so Babel rewrites classes as functions first, as React Native's Babel preset
//   does. Babel is installed with npm ci from package-lock.json, so node and npm must be on the PATH.

val hermesCliVersion = "0.12.0"

repositories {
    exclusiveContent {
        forRepository {
            ivy {
                name = "npmRegistry"
                url = uri("https://registry.npmjs.org/")
                patternLayout { artifact("[module]/-/[module]-[revision].[ext]") }
                metadataSources { artifact() }
            }
        }
        filter { includeModule("npm", "hermes-engine-cli") }
    }
}

val hermesCli: Configuration = configurations.create("hermesCli") {
    isCanBeConsumed = false
    isTransitive = false
}

dependencies {
    hermesCli("npm:hermes-engine-cli:$hermesCliVersion@tgz")
}

val hermesBinDir = when {
    org.gradle.internal.os.OperatingSystem.current().isMacOsX -> "osx-bin"
    org.gradle.internal.os.OperatingSystem.current().isWindows -> "win64-bin"
    else -> "linux64-bin"
}

val extractHermes = tasks.register<Sync>("extractHermes") {
    description = "Extracts the Hermes CLI for this OS from the hermes-engine-cli npm package"
    from({ tarTree(resources.gzip(hermesCli.singleFile)) }) {
        include("package/$hermesBinDir/**")
        // Strip the package/<os>-bin/ prefix
        eachFile { path = relativePath.segments.drop(2).joinToString("/") }
        filePermissions { unix("rwxr-xr-x") }
    }
    includeEmptyDirs = false
    into(layout.buildDirectory.dir("hermes/bin"))
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

val isWindows = hermesBinDir == "win64-bin"
val babelDir = layout.buildDirectory.dir("hermes/babel")

val hermesBabelInstall = tasks.register<Exec>("hermesBabelInstall") {
    description = "Installs Babel from package-lock.json for the Hermes tests"
    val sources = listOf("package.json", "package-lock.json", "transform-classes.js").map {
        layout.projectDirectory.file("hermes/$it")
    }
    inputs.files(sources)
    outputs.dir(babelDir)
    workingDir(babelDir)
    executable = if (isWindows) "npm.cmd" else "npm"
    args("ci", "--no-audit", "--no-fund")
    doFirst {
        val dir = babelDir.get().asFile
        dir.deleteRecursively()
        dir.mkdirs()
        sources.forEach { it.asFile.copyTo(dir.resolve(it.asFile.name)) }
    }
}

val hermesTransformedBundle = layout.buildDirectory.file("hermes/test-bundle.es5.js")

val jsHermesTransform = tasks.register<Exec>("jsHermesTransform") {
    description = "Rewrites the classes in the Hermes test bundle as functions"
    dependsOn(hermesBabelInstall, jsHermesBundle)
    inputs.file(hermesBundle)
    outputs.file(hermesTransformedBundle)
    executable = "node"
    args(
        babelDir.get().file("transform-classes.js").asFile.path,
        hermesBundle.get().asFile.path,
        hermesTransformedBundle.get().asFile.path
    )
}

tasks.register<Exec>("jsHermesTest") {
    description = "Runs the JS unit tests on the Hermes JavaScript engine"
    group = "verification"
    dependsOn(extractHermes, jsHermesTransform)
    inputs.file(hermesTransformedBundle)
    executable = layout.buildDirectory.file("hermes/bin/" + if (isWindows) "hermes.exe" else "hermes").get().asFile.path
    // -w hides compile-time warnings about globals such as console, which the shim defines at run time
    args("-w", hermesTransformedBundle.get().asFile.path)
}
