// Modified by 0xkey
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import kotlinx.kover.gradle.plugin.dsl.KoverProjectExtension
import org.gradle.api.DefaultTask
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

plugins {
    id("com.vanniktech.maven.publish") version "0.34.0" apply false

    kotlin("jvm") version "2.2.20" apply false
    kotlin("plugin.serialization") version "2.2.20" apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.android.application) apply false
    id("com.android.library") version "8.13.0" apply false
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.18.1"
    id("org.jetbrains.kotlinx.kover") version "0.9.3"
}

/**
 * Line-coverage floors of the JVM unit tests, checked by `koverVerifyUnit` in CI. Raise a floor when
 * coverage rises; never lower one to make a change pass. Generated code and adapters that only run on
 * a device (covered by instrumented tests) are excluded.
 */
val coverageFloors = mapOf(
    ":packages:crypto" to 85,
    ":packages:encoding" to 85,
    ":packages:http" to 90,
    ":packages:stamper" to 55,
    ":packages:sdk-kotlin" to 14,
)

kover {
    merge {
        projects(*coverageFloors.keys.toTypedArray())
        createVariant("unit") { add("jvm", "debug", optional = true) }
    }
}

coverageFloors.forEach { (path, floor) ->
    project(path).afterEvaluate {
        extensions.configure<KoverProjectExtension> {
            reports {
                filters {
                    excludes {
                        classes(
                            "io.zeroxkey.http.ZeroXKeyClient", "io.zeroxkey.http.ZeroXKeyClient$*",
                            "io.zeroxkey.stamper.internal.keys.AndroidKeystoreBackend",
                            "*.BuildConfig",
                        )
                    }
                }
                variant("unit") {
                    verify { rule { minBound(floor) } }
                }
            }
        }
    }
}

apiValidation {
    ignoredProjects += listOf("tools", "kotlin-demo-wallet")
    nonPublicMarkers += "io.zeroxkey.stamper.InternalZeroXKeyApi"
}

val publishable = listOf(
    ":packages:crypto",
    ":packages:encoding",
    ":packages:http",
    ":packages:passkey",
    ":packages:stamper",
    ":packages:types",
    ":packages:sdk-kotlin",
)

group = "io.0xkey"
version = "0.1.1"

/** GitHub Packages registry of this repository: the only remote publishing target. */
val githubPackagesUrl = "https://maven.pkg.github.com/0xkey-io/sdk-kotlin"

configure(publishable.map { project(it) }) {
    apply(plugin = "com.vanniktech.maven.publish")

    extensions.configure<PublishingExtension> {
        repositories {
            maven {
                name = "GitHubPackages"
                url = uri(githubPackagesUrl)
                credentials {
                    username = providers.environmentVariable("GITHUB_ACTOR").orNull
                    password = providers.environmentVariable("GITHUB_TOKEN").orNull
                }
            }
        }
    }
    tasks.matching { it.name.endsWith("ToGitHubPackagesRepository") }
        .configureEach { dependsOn(":verifyPublishVersion") }

    // Every published archive (jar, aar, sources, javadoc) carries LICENSE and NOTICE in META-INF.
    tasks.withType<AbstractArchiveTask>()
        .matching {
            it is Jar || it.name.endsWith("JavadocJar") ||
                (it.name.startsWith("bundle") && it.name.endsWith("Aar"))
        }
        .configureEach {
            from(rootProject.layout.projectDirectory.file("LICENSE")) { into("META-INF") }
            from(rootProject.layout.projectDirectory.file("NOTICE")) { into("META-INF") }
        }

    extensions.configure<MavenPublishBaseExtension> {
        pom {
            name.set(project.name)
            description.set("0xkey Kotlin SDK module: ${project.name}")
            url.set("https://github.com/0xkey-io/sdk-kotlin")
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                }
            }
            scm {
                url.set("https://github.com/0xkey-io/sdk-kotlin")
                connection.set("scm:git:https://github.com/0xkey-io/sdk-kotlin.git")
                developerConnection.set("scm:git:ssh://git@github.com:0xkey-io/sdk-kotlin.git")
            }
            developers {
                developer { id.set("0xkey"); name.set("0xkey") }
            }
        }
    }
}

val lastBumpedFile = layout.projectDirectory.file(".changeset/.last_bumped_modules")

val bumpedModulesProvider = providers.provider {
    val f = lastBumpedFile.asFile
    if (!f.exists()) emptyList()
    else f.readLines()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
}


tasks.register("publishSelectedToMavenLocal") {
    group = "publishing"
    description = "Publish only modules listed in .changeset/.last_bumped_modules to Maven Local"

    dependsOn(
        bumpedModulesProvider.map { mods ->
            mods.map { mod -> ":packages:$mod:publishToMavenLocal" }
        }
    )

    finalizedBy("printPublishMatrix")
}

tasks.register("publishAllToMavenLocal") {
    group = "publishing"
    description= "Publish all modules to Maven Local"

    dependsOn(
        publishable.map { mod ->"${mod}:publishToMavenLocal" }
    )
}

// All publishable modules share one version, so a release publishes all of them.
tasks.register("publishAllToGitHubPackages") {
    group = "publishing"
    description = "Publish all modules to the GitHub Packages registry (needs GITHUB_ACTOR / GITHUB_TOKEN)"

    dependsOn("verifyPublishVersion")
    dependsOn(
        publishable.map { mod -> "${mod}:publishAllPublicationsToGitHubPackagesRepository" }
    )

    finalizedBy("printPublishMatrix")
}

/**
 * Refuses to publish a -SNAPSHOT or a mixed version. With -PexpectedVersion=X.Y.Z (the release
 * workflow passes the tag without its `v`), every publishable module must be at exactly that version.
 */
abstract class VerifyPublishVersionTask : DefaultTask() {
    @get:Input abstract val versions: ListProperty<String>
    @get:Input @get:org.gradle.api.tasks.Optional abstract val expected: Property<String>

    @TaskAction
    fun run() {
        val distinct = versions.get().map { it.substringAfter('=') }.distinct()
        check(distinct.size == 1) { "Publishable modules disagree on the version: ${versions.get()}" }
        val version = distinct.single()
        check(!version.endsWith("-SNAPSHOT")) { "Refusing to publish snapshot version $version" }
        expected.orNull?.let {
            check(version == it) { "Module version $version does not match the expected release version $it" }
        }
        println("Publish version: $version")
    }
}

val verifyPublishVersion = tasks.register<VerifyPublishVersionTask>("verifyPublishVersion") {
    expected.set(providers.gradleProperty("expectedVersion"))
}

gradle.projectsEvaluated {
    verifyPublishVersion.configure {
        versions.set(publishable.map { "$it=${project(it).version}" })
    }
}

abstract class PrintPublishMatrixTask : DefaultTask() {
    @get:Input abstract val repository: Property<String>
    @get:Input abstract val lines: ListProperty<String>

    @TaskAction
    fun run() {
        val divider = "─".repeat(92)
        println()
        println("Publishing Matrix  (remote repository: ${repository.get()})")
        println(divider)
        println(String.format("%-28s %-36s %-12s", "Module", "Coordinates (group:artifact:version)", "Type"))
        println(divider)
        lines.get().forEach(::println)
        println(divider)
        println("Tip: If an artifactId looks wrong, check your Vanniktech coordinates() or module name.")
        println()
    }
}

val printMatrix = tasks.register<PrintPublishMatrixTask>("printPublishMatrix") {
    repository.set(githubPackagesUrl)
}

/* Build matrix lines after projects are configured */
gradle.projectsEvaluated {
    val matrixLines: List<String> = publishable.flatMap { path ->
        val p = project(path)
        val type = when {
            p.plugins.hasPlugin("com.android.library") -> "android-lib"
            p.plugins.hasPlugin("org.jetbrains.kotlin.jvm") -> "kotlin-jvm"
            p.plugins.hasPlugin("java-library") -> "java-lib"
            else -> "unknown"
        }
        val pubs = p.extensions.findByType(PublishingExtension::class.java)
            ?.publications
            ?.withType(MavenPublication::class.java)
            ?.toList()
            ?: emptyList()

        if (pubs.isNotEmpty()) {
            pubs.mapIndexed { idx, pub ->
                val coords = "${p.group}:${pub.artifactId}:${p.version}"
                val left = if (idx == 0) path.padEnd(28) else " ".repeat(28)
                String.format(
                    "%s %-36s %-12s  (publication=%s)",
                    left, coords.padEnd(36), type.padEnd(12), pub.name
                )
            }
        } else {
            val coords = "${p.group}:${p.name}:${p.version}"
            listOf(
                String.format(
                    "%-28s %-36s %-12s  (no publications found)",
                    path, coords, type
                )
            )
        }
    }

    printMatrix.configure {
        lines.set(matrixLines)
    }

    allprojects {
        tasks.matching { it.name.contains("publish", ignoreCase = true) && it.name.contains("GitHubPackages", ignoreCase = true) }
            .configureEach { finalizedBy(":printPublishMatrix") }

        tasks.matching { it.name.contains("publish", ignoreCase = true) && it.name.contains("MavenLocal", ignoreCase = true) }
            .configureEach { finalizedBy(":printPublishMatrix") }
    }
}

// Register tasks
tasks.register<ChangesetsStatusTask>("changesetsStatus") {
    changesetDir.set(layout.projectDirectory.dir(".changeset"))
}
tasks.register<ChangesetsVersionTask>("changesetsVersion") {
    rootDirProp.set(layout.projectDirectory)
    changesetDir.set(layout.projectDirectory.dir(".changeset"))
    generatedVersionDir.set(layout.projectDirectory.file("./packages/http/src/main/kotlin/io/zeroxkey/http/Version.kt"))
    modules.set(publishable)
}
tasks.register<ChangesetsChangelogTask>("changesetsChangelog") {
    rootDirProp.set(layout.projectDirectory)
    changesetDir.set(layout.projectDirectory.dir(".changeset"))
    generatedVersionDir.set(layout.projectDirectory.file("./packages/http/src/main/kotlin/io/zeroxkey/http/Version.kt"))
    modules.set(publishable)
}

// Codegen tasks
tasks.register("generate") {
    group = "codegen"
    description = "Generate all code from OpenAPI specs (types + http client)"
    dependsOn(
        ":packages:types:regenerateModels",
        ":packages:http:regenerateHttpClient"
    )
}