// Modified by 0xkey
plugins {
    id("java-library")
    kotlin("jvm")
    kotlin("plugin.serialization")
}

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.core)
    testImplementation(kotlin("test"))
}

group = "io.0xkey"
version = "0.2.0"

mavenPublishing {
    coordinates("io.0xkey", "types", version.toString())
}

val typesCodegen = tasks.register<JavaExec>("types-codegen") {
    group = "types-codegen"
    description = "Generate single-file 0xkey API Models from Swagger"
    mainClass.set("io.zeroxkey.tools.TypesGeneratorKt")
    classpath = project(":packages:tools").configurations.named("runtimeClasspath").get() +
            project(":packages:tools").sourceSets["main"].output

    args(
        "--out", file("$projectDir/src/main/kotlin").absolutePath,
        "--test-out", file("$projectDir/src/test/kotlin").absolutePath,
        "--pkg", "io.zeroxkey.types",
        "--types-file-name", "Models"
    )
}

tasks.register("regenerateModels") {
    group = "typesCodegen"
    description = "Generate models"
    dependsOn(typesCodegen)
}

kotlin {
    jvmToolchain(11)
}
