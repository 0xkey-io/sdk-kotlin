// Modified by 0xkey
plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    kotlin("plugin.serialization")
    id("com.vanniktech.maven.publish")
}

android {
    namespace = "io.zeroxkey.http"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        proguardFiles("proguard-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    sourceSets["main"].java.srcDir("${layout.buildDirectory}/src/main/kotlin")
    sourceSets["main"].resources.srcDir("${layout.buildDirectory}/src/main/resources")
}

group = "io.0xkey"
version = "0.2.0"

mavenPublishing {
    coordinates("io.0xkey", "http", version.toString())
}

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.coroutines.core)
    api(project(":packages:stamper"))
    api(project(":packages:encoding"))
    api(project(":packages:types"))
    // tests
    testImplementation(kotlin("test"))
    testImplementation(libs.mockwebserver)
    testImplementation(libs.kotlinx.coroutines.test)
}

val clientCodegen = tasks.register<JavaExec>("client-codegen") {
    group = "client-codegen"
    description = "Generate single-file ZeroXKeyClient from Swagger"
    mainClass.set("io.zeroxkey.tools.ClientGeneratorKt")
    classpath = project(":packages:tools").configurations.named("runtimeClasspath").get() +
            project(":packages:tools").sourceSets["main"].output

    args(
        "--out", file("$projectDir/src/main/kotlin").absolutePath,
        "--pkg", "io.zeroxkey.http",
        "--models-pkg", "io.zeroxkey.types",
        "--client-class-name", "ZeroXKeyClient"
    )
}


tasks.register("regenerateHttpClient") {
    group = "clientCodegen"
    description = "Generate client"
    dependsOn(clientCodegen)
}

kotlin {
    jvmToolchain(11)
}