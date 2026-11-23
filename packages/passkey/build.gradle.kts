// Modified by 0xkey
plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    kotlin("plugin.serialization")
    id("com.vanniktech.maven.publish")
}

android {
    namespace = "io.zeroxkey.passkey"
    compileSdk = 36


    defaultConfig {
        minSdk = 28
        proguardFiles("proguard-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

group = "io.0xkey"
version = "0.1.0"

mavenPublishing {
    coordinates("io.0xkey", "passkey", version.toString())
}

dependencies {
    implementation(project(":packages:encoding"))
    implementation(project(":packages:types"))
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services.auth)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlinx.coroutines.test)
}

kotlin {
    jvmToolchain(11)
}