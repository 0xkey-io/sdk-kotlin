// Modified by 0xkey
plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    kotlin("plugin.serialization")
    id("com.vanniktech.maven.publish")
}

android {
    namespace = "io.zeroxkey.stamper"
    compileSdk = 36


    defaultConfig {
        minSdk = 28
        proguardFiles("proguard-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

group = "io.0xkey"
version = "0.1.0"

mavenPublishing {
    coordinates("io.0xkey", "stamper", version.toString())
}

dependencies {
    implementation(project(":packages:encoding"))
    implementation(project(":packages:passkey"))
    implementation(project(":packages:crypto"))
    testImplementation(kotlin("test"))
    implementation(libs.bcprov.jdk15to18)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.bcprov.jdk15to18)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.test.runner)

}

kotlin {
    jvmToolchain(11)
}

tasks.withType<Test>().configureEach {
    providers.gradleProperty("vectorOut").orNull?.let { systemProperty("zeroxkey.vectorOut", it) }
    providers.gradleProperty("vectorFixtures").orNull?.let { systemProperty("zeroxkey.vectorFixtures", it) }
}
