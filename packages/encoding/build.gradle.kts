// Modified by 0xkey
plugins {
    id("java-library")
    kotlin("jvm")
    id("com.vanniktech.maven.publish")
}

group = "io.0xkey"
version = "0.1.0"

mavenPublishing {
    coordinates("io.0xkey", "encoding", version.toString())
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
    implementation(kotlin("stdlib-jdk8"))
    implementation(libs.bitcoinj.core)
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.serialization.json)
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}