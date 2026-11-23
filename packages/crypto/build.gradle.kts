// Modified by 0xkey
plugins {
    id("java-library")
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("com.vanniktech.maven.publish")
}

group = "io.0xkey"
version = "0.1.0"

mavenPublishing {
    coordinates("io.0xkey", "crypto", version.toString())
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(project(":packages:encoding"))
    testImplementation(platform(libs.junit.bom))
    testRuntimeOnly(libs.junit.launcher)
    implementation(libs.bcprov.jdk15to18)
    implementation(libs.kotlinx.serialization.json)
}

kotlin {
    jvmToolchain(11)
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<Test>().configureEach {
    providers.gradleProperty("vectorOut").orNull?.let { systemProperty("zeroxkey.vectorOut", it) }
    providers.gradleProperty("vectorFixtures").orNull?.let { systemProperty("zeroxkey.vectorFixtures", it) }
}
