// Modified by 0xkey
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "io.zeroxkey.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.zeroxkey.demo"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        android.buildFeatures.buildConfig = true

        // Root local.properties first, then this module's; module values win. Blank values fall
        // back to the SDK defaults. See local.properties.example.
        val props = Properties().apply {
            listOf(
                rootProject.layout.projectDirectory.file("local.properties").asFile,
                project.layout.projectDirectory.file("local.properties").asFile,
            ).filter { it.exists() }.forEach { file -> file.inputStream().use { load(it) } }
        }
        fun prop(key: String) = props.getProperty(key)?.trim().orEmpty()

        buildConfigField("String", "ORGANIZATION_ID", "\"${prop("ZEROXKEY_ORGANIZATION_ID")}\"")
        buildConfigField("String", "AUTH_PROXY_CONFIG_ID", "\"${prop("ZEROXKEY_AUTH_PROXY_CONFIG_ID")}\"")
        buildConfigField("String", "RP_ID", "\"${prop("ZEROXKEY_RP_ID")}\"")
        buildConfigField("String", "API_BASE_URL", "\"${prop("ZEROXKEY_API_BASE_URL")}\"")
        buildConfigField("String", "AUTH_PROXY_BASE_URL", "\"${prop("ZEROXKEY_AUTH_PROXY_BASE_URL")}\"")
        buildConfigField("String", "APP_SCHEME", "\"${prop("ZEROXKEY_APP_SCHEME")}\"")

        // Optional Google OAuth client IDs. When blank, the SDK falls back to the
        // auth proxy's configured client ID. ZEROXKEY_GOOGLE_SECONDARY_CLIENT_IDS is a
        // comma-separated list of additional client IDs (e.g. web + mobile) that
        // should resolve to the same sub-organization.
        buildConfigField("String", "GOOGLE_CLIENT_ID", "\"${prop("ZEROXKEY_GOOGLE_CLIENT_ID")}\"")
        buildConfigField("String", "GOOGLE_SECONDARY_CLIENT_IDS", "\"${prop("ZEROXKEY_GOOGLE_SECONDARY_CLIENT_IDS")}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.navigation.ui.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.okhttp)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)

    implementation(project(":packages:http"))
    implementation(project(":packages:types"))
    implementation(project(":packages:stamper"))
    implementation(project(":packages:sdk-kotlin"))
    implementation(project(":packages:passkey"))
}