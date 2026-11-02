plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.mozilla.rust-android-gradle.rust-android")
}

group = "org.irpush"
version = "0.1"

android {
    namespace = "org.irpush"
    compileSdk = 35
    ndkVersion = "26.3.11579264"
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

cargo {
    module = "../.."
    libname = "irpush"
    targets = listOf("arm64", "x86_64")
    profile = "release"
    features { defaultAnd(arrayOf("jni")) }
    extraCargoBuildArguments = listOf("--lib", "--locked")
}

tasks.matching { it.name.matches(Regex("merge[A-Za-z]+JniLibFolders")) }.configureEach {
    dependsOn("cargoBuild")
}
