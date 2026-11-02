buildscript {
    repositories { google(); mavenCentral() }
    dependencies { classpath("org.mozilla.rust-android-gradle:plugin:0.9.6") }
}
plugins {
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
