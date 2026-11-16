plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

// Keep the complete AAR (including its certificate-revocation network policy)
// synchronized with the Rust dependency instead of extracting only classes.jar.
val rustlsCompanionVersion = providers.fileContents(rootProject.layout.projectDirectory.file("../Cargo.lock")).asText.map { lock ->
    val entry = lock.split("[[package]]").single { block ->
        block.lineSequence().any { it.trim() == "name = \"rustls-platform-verifier-android\"" }
    }
    entry.lineSequence().first { it.trimStart().startsWith("version = ") }
        .substringAfter('"').substringBefore('"')
}

android {
    namespace = "dev.nelszack.passwordmanager"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = "dev.nelszack.passwordmanager"
        minSdk = 28
        targetSdk = 36
        versionCode = 12
        versionName = "0.3.0"
        ndk { abiFilters += providers.gradleProperty("pmAbis").orElse("arm64-v8a,x86_64").get().split(',') }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    signingConfigs {
        create("privateRelease") {
            val keyPath = providers.environmentVariable("PM_ANDROID_KEYSTORE").orNull
            if (keyPath != null) {
                storeFile = file(keyPath)
                storePassword = providers.environmentVariable("PM_ANDROID_STORE_PASSWORD").orNull
                keyAlias = providers.environmentVariable("PM_ANDROID_KEY_ALIAS").orNull
                keyPassword = providers.environmentVariable("PM_ANDROID_KEY_PASSWORD").orNull
            }
        }
    }
    buildTypes {
        release { signingConfig = signingConfigs.getByName("privateRelease"); isDebuggable = false }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = false } }
}
dependencies {
    implementation("androidx.autofill:autofill:1.3.0")
    implementation("org.rustls:rustls-platform-verifier:${rustlsCompanionVersion.get()}")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.credentials:credentials:1.5.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

val verifyNativeLibraries by tasks.registering {
    doLast {
        for (abi in providers.gradleProperty("pmAbis").orElse("arm64-v8a,x86_64").get().split(',')) {
            check(file("src/main/jniLibs/$abi/libpm_mobile.so").isFile) { "Build Rust first: python3 scripts/build_android.py" }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyNativeLibraries) }
