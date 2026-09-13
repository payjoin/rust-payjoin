plugins {
    // KGP's Gradle compatibility matrix must cover the wrapper version pinned in
    // gradle/wrapper/gradle-wrapper.properties (currently 9.1.0). 2.1.20 only tests
    // against Gradle up to 8.12.1; 2.3.20+ is the first stable KGP line whose matrix
    // extends to 9.1.0 (tested up to 9.3.0).
    kotlin("jvm") version "2.3.21"
}

repositories {
    mavenCentral()
}

dependencies {
    api("net.java.dev.jna:jna:5.17.0")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

tasks.test {
    useJUnitPlatform()
    val libDir = layout.projectDirectory.dir("lib").asFile
    val os = System.getProperty("os.name").lowercase()
    val nativeName = when {
        os.contains("mac") || os.contains("darwin") -> "libpayjoin_ffi.dylib"
        os.contains("win") -> "payjoin_ffi.dll"
        else -> "libpayjoin_ffi.so"
    }
    val native = libDir.resolve(nativeName).takeIf { it.exists() }
    if (native != null) {
        inputs.file(native)
        systemProperty("uniffi.component.payjoin.libraryOverride", native.absolutePath)
    }
    systemProperty("jna.library.path", libDir.absolutePath)
}
