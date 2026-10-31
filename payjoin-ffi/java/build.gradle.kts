plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencies {
    // Generated bindings use Java's Foreign Function & Memory API (java.lang.foreign) directly -
    // no JNA, no Kotlin coroutines, no runtime dependency of any kind. See README.md.
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// README.md: java.lang.foreign (Project Panama) was finalized (no longer preview) in JDK 22
// (JEP 454), which is the floor the generator itself declares. `--release 22`, not
// `sourceCompatibility`/`targetCompatibility`: those two only set the bytecode/language level,
// they don't stop javac compiling against APIs added to the JDK *after* 22 when Gradle itself
// happens to run under a newer one (25, here) - `--release` additionally compiles against that
// older release's own API signature, so a build that only works because it's running under 25
// fails loudly instead of shipping something that breaks for a consumer on a real JDK 22.
//
// Trusts whatever JDK started Gradle (must be 22+) rather than a `toolchain{}` block, which
// requests an exact major version and requires network auto-provisioning (a foojay-resolver-style
// plugin, not added here) to find one you don't already have installed - same tradeoff the Kotlin
// bindings' build.gradle.kts already makes for its own JDK 21 floor.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(22)
}

val nativeLibraryOverride = layout.projectDirectory.dir("lib").asFile.let { libDir ->
    val os = System.getProperty("os.name").lowercase()
    val nativeName = when {
        os.contains("mac") || os.contains("darwin") -> "libpayjoin_ffi.dylib"
        os.contains("win") -> "payjoin_ffi.dll"
        else -> "libpayjoin_ffi.so"
    }
    libDir.resolve(nativeName).takeIf { it.exists() }
}

tasks.test {
    useJUnitPlatform()
    // The FFM API gates native calls behind the JDK's restricted-methods check (JEP 454) - see
    // "JDK/runtime requirements" in README.md. ALL-UNNAMED is correct here because tests run on
    // the classpath (unnamed module), not as a named JPMS module.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    if (nativeLibraryOverride != null) {
        inputs.file(nativeLibraryOverride)
        // Same "uniffi.component.<namespace>.libraryOverride" convention the generated
        // NamespaceLibrary.findLibraryName() reads - see scripts/generate_bindings.sh.
        systemProperty("uniffi.component.payjoin.libraryOverride", nativeLibraryOverride.absolutePath)
    }
}
