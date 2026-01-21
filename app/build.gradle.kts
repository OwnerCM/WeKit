import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.ByteArrayOutputStream
import java.io.RandomAccessFile
import java.lang.Long.toHexString
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.UUID
import java.util.zip.CRC32
import java.nio.file.Files
import java.nio.file.Paths

// 定义生成的头文件路径
val secretsHeaderDir = file("src/main/cpp/include")
val generatedHeaderFile = file("src/main/cpp/include/generated_checksums.h")
val MAGIC_PLACEHOLDER_INT = 0x1A2B3C4D
val MAGIC_BYTES = ByteBuffer.allocate(4)
    .order(ByteOrder.LITTLE_ENDIAN)
    .putInt(MAGIC_PLACEHOLDER_INT)
    .array()

plugins {
    id("build-logic.android.application")
    alias(libs.plugins.protobuf)
    alias(libs.plugins.serialization)
    alias(libs.plugins.android.application)
    id("com.google.devtools.ksp") version "2.3.4"
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}


android {
    namespace = "moe.ouom.wekit"
    compileSdk = 36

    val buildUUID = UUID.randomUUID()
    println(
        """
        __        __  _____   _  __  ___   _____ 
         \ \      / / | ____| | |/ / |_ _| |_   _|
          \ \ /\ / /  |  _|   | ' /   | |    | |  
           \ V  V /   | |___  | . \   | |    | |  
            \_/\_/    |_____| |_|\_\ |___|   |_|  
                                              
                        [WECHAT KIT] WeChat, Now with Superpowers
        """
    )

    println("buildUUID: $buildUUID")

    signingConfigs {
        create("release") {
            val storePath = project.findProperty("KEYSTORE_FILE") as String? ?: "wekit.jks"
            val resolved = file(storePath)
            if (resolved.exists()) {
                storeFile = resolved
                storePassword = project.findProperty("KEYSTORE_PASSWORD") as String? ?: ""
                keyAlias = project.findProperty("KEY_ALIAS") as String? ?: "key0"
                keyPassword = project.findProperty("KEY_PASSWORD") as String? ?: ""
            } else {
                println("🔐 Release keystore not found at '${resolved.path}'. Will fallback for PR/builds without secrets.")
            }
        }
    }


    defaultConfig {
        applicationId = "moe.ouom.wekit"
        buildConfigField("String", "BUILD_UUID", "\"${buildUUID}\"")
        buildConfigField("String", "TAG", "\"[WeKit-TAG]\"")
        buildConfigField("long", "BUILD_TIMESTAMP", "${System.currentTimeMillis()}L")
        ndk { abiFilters += "arm64-v8a" }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                cppFlags("-I${project.file("src/main/cpp/include")}")
                arguments += listOf("-DANDROID_STL=c++_shared")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        val releaseSigning = signingConfigs.getByName("release")
        val debugSigning = signingConfigs.getByName("debug")

        release {
            isMinifyEnabled = true
            isShrinkResources = true

            signingConfig = if (releaseSigning.storeFile?.exists() == true) {
                releaseSigning
            } else {
                println("✅ No release keystore detected; using DEBUG signing for release variant (PR-friendly).")
                debugSigning
            }

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.fromTarget("17"))
        }
    }

    packaging {
        resources.excludes += listOf(
            "kotlin/**",
            "**.bin",
            "kotlin-tooling-metadata.json"
        )
        resources {
            merges += "META-INF/xposed/*"
            excludes += "**"
        }
    }

    androidResources {
        additionalParameters += listOf(
            "--allow-reserved-package-id",
            "--package-id", "0x69"
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
        viewBinding = true
    }
}

fun String.capitalizeUS() = replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.US) else it.toString() }

val adbProvider = androidComponents.sdkComponents.adb
fun hasConnectedDevice(): Boolean {
    val adbPath = adbProvider.orNull?.asFile?.absolutePath ?: return false
    return runCatching {
        val proc = ProcessBuilder(adbPath, "devices").redirectErrorStream(true).start()
        proc.waitFor(5, TimeUnit.SECONDS)
        proc.inputStream.bufferedReader().readLines().any { it.trim().endsWith("\tdevice") }
    }.getOrElse { false }
}

val packageName = "com.tencent.mm"
val killWeChat = tasks.register("kill-wechat") {
    group = "wekit"
    description = "Force-stop WeChat on a connected device; skips gracefully if none."
    onlyIf { hasConnectedDevice() }
    doLast {
        val adbFile = adbProvider.orNull?.asFile ?: return@doLast
        for (i in 1..10) {
            project.exec {
                commandLine(adbFile, "shell", "am", "force-stop", packageName)
                isIgnoreExitValue = true
                standardOutput = ByteArrayOutputStream(); errorOutput = ByteArrayOutputStream()
            }
        }

        logger.lifecycle("✅  kill-wechat executed.")
    }
}

androidComponents.onVariants { variant ->
    if (!variant.debuggable) return@onVariants

    val vCap = variant.name.capitalizeUS()
    val installTaskName = "install${vCap}"

    val installAndRestart = tasks.register("install${vCap}AndRestartWeChat") {
        group = "wekit"
        dependsOn(installTaskName)
        finalizedBy(killWeChat)
        onlyIf { hasConnectedDevice() }
    }

    afterEvaluate { tasks.findByName("assemble${vCap}")?.finalizedBy(installAndRestart) }
}

afterEvaluate {
    tasks.matching { it.name.startsWith("install") }.configureEach { onlyIf { hasConnectedDevice() } }
    if (!hasConnectedDevice()) logger.lifecycle("⚠️  No device detected — all install tasks skipped")
}

android.applicationVariants.all {
    outputs.all {
        if (this is com.android.build.gradle.internal.api.ApkVariantOutputImpl) {
            val config = project.android.defaultConfig
            val versionName = config.versionName
            this.outputFileName = "WeKit-RELEASE-${versionName}.apk"
        }
    }
}

fun getDexIndex(name: String): Int {
    if (name == "classes.dex") return 1
    val number = name.substringAfter("classes").substringBefore(".dex")
    return if (number.isEmpty()) 1 else number.toInt()
}

tasks.register("generateDexChecksum") {
    group = "wekit"
    description = "Calculates CRC32 of ALL classes*.dex files and updates generated_checksums.h"
    outputs.file(generatedHeaderFile)

    doLast {
        // 获取 R8/混淆后的输出目录
        val dexDir = layout.buildDirectory.dir("intermediates/dex/release/minifyReleaseWithR8").get().asFile

        // 查找所有 classes*.dex 文件
        val dexFiles = dexDir.walk()
            .filter { it.isFile && it.name.matches(Regex("classes\\d*\\.dex")) }
            .toList()

        if (dexFiles.isEmpty()) {
            println("⚠️ [WeKit] No dex files found in ${dexDir.absolutePath}. Writing placeholders.")
            if (!secretsHeaderDir.exists()) secretsHeaderDir.mkdirs()
            generatedHeaderFile.writeText("""
                #pragma once
                static const int EXPECTED_DEX_COUNT = 0;
                static const uint32_t EXPECTED_DEX_CRCS[] = {};
            """.trimIndent())
            return@doLast
        }

        val sortedDexFiles = dexFiles.sortedWith(Comparator { f1, f2 ->
            val n1 = getDexIndex(f1.name)
            val n2 = getDexIndex(f2.name)
            n1.compareTo(n2)
        })

        val crcList = mutableListOf<String>()
        var totalSize: Long = 0

        println("🔒 [WeKit] Found ${sortedDexFiles.size} DEX files. Calculating Checksums...")

        sortedDexFiles.forEach { file ->
            val crc = CRC32()
            crc.update(file.readBytes())
            val hexCrc = "0x${toHexString(crc.value).uppercase()}"
            crcList.add(hexCrc)
            totalSize += file.length()
            println("   -> ${file.name}: $hexCrc (Size: ${file.length()})")
        }

        val cppArrayContent = crcList.joinToString(", ")

        if (!secretsHeaderDir.exists()) secretsHeaderDir.mkdirs()

        generatedHeaderFile.writeText("""
            // AUTOMATICALLY GENERATED BY GRADLE
            // Generated at: ${System.currentTimeMillis()}
            
            #pragma once
            #include <vector>
            #include <cstdint>
            
            static const int EXPECTED_DEX_COUNT = ${sortedDexFiles.size};
            static const uint32_t EXPECTED_DEX_CRCS[] = { $cppArrayContent };
        """.trimIndent())
    }
}

tasks.register("patchSoSize") {
    group = "wekit"
    description = "Injects the real SO file size into the binary by replacing the placeholder."

    doLast {
        val buildDir = layout.buildDirectory.get().asFile
        val libDir = buildDir.resolve("intermediates/stripped_native_libs/release/out/lib")

        if (!libDir.exists()) {
            println("⚠️ [WeKit-Patch] Native lib dir not found. Build might have failed or path changed.")
            return@doLast
        }

        libDir.walk().filter { it.isFile && it.name == "libwekit.so" }.forEach { soFile ->
            val content = soFile.readBytes()
            val fileSize = soFile.length().toInt()

            var patchOffset = -1
            for (i in 0 until content.size - 4) {
                if (content[i] == MAGIC_BYTES[0] &&
                    content[i + 1] == MAGIC_BYTES[1] &&
                    content[i + 2] == MAGIC_BYTES[2] &&
                    content[i + 3] == MAGIC_BYTES[3]) {
                    patchOffset = i
                    break
                }
            }

            if (patchOffset != -1) {
                println("💉 [WeKit-Patch] Patching ${soFile.absolutePath}")
                println("   -> Found placeholder at offset: $patchOffset")
                println("   -> Injecting size: $fileSize bytes")

                val sizeBytes = ByteBuffer.allocate(4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(fileSize)
                    .array()

                RandomAccessFile(soFile, "rw").use { raf ->
                    raf.seek(patchOffset.toLong())
                    raf.write(sizeBytes)
                }
            } else {
                println("❌ [WeKit-Patch] Placeholder NOT found in ${soFile.absolutePath}. Optimizer might have killed it?")
            }
        }
    }
}

afterEvaluate {
    android.applicationVariants.forEach { variant ->
        if (variant.buildType.name.equals("release", ignoreCase = true)) {
            val variantName = variant.name.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
            println("⚙️ [WeKit] Hooking Release Build for: $variantName")

            val r8Task = tasks.findByName("minify${variantName}WithR8")
            val checksumTask = tasks.findByName("generateDexChecksum")
            val stripTask = tasks.findByName("strip${variantName}DebugSymbols")
            val packageTask = tasks.findByName("package${variantName}")

            if (r8Task != null && checksumTask != null) {
                checksumTask.dependsOn(r8Task)
                tasks.configureEach {
                    val taskName = this.name
                    if (taskName.startsWith("buildCMake") && taskName.contains("Rel")) {
                        println("   🔒 Locking task '$taskName' to wait for Dex Checksum")
                        this.dependsOn(checksumTask)
                    }
                    if (taskName.startsWith("configureCMake") && taskName.contains("Rel")) {
                        this.dependsOn(checksumTask)
                    }
                }
            }

            if (stripTask != null && packageTask != null) {
                val patchTaskName = "patchSoSize${variantName}"

                // 防止任务重复注册报错
                if (tasks.findByName(patchTaskName) == null) {
                    val patchTask = tasks.register(patchTaskName) {
                        group = "wekit"
                        description = "Injects SO size for $variantName"

                        dependsOn(stripTask)

                        doLast {
                            println("💉 [WeKit-Patch] Starting patch process...")

                            // 动态获取 strip 任务的输出目录
                            val searchDirs = stripTask.outputs.files.files.filter { it.exists() && it.isDirectory }

                            if (searchDirs.isEmpty()) {
                                println("❌ [WeKit-Patch] No output directories found for strip task!")
                                return@doLast
                            }

                            var patchedCount = 0
                            searchDirs.forEach { dir ->
                                dir.walk().filter { it.isFile && it.name == "libwekit.so" }.forEach { soFile ->
                                    val fileSize = soFile.length().toInt()
                                    val content = soFile.readBytes()

                                    var patchOffset = -1
                                    for (i in 0 until content.size - 4) {
                                        if (content[i] == MAGIC_BYTES[0] &&
                                            content[i + 1] == MAGIC_BYTES[1] &&
                                            content[i + 2] == MAGIC_BYTES[2] &&
                                            content[i + 3] == MAGIC_BYTES[3]) {
                                            patchOffset = i
                                            break
                                        }
                                    }

                                    if (patchOffset != -1) {
                                        println("   ✅ Patching: ${soFile.absolutePath}")
                                        println("      Offset: $patchOffset, Size: $fileSize")
                                        val sizeBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(fileSize).array()
                                        RandomAccessFile(soFile, "rw").use { raf ->
                                            raf.seek(patchOffset.toLong())
                                            raf.write(sizeBytes)
                                        }
                                        patchedCount++
                                    }
                                }
                            }

                            if (patchedCount == 0) {
                                println("❌ [WeKit-Patch] Failed! No SO files were patched.")
                            }
                        }
                    }
                    packageTask.dependsOn(patchTask)
                }
            }
        }
    }
}


kotlin {
    sourceSets.configureEach { kotlin.srcDir("$buildDir/generated/ksp/$name/kotlin/") }
    sourceSets.main { kotlin.srcDir(File(rootDir, "libs/util/ezxhelper/src/main/java")) }
}

protobuf {
    protoc { artifact = libs.google.protobuf.protoc.get().toString() }
    generateProtoTasks { all().forEach { it.builtins { create("java") { option("lite") } } } }
}

configurations.configureEach { exclude(group = "androidx.appcompat", module = "appcompat") }

dependencies {
    implementation(libs.core.ktx)

    implementation(libs.appcompat)

    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout) { exclude("androidx.appcompat", "appcompat") }

    implementation(platform(libs.compose.bom))

    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material.icons.extended)

    implementation(libs.kotlinx.io.jvm)
    implementation(libs.dexkit)
    implementation(libs.hiddenapibypass)
    implementation(libs.gson)

    implementation(ktor("serialization", "kotlinx-json"))
    implementation(grpc("protobuf", "1.62.2"))

    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.mmkv)
    implementation(projects.libs.common.libxposed.service)

    compileOnly(libs.xposed)
    compileOnly(projects.libs.common.libxposed.api)

    implementation(libs.dexlib2)
    implementation(libs.google.guava)
    implementation(libs.google.protobuf.java)
    implementation(libs.kotlinx.serialization.protobuf)

    implementation(libs.sealedEnum.runtime)
    ksp(libs.sealedEnum.ksp)
    implementation(projects.libs.common.annotationScanner)
    ksp(projects.libs.common.annotationScanner)

    implementation(libs.material.preference)
    implementation(libs.dev.appcompat)

    implementation(libs.recyclerview)

    implementation(libs.material.dialogs.core)
    implementation(libs.material.dialogs.input)
    implementation(libs.preference)
    implementation(libs.fastjson2)

    // 因为放弃了资源注入，此库不再使用
//    implementation(projects.libs.ui.xView)

    implementation(libs.glide)
    implementation(libs.byte.buddy)
    implementation(libs.dalvik.dx)
    implementation(libs.okhttp3.okhttp)
    implementation(libs.markdown.core)
    implementation(libs.blurview)

    implementation(libs.hutool.core)
    implementation(libs.nanohttpd)

    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)

    implementation(libs.jackson.databind)
    implementation(libs.jackson.core)
    implementation(libs.stax.api)
    implementation(libs.woodstox.core)
}
