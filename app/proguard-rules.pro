# ==========================================================
# Global Attributes & Basics (通用设置)
# ==========================================================
# 保留泛型、注解、行号
-keepattributes Signature,RuntimeVisibleAnnotations,AnnotationDefault,LineNumberTable,SourceFile,*Annotation*

# 保持所有 Native 方法
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保持 Parcelable 实现
-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator *;
}

# 保持枚举类的标准方法
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ==========================================================
# App Specific (项目特定)
# ==========================================================
-keep class moe.ouom.wekit.** { *; }

# ==========================================================
# Xposed & LSPosed
# ==========================================================

-adaptresourcefilecontents META-INF/xposed/java_init.list
-keep,allowobfuscation,allowoptimization public class * extends io.github.libxposed.api.XposedModule {
    public <init>(...);
    public void onPackageLoaded(...);
    public void onSystemServerLoaded(...);
}

-keep,allowoptimization,allowobfuscation @io.github.libxposed.api.annotations.* class * {
    @io.github.libxposed.api.annotations.BeforeInvocation <methods>;
    @io.github.libxposed.api.annotations.AfterInvocation <methods>;
}

# 忽略相关警告
-dontwarn de.robv.android.xposed.**
-dontwarn io.github.libxposed.api.**

# ==========================================================
# Jetpack Compose
# ==========================================================
-keepclassmembers class * {
    @androidx.compose.runtime.Composable <methods>;
}

# 保持 R 文件字段（有时在混淆资源ID时需要）
-keepclassmembers class **.R$* {
    public static <fields>;
}

# ==========================================================
# Material Design & AndroidX
# ==========================================================
-keep class com.google.android.material.internal.** { *; }
-keep public class com.google.android.material.internal.CheckableImageButton { *; }
-dontwarn com.google.android.material.**
-dontwarn androidx.**

# ==========================================================
# Serialization (Gson & Kotlinx)
# ==========================================================
# Gson
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class com.google.gson.Gson { *; }
-keepclassmembers,allowobfuscation class * {
  @com.google.gson.annotations.SerializedName <fields>;
}

# Kotlinx Serialization
-keep class kotlinx.serialization.** { *; }
-keepclassmembers class ** {
    @kotlinx.serialization.Serializable <methods>;
}
-if @kotlinx.serialization.Serializable class **
-keepclassmembers class <1> {
    static <1>$Companion Companion;
}
-if @kotlinx.serialization.Serializable class ** {
    static **$* *;
}
-keepclassmembers class <2>$<3> {
    kotlinx.serialization.KSerializer serializer(...);
}
-if @kotlinx.serialization.Serializable class ** {
    public static ** INSTANCE;
}
-keepclassmembers class <1> {
    public static <1> INSTANCE;
    kotlinx.serialization.KSerializer serializer(...);
}

# Protobuf
-keep class com.google.protobuf.** { *; }
-dontwarn com.google.protobuf.**

# ==========================================================
# Network
# ==========================================================
-keepattributes *Annotation*
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

# ==========================================================
# Third Party Libs
# ==========================================================
-keep class com.android.dx.** { *; }
-keep class net.bytebuddy.** { *; }
-dontwarn com.sun.jna.**

# ==========================================================
# Side Effects & Optimizations
# ==========================================================
# 移除 Kotlin Intrinsics 检查
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
    public static void check*(...);
    public static void throw*(...);
}

# 移除 Objects.requireNonNull
-assumenosideeffects class java.util.Objects {
    public static ** requireNonNull(...);
}

# 忽略 ByteBuddy 和 Mocking 相关的类
-dontwarn net.bytebuddy.**
-dontwarn java.lang.instrument.**
-dontwarn org.mockito.**

# 忽略 FindBugs/SpotBugs 注解
-dontwarn edu.umd.cs.findbugs.**
-dontwarn javax.annotation.**

# 忽略 KotlinPoet 和 Java Model 类
-dontwarn com.squareup.kotlinpoet.**
-dontwarn javax.lang.model.**

# 忽略 ServiceProvider 相关的 OSGi 注解
-dontwarn aQute.bnd.annotation.spi.**

# ==========================================================
# Build Behavior
# ==========================================================
-dontoptimize
-dontobfuscate