# HSIP Keyboard ProGuard Rules

# Keep native methods (JNI)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep HSIPEngine native methods
-keep class io.hsip.keyboard.crypto.HSIPEngine {
    native <methods>;
}

# Keep Jetpack Compose
-dontwarn androidx.compose.**
-keep class androidx.compose.** { *; }

# Keep Kotlin metadata
-keep class kotlin.Metadata { *; }

# Keep data classes used for serialization
-keepclassmembers class io.hsip.keyboard.crypto.Contact {
    *;
}
-keepclassmembers class io.hsip.keyboard.crypto.DecryptResult {
    *;
}

# Suppress warnings for optional dependencies
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
