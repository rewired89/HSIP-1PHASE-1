# HSIP Android Gradle Configuration Fix

## ✅ Issue Fixed

**Problem:** Gradle error when using `PREFER_SETTINGS` repository mode
```
Build was configured to prefer settings repositories over project repositories
but repository 'Google' was added by build file 'build.gradle'
```

## 🔧 Solution

### **Old Configuration (❌ Causes Error):**

```gradle
// build.gradle - OLD WAY
buildscript {
    repositories {
        google()        // ❌ NOT ALLOWED with PREFER_SETTINGS
        mavenCentral()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:8.1.4'
    }
}

allprojects {
    repositories {   // ❌ NOT ALLOWED with PREFER_SETTINGS
        google()
        mavenCentral()
    }
}
```

### **New Configuration (✅ Correct):**

**`android-app/build.gradle`:**
```gradle
// Top-level build file for HSIP Keyboard Android
plugins {
    id 'com.android.application' version '8.1.4' apply false
    id 'org.jetbrains.kotlin.android' version '1.9.20' apply false
}

// Keep these for reference in app/build.gradle
ext {
    kotlin_version = "1.9.20"
    compose_version = "1.5.4"
}

task clean(type: Delete) {
    delete rootProject.buildDir
}
```

**`android-app/settings.gradle`:**
```gradle
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "HSIP Keyboard"
include ':app'
```

**`android-app/app/build.gradle`:**
```gradle
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}

android {
    // ... rest of configuration
}
```

## 📚 Why This Works

### **Modern Gradle (7.0+) Approach:**

1. **`pluginManagement`** in `settings.gradle` → Defines where to get plugins
2. **`dependencyResolutionManagement`** in `settings.gradle` → Centralized repository configuration
3. **`plugins` DSL** in `build.gradle` → References plugins without needing repositories
4. **No `buildscript` or `allprojects`** → Repositories are centralized

### **Benefits:**

✅ **Single source of truth** - All repositories in one place
✅ **Better performance** - Gradle can cache and optimize better
✅ **Cleaner build files** - Less duplication
✅ **Future-proof** - Recommended approach for modern Gradle

## 🎯 Summary

When using `PREFER_SETTINGS` mode:
- ❌ **DON'T** put `repositories {}` in `build.gradle` buildscript
- ❌ **DON'T** put `repositories {}` in allprojects
- ✅ **DO** put plugin repositories in `pluginManagement` (settings.gradle)
- ✅ **DO** put dependency repositories in `dependencyResolutionManagement` (settings.gradle)
- ✅ **DO** use `plugins {}` DSL in build.gradle files

---

**Last Updated:** December 20, 2025
**Commit:** `618b0a3` - Fix Gradle build: convert buildscript to plugins DSL
