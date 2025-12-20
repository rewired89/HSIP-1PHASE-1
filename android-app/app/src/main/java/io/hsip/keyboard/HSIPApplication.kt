package io.hsip.keyboard

import android.app.Application
import io.hsip.keyboard.crypto.HSIPEngine

class HSIPApplication : Application() {

    companion object {
        lateinit var instance: HSIPApplication
            private set

        init {
            // TODO: Load native Rust library when implemented
            // System.loadLibrary("hsip_keyboard")
        }
    }

    lateinit var hsipEngine: HSIPEngine
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Initialize HSIP crypto engine
        hsipEngine = HSIPEngine(this)

        // Initialize identity if first launch
        if (!hsipEngine.hasIdentity()) {
            hsipEngine.generateIdentity()
        }
    }
}
