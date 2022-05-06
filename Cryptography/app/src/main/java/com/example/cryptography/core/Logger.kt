package com.example.cryptography.core

import android.util.Log

internal class Logger private constructor(
    private val tag: String
) {

    fun d(msg: String) = Log.d(tag, msg)

    fun e(msg: String) = Log.e(tag, msg)

    companion object {
        @JvmStatic
        fun getLogger(clazz: Class<*>): Logger {
            return Logger(clazz.simpleName)
        }
    }
}

