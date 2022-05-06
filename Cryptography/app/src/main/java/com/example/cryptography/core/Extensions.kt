package com.example.cryptography.core

import android.util.Base64
import java.security.Key


fun Key.encodeToString(): String? {
    return encoded?.encodeBase64()
}


fun String.decodeBase64(): ByteArray {
    return Base64.decode(this, Base64.DEFAULT)
}


fun ByteArray.encodeBase64(): String {
    return Base64.encodeToString(this, Base64.DEFAULT)
}
