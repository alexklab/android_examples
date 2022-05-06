package com.example.cryptography.core

interface ECDHEncoder {

    fun init()

    fun encodeMessage(value: String): EncodedMessage

    fun decodeMessage(message: EncodedMessage): String

    fun setRemotePublicKey(encodedKey: String)

    fun getLocalPublicKey(): String

    fun exchangeECDHKeys(encodedr: ECDHEncoder)

}