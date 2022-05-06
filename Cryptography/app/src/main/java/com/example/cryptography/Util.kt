package com.example.cryptography

import com.example.cryptography.bouncycastle.BouncyCastleECDHEncoder
import com.example.cryptography.bouncycastle.CardCvvHandlerImpl
import com.example.cryptography.bouncycastle.dto.CardCvvRequestDTO
import com.example.cryptography.core.Logger

object Util {
    private val log = Logger.getLogger(Util::class.java)

    fun testBcToBc() {
        try {
            val serverEncoder = BouncyCastleECDHEncoder()
            val clientEncoder = BouncyCastleECDHEncoder()

            serverEncoder.exchangeECDHKeys(clientEncoder)


            val encoded = serverEncoder.encodeMessage("Hello!")

            clientEncoder.decodeMessage(encoded)

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }


    fun test1() {
        try {
            val deviceEncoder = DeviceEncoder() // BcDeviceEncoder()
            val service = CardCvvHandlerImpl()


            // #1 Exchange keys, and get encoded data
            val cvv = "12334"
            val encodedData = service.getCvv(
                cvv, CardCvvRequestDTO(
                    devicePubicKey = deviceEncoder.getEncodedPublicKey()
                )
            )

            deviceEncoder.decodeCvv(encodedData)

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}

