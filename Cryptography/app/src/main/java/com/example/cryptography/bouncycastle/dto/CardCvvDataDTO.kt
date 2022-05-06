package com.example.cryptography.bouncycastle.dto

class CardCvvDataDTO(
    val encryptedCvv: String,
    val platformSalt: String,
    val platformPublicKey: String
) {


    companion object {
        @JvmStatic
        fun builder() = Builder()
    }

    class Builder {

        private var encryptedCvv: String? = null
        private var platformSalt: String? = null
        private var platformPublicKey: String? = null

        fun encryptedCvv(encryptedCvv: String): Builder {
            this.encryptedCvv = encryptedCvv
            return this
        }

        fun platformSalt(salt: String): Builder {
            this.platformSalt = salt
            return this
        }

        fun platformPublicKey(platformPublicKey: String): Builder {
            this.platformPublicKey = platformPublicKey
            return this
        }

        fun build() = CardCvvDataDTO(
            encryptedCvv = encryptedCvv ?: "",
            platformSalt = platformSalt ?: "",
            platformPublicKey = platformPublicKey ?: ""
        )
    }
}