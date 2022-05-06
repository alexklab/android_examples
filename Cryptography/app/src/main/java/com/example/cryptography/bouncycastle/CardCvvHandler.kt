package com.example.cryptography.bouncycastle

import kotlin.Throws
import com.example.cryptography.bouncycastle.dto.CardCvvRequestDTO
import com.example.cryptography.bouncycastle.dto.CardCvvDataDTO
import java.lang.Exception

interface CardCvvHandler {
    @Throws(Exception::class)
    fun getCvv(cardId: String?, cvvRequestDTO: CardCvvRequestDTO): CardCvvDataDTO
}