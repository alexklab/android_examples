package com.example.cryptography

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.example.cryptography.bouncycastle.dto.CardCvvDataDTO
import com.example.cryptography.core.Logger
import com.example.cryptography.core.decodeBase64
import com.example.cryptography.core.encodeBase64
import com.example.cryptography.core.encodeToString
import com.google.crypto.tink.aead.subtle.AesGcmSiv
import com.google.crypto.tink.subtle.Hkdf
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.util.BigIntegers
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement


class DeviceEncoder {
    private val log = Logger.getLogger(DeviceEncoder::class.java)
    private val ALIAS = "ec_local_key_pair"


    /**
     * Generate a new EC key pair entry in the Android Keystore by
     * using the KeyPairGenerator API. The private key can only be
     * used for signing or verification and only with SHA-256 or
     * SHA-512 as the message digest.
     **/
    @RequiresApi(Build.VERSION_CODES.M)

    private var keyPair: KeyPair? = null

    fun generateKey(): KeyPair {
        keyPair?.let { return it }
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                        //   or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
                        or KeyProperties.PURPOSE_AGREE_KEY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .build()
        )

        return keyPairGenerator.generateKeyPair()
            .also { keyPair = it }
    }

    fun getEncodedPublicKey(): String {
        val key = generateKey().public as ECPublicKey
        log.d("$key")

        val w = key.w
        val x = BigIntegers.asUnsignedByteArray(w.affineX)
        val p0 = ByteArray(x.size + 1)
        p0[0] = if (w.affineY.testBit(0)) 0x03 else 0x02
        System.arraycopy(x, 0, p0, 1, x.size)
        return p0.encodeBase64()
    }

    fun decodeCvv(data: CardCvvDataDTO) {
        log.d("decodeCvv >>> $data")
        val keys = generateKey()
        val remotePublicKey = loadPublicKey(data.platformPublicKey)

        // Create a shared secret based on our private key and the other party's public key.
        val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        keyAgreement.init(keys.private)
        keyAgreement.doPhase(remotePublicKey, true)
        val sharedSecret = byteArrayOf() //keyAgreement.generateSecret()

        val info = ByteArrayOutputStream()
        info.write("ECDH secp256r1 AES-256-GCM-SIV\\0".toByteArray())
        info.write(keys.public.encoded)
        info.write(remotePublicKey.encoded)

        // This example uses the Tink library and the HKDF key derivation function.
        val salt = data.platformSalt.decodeBase64()
        val key = AesGcmSiv(
            Hkdf.computeHkdf(
                "HMACSHA256", sharedSecret, salt, info.toByteArray(), 32
            )
        )

        val associatedData = byteArrayOf()
        val decryptedCvv = key.encrypt(data.encryptedCvv.decodeBase64(), associatedData)


        log.d("decodeCvv <<< ${String(decryptedCvv)}")
    }

    private fun loadPublicKey(key: String): PublicKey {
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        val spec = X509EncodedKeySpec(key.decodeBase64())
        return keyFactory.generatePublic(spec)
    }

    fun encodeCvv(alias: String, cvv: String, remotePublicKey: String): CardCvvDataDTO {
        log.d("encodeCvv >>>")
        log.d(String.format("CVV: %s", cvv))
        val salt = generateRandomSalt()
        log.d(String.format("SALT: %s", salt.encodeBase64()))

        log.d(String.format("REMOTE PUBLIC KEY: %s", remotePublicKey))

        val localKeyPair = generateKey()

        val localPublicKey = localKeyPair.public.encodeToString()
        val localPrivateKey = localKeyPair.private.encodeToString()
        val remotePublicKeys = loadPublicKey(remotePublicKey)

        log.d(String.format("LOCAL  PUBLIC KEY: %s", localPublicKey))
        log.d(String.format("LOCAL  PRIVATE KEY: %s", localPrivateKey))

        // Create a shared secret based on our private key and the other party's public key.
        val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        keyAgreement.init(localKeyPair.private)
        keyAgreement.doPhase(remotePublicKeys, true)
        val sharedSecret = keyAgreement.generateSecret()

        // sharedSecret cannot safely be used as a key yet. We must run it through a key derivation
        // function with some other data: "salt" and "info". Salt is an optional random value,
        // omitted in this example. It's good practice to include both public keys and any other
        // key negotiation data in info. Here we use the public keys and a label that indicates
        // messages encrypted with this key are coming from the server.

        val info = ByteArrayOutputStream()
        info.write("ECDH secp256r1 AES-256-GCM-SIV\\0".toByteArray())
        info.write(localKeyPair.public.encoded)
        info.write(remotePublicKeys.encoded)

        // This example uses the Tink library and the HKDF key derivation function.
        val key = AesGcmSiv(
            Hkdf.computeHkdf(
                "HMACSHA256", sharedSecret, salt, info.toByteArray(), 32
            )
        )

        val associatedData = byteArrayOf()
        val encryptedCvv = key.encrypt(cvv.toByteArray(), associatedData)
        log.d("encodeCvv <<<")
        return CardCvvDataDTO(
            platformSalt = salt.encodeBase64(),
            encryptedCvv = encryptedCvv.encodeBase64(),
            platformPublicKey = localPublicKey ?: ""
        )
    }

    private fun generateRandomSalt(): ByteArray {
        val salt = ByteArray(32)
        val random = SecureRandom()
        random.nextBytes(salt)
        return salt
    }
}



