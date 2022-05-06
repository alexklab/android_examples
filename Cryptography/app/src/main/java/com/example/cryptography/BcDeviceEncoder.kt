package com.example.cryptography

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.cryptography.bouncycastle.dto.CardCvvDataDTO
import com.example.cryptography.core.Logger
import com.example.cryptography.core.decodeBase64
import com.example.cryptography.core.encodeBase64
import com.example.cryptography.core.encodeToString
import com.google.crypto.tink.aead.subtle.AesGcmSiv
import com.google.crypto.tink.subtle.Hkdf
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.io.ByteArrayOutputStream
import java.security.*
import javax.crypto.KeyAgreement


class BcDeviceEncoder {
    private val log = Logger.getLogger(BcDeviceEncoder::class.java)
    private val ALGORITHM = "ECDH"
    private val CURVE = "secp256r1"
    private val PROVIDER = BouncyCastleProvider.PROVIDER_NAME


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
        Security.addProvider(BouncyCastleProvider())
        val keyPairGenerator =
            KeyPairGenerator.getInstance(ALGORITHM, PROVIDER)
        val params = CustomNamedCurves.getByName(CURVE)
        val ecSpec = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)

        keyPairGenerator.initialize(ecSpec, SecureRandom())
        return keyPairGenerator.generateKeyPair()
            .also { keyPair = it }
    }

    fun getEncodedPublicKey(): String {
        val ecKey = generateKey().public as ECPublicKey
        return ecKey.q.getEncoded(true).encodeBase64()
    }

    fun decodeCvv(data: CardCvvDataDTO) {
        log.d("decodeCvv >>> $data")
        val keys = generateKey()
        val remotePublicKey = loadPublicKey(data.platformPublicKey)

        // Create a shared secret based on our private key and the other party's public key.
        val keyAgreement = getEcdhKeyAgreement(remotePublicKey, keys.private)
        val sharedKey = keyAgreement.generateSecret().encodeBase64()


        // Generating iv and HKDF-AES key
        val saltBytes = data.platformSalt.decodeBase64()
        val aesKey: ByteArray = generateAesKey(saltBytes, sharedKey)
        val iv: ByteArray = saltBytes.copyOfRange(saltBytes.size - 12, saltBytes.size)

        // Perform Decryption
        val encryptedBytes: ByteArray = data.encryptedCvv.decodeBase64()
        val cipher = GCMBlockCipher(AESEngine())
        val parameters = AEADParameters(KeyParameter(aesKey), 128, iv, null)
        cipher.init(false, parameters)
        val plainBytes = ByteArray(cipher.getOutputSize(encryptedBytes.size))
        val retLen =
            cipher.processBytes(encryptedBytes, 0, encryptedBytes.size, plainBytes, 0)
        cipher.doFinal(plainBytes, retLen)
        val decryptedData = String(plainBytes)

        log.d("decodeCvv <<< $decryptedData")
    }

    // Method for generating HKDF AES key
    private fun generateAesKey(salt: ByteArray, ikm: String): ByteArray {
        val hkdfBytesGenerator = HKDFBytesGenerator(SHA256Digest())
        val hkdfParams = HKDFParameters(ikm.decodeBase64(), salt.copyOfRange(0, 20), null)
        hkdfBytesGenerator.init(hkdfParams)
        val aesKey = ByteArray(32)
        hkdfBytesGenerator.generateBytes(aesKey, 0, 32)
        return aesKey
    }

    private fun getEcdhKeyAgreement(publicKey: PublicKey, privateKey: PrivateKey): KeyAgreement {
        val keyAgreement: KeyAgreement = KeyAgreement.getInstance(ALGORITHM, PROVIDER)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement
    }

    private fun loadPublicKey(key: String): PublicKey {

        Security.addProvider(BouncyCastleProvider())
        val params = CustomNamedCurves.getByName(CURVE)
        val spec = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)

        val publicKeySpec = ECPublicKeySpec(spec.curve.decodePoint(key.decodeBase64()), spec)

        return KeyFactory.getInstance(ALGORITHM, PROVIDER)
            .generatePublic(publicKeySpec)
    }

    private fun generateRandomSalt(): ByteArray {
        val salt = ByteArray(32)
        val random = SecureRandom()
        random.nextBytes(salt)
        return salt
    }
}



