package com.example.cryptography.bouncycastle

import com.example.cryptography.core.*
import com.google.crypto.tink.signature.SignatureKeyTemplates
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.*
import javax.crypto.KeyAgreement

class BouncyCastleECDHEncoder : ECDHEncoder {

    private val log = Logger.getLogger(BouncyCastleECDHEncoder::class.java)

    private var localKeyPair: KeyPair? = null
    private var remotePublicKey: PublicKey? = null

    override fun init() {
        Security.addProvider(BouncyCastleProvider())
    }

    override fun getLocalPublicKey(): String {
        return encodePublicKey(getKeyPair().public)
    }

    override fun setRemotePublicKey(encodedKey: String) {
        remotePublicKey = decodePublicKey(encodedKey)
    }

    override fun exchangeECDHKeys(encodedr: ECDHEncoder) {
        setRemotePublicKey(encodedr.getLocalPublicKey())
        encodedr.setRemotePublicKey(getLocalPublicKey())
    }

    override fun encodeMessage(value: String): EncodedMessage {
        log.d(">> encodeMessage: '$value'")

        val publicKey = this.remotePublicKey
            ?: throw IllegalStateException("Remote public key not found. Keys exchange required")

        // Generate random salt
        val salt = generateSalt()
        log.d("Salt: $salt")

        val cipher = getHkdfAesChiper(
            publicKey = publicKey,
            privateKey = getKeyPair().private,
            saltBytes = salt.decodeBase64(),
            forEncryption = true
        )

        // Perform Encryption
        val stringBytes = value.toByteArray()
        val plainBytes = ByteArray(cipher.getOutputSize(stringBytes.size))
        val retLen = cipher.processBytes(stringBytes, 0, stringBytes.size, plainBytes, 0)
        cipher.doFinal(plainBytes, retLen)

        val encodedText = plainBytes.encodeBase64()
        log.d("encoded: $encodedText")

        return EncodedMessage(
            value = plainBytes.encodeBase64(),
            salt = salt
        )
    }

    override fun decodeMessage(message: EncodedMessage): String {
        log.d(">> decodeMessage: '${message.value}'")

        val publicKey = this.remotePublicKey
            ?: throw IllegalStateException("Remote public key not found. Keys exchange required")

        val cipher = getHkdfAesChiper(
            publicKey = publicKey,
            privateKey = getKeyPair().private,
            saltBytes = message.salt.decodeBase64(),
            forEncryption = false
        )

        // Perform Decryption
        val stringBytes = message.value.toByteArray()
        val plainBytes = ByteArray(cipher.getOutputSize(stringBytes.size))
        val retLen = cipher.processBytes(stringBytes, 0, stringBytes.size, plainBytes, 0)
        cipher.doFinal(plainBytes, retLen)
        val decodedText = String(plainBytes)
        log.d("decoded: $decodedText")

        return decodedText
    }


    private fun getHkdfAesChiper(
        publicKey: PublicKey,
        privateKey: PrivateKey,
        saltBytes: ByteArray,
        forEncryption: Boolean
    ): GCMBlockCipher {
        // Generating iv and HKDF-AES key
        val keyAgreement = KeyAgreement.getInstance(Algorithms.ECDH, PROVIDER)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        val sharedKey = keyAgreement.generateSecret().encodeBase64()
        log.d("SharedKey: $sharedKey")

        // generating HKDF AES key
        val hkdfParams =
            HKDFParameters(sharedKey.decodeBase64(), saltBytes.copyOfRange(0, 20), null)
        val hkdfBytesGenerator = HKDFBytesGenerator(SHA256Digest())
        hkdfBytesGenerator.init(hkdfParams)
        val aesKey = ByteArray(32)
        hkdfBytesGenerator.generateBytes(aesKey, 0, 32)
        log.d("HKDF AES key: ${aesKey.encodeBase64()}")

        val iv = saltBytes.copyOfRange(saltBytes.size - 12, saltBytes.size)

        val cipher = GCMBlockCipher(AESEngine())
        val parameters = AEADParameters(KeyParameter(aesKey), 128, iv, null)

        cipher.init(forEncryption, parameters)
        return cipher
    }

    private fun generateSalt(): String {
        val salt = ByteArray(32)
        val random = SecureRandom()
        random.nextBytes(salt)
        return salt.encodeBase64()
    }

    private fun decodePublicKey(encodedKey: String): PublicKey {
        val data = encodedKey.decodeBase64()
        val params = CustomNamedCurves.getByName(Curves.SECP_256_R1)
        val spec = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)

        val publicKeySpec = ECPublicKeySpec(spec.curve.decodePoint(data), spec)
        return KeyFactory.getInstance(Algorithms.ECDH, PROVIDER)
            .generatePublic(publicKeySpec)
    }

    private fun decodePrivateKey(encodedKey: String): PrivateKey {
        val data = encodedKey.decodeBase64()
        val params = CustomNamedCurves.getByName(Curves.SECP_256_R1)
        val parameterSpec = ECParameterSpec(
            params.curve, params.g, params.n, params.h, params.seed
        )
        val privateKeySpec = ECPrivateKeySpec(BigInteger(data), parameterSpec)
        return KeyFactory.getInstance(Algorithms.ECDH, PROVIDER)
            .generatePrivate(privateKeySpec)
    }

    private fun encodePublicKey(key: PublicKey): String {
        val ecKey = key as ECPublicKey
        return ecKey.q.getEncoded(true).encodeBase64()
    }

    private fun encodePrivateKey(key: PrivateKey): String {
        val ecKey = key as ECPrivateKey
        return ecKey.d.toByteArray().encodeBase64()
    }

    private fun getKeyPair(): KeyPair {
        return localKeyPair ?: generateKeysPair()
            .also { localKeyPair = it }
    }

    private fun generateKeysPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(Algorithms.ECDH, PROVIDER)
        val params = CustomNamedCurves.getByName(Curves.SECP_256_R1)
        val spec = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)
        keyPairGenerator.initialize(spec, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    private companion object {
        const val PROVIDER = BouncyCastleProvider.PROVIDER_NAME
    }

}