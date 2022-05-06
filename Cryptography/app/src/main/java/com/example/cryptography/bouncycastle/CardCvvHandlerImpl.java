package com.example.cryptography.bouncycastle;

import com.example.cryptography.bouncycastle.dto.CardCvvDataDTO;
import com.example.cryptography.bouncycastle.dto.CardCvvRequestDTO;
import com.example.cryptography.core.Logger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;


public class CardCvvHandlerImpl implements CardCvvHandler {
    private static final Logger LOGGER = Logger.getLogger(CardCvvHandlerImpl.class);
    public static final String ALGORITHM = "ECDH";
    public static final String CURVE = "secp256r1"; //"curve25519"
    public static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    public static final String CVV = "777";

    @Override
    public CardCvvDataDTO getCvv(String cardId, CardCvvRequestDTO cvvRequestDTO) throws Exception {

        LOGGER.d(String.format("ALGORITHM: %s", ALGORITHM));
        LOGGER.d(String.format("CURVE: %s", CURVE));
        LOGGER.d(String.format("CVV: %s", CVV));

        try {
            // Generate the DH keys for sender and receiver
            KeyPair platformKeyPair = generateKeyPair();
            String platformPrivateKey = getBase64String(getEncodedPrivateKey(platformKeyPair.getPrivate()));
            String platformPublicKey = getBase64String(platformKeyPair.getPublic().getEncoded()); // getBase64String(getEncodedPublicKey(platformKeyPair.getPublic()));

            LOGGER.d(String.format("PRIVATE KEY: %s", platformPrivateKey));
            LOGGER.d(String.format("PUBLIC KEY: %s", platformPublicKey));

            // Generate random salt
            String salt = generateRandomSalt();
            LOGGER.d(String.format("SALT: %s", salt));

            //Encrypt cvv
            String encryptedCvv = encrypt(salt, platformPrivateKey, cvvRequestDTO.getDevicePubicKey(), CVV);

            return CardCvvDataDTO.builder()
                    .encryptedCvv(encryptedCvv)
                    .platformSalt(salt)
                    .platformPublicKey(platformPublicKey)
                    .build();
        } catch (Exception ex) {
            LOGGER.e(String.format("Card cvv get exception: %s", ex.getLocalizedMessage()));
            throw ex;
        }
    }

    private String encrypt(String salt, String platformPrivateKey, String devicePublicKey, String stringToEncrypt) throws Exception {

        // Generating shared secret
        String sharedKey = doECDH(getBytesForBase64String(platformPrivateKey), getBytesForBase64String(devicePublicKey));
        LOGGER.d(String.format("Shared key: %s", sharedKey));

        // Generating iv and HKDF-AES key
        byte[] saltBytes = getBytesForBase64String(salt);
        byte[] iv = Arrays.copyOfRange(saltBytes, saltBytes.length - 12, saltBytes.length);
        byte[] aesKey = generateAesKey(saltBytes, sharedKey);
        LOGGER.d(String.format("HKDF AES key:  %s", getBase64String(aesKey)));

        // Perform Encryption
        String encryptedData = "";
        try {
            byte[] stringBytes = stringToEncrypt.getBytes();

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters =
                    new AEADParameters(new KeyParameter(aesKey), 128, iv, null);

            cipher.init(true, parameters);
            byte[] plainBytes = new byte[cipher.getOutputSize(stringBytes.length)];
            int retLen = cipher.processBytes
                    (stringBytes, 0, stringBytes.length, plainBytes, 0);
            cipher.doFinal(plainBytes, retLen);

            encryptedData = getBase64String(plainBytes);
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
        LOGGER.d(String.format("EncryptedData:  %s", encryptedData));
        return encryptedData;
    }

    // Method for generating HKDF AES key
    private static byte[] generateAesKey(byte[] xorOfRandoms, String sharedKey) {
        byte[] salt = Arrays.copyOfRange(xorOfRandoms, 0, 20);
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters hkdfParameters = new HKDFParameters(getBytesForBase64String(sharedKey), salt, null);
        hkdfBytesGenerator.init(hkdfParameters);
        byte[] aesKey = new byte[32];
        hkdfBytesGenerator.generateBytes(aesKey, 0, 32);
        return aesKey;
    }

    // Method for generating shared secret
    private static String doECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte[] secret = ka.generateSecret();
        return getBase64String(secret);
    }

    private static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        X9ECParameters ecP = CustomNamedCurves.getByName(CURVE);
        ECParameterSpec params = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        return kf.generatePrivate(privateKeySpec);
    }

    private static PublicKey loadPublicKey(byte[] data) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters ecP = CustomNamedCurves.getByName(CURVE);
        ECParameterSpec ecNamedCurveParameterSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());

        return KeyFactory.getInstance(ALGORITHM, PROVIDER)
                .generatePublic(new ECPublicKeySpec(ecNamedCurveParameterSpec.getCurve().decodePoint(data),
                        ecNamedCurveParameterSpec));
    }

    // Method for generating DH Keys
    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        X9ECParameters ecParameters = CustomNamedCurves.getByName(CURVE);
        ECParameterSpec ecSpec = new ECParameterSpec(ecParameters.getCurve(), ecParameters.getG(),
                ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed());

        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static String getBase64String(byte[] value) {
        return new String(org.bouncycastle.util.encoders.Base64.encode(value));
    }

    public static byte[] getBytesForBase64String(String value) {
        return org.bouncycastle.util.encoders.Base64.decode(value);
    }

    public byte[] getEncodedPrivateKey(PrivateKey key) {
        ECPrivateKey ecKey = (ECPrivateKey) key;
        return ecKey.getD().toByteArray();
    }

    public static byte[] getEncodedPublicKey(PublicKey key) {
        ECPublicKey ecKey = (ECPublicKey) key;
        return ecKey.getQ().getEncoded(true);
    }

    // Method for generating random string
    public static String generateRandomSalt() {
        byte[] salt = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return getBase64String(salt);
    }
}
