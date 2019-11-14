package app

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import java.security.Key
import java.security.KeyFactory
import java.security.Security
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


@SpringBootApplication
class EncryptorApplication: CommandLineRunner {

    init {
        Security.addProvider(BouncyCastleProvider());
    }

    override fun run(vararg args: String?) {
        val secretKey = dataKey()
        val b64 = Base64.getEncoder().encode(secretKey.encoded)
        println("secretKey: '${String(b64)}'.")

        val publicKey = publicKey(Base64.getDecoder().decode(encodedPublicKey))
        val encryptingCipher = encryptingCipher(publicKey)
        println("encryptingCipher.provider: '${encryptingCipher.provider}'.")
        println("encryptingCipher.algorithm: '${encryptingCipher.algorithm}'.")
        println("encryptingCipher.parameters: '${encryptingCipher.parameters}'.")

        val encrypted = encryptingCipher.doFinal(secretKey.encoded)
        val encodedAndEncrypted = Base64.getEncoder().encode(encrypted)
        println("encodedAndEncrypted: '${String(encodedAndEncrypted)}'.")

        println("===")
        val privateKey = privateKey(Base64.getDecoder().decode(encodedPrivateKey))
        val decryptingCipher = decryptingCipher(privateKey)
        println("decryptingCipher.provider: '${decryptingCipher.provider}'.")
        println("decryptingCipher.algorithm: '${decryptingCipher.algorithm}'.")
        println("decryptingCipher.parameters: '${decryptingCipher.parameters}'.")

        val decrypted = decryptingCipher.doFinal(encrypted)
        val decryptedAndEncoded = Base64.getEncoder().encode(decrypted)
        println("decryptedAndEncoded: '${String(decryptedAndEncoded)}'.")

    }

    private fun encryptingCipher(key: Key) =
            Cipher.getInstance(transformation).apply {
                init(Cipher.ENCRYPT_MODE, key, defaultSunJceParameterSpec())
            }

    private fun decryptingCipher(key: Key) =
            Cipher.getInstance(transformation, "BC").apply {
                init(Cipher.DECRYPT_MODE, key, defaultSunJceParameterSpec())  //, defaultSunJceParameterSpec()
            }

    fun defaultSunJceParameterSpec() =
            OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT);

    private fun dataKey() =
            KeyGenerator.getInstance("AES").apply {
                init(128)
            }.generateKey()

    fun publicKey(keyEncryptionKeyBytes: ByteArray): Key =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyEncryptionKeyBytes))

    fun privateKey(keyEncryptionKeyBytes: ByteArray): Key =
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyEncryptionKeyBytes))

    private val transformation = "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding"
    private val encodedPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2G1pbVWCVVCvId+NgBQsF2KasDySO1+b110ZHEWxbdaapL07HYPgaI1spP8J0DQd79ebVLle8ASMQKQAhpBCkAhPplYDcFgI46Nb6jgKUCj02240AJ9hXPfVdv/Bx6DXl+Q9yBeCwivp1TdypUcOyW5Jhe/UM+qgb0Sb4BEro60BFumGuDja7U7c5PoGOPvPYKXPhLqr9iVD+zIu4CnrWb57XITiV7+nu9v28G9O2RtaKllbirEbFqX7awSE6hH8YhAAMfO2Olho0skqaa2hmLtC++Hmrcew+QE++XDRbBe2Ij/lBSE0SkkBuRItjaUdNT1dOfxZRuSitcZj0LPUwIDAQAF"
    private val encodedPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/YbWltVYJVUK8h342AFCwXYpqwPJI7X5vXXRkcRbFt1pqkvTsdg+BojWyk/wnQNB3v15tUuV7wBIxApACGkEKQCE+mVgNwWAjjo1vqOApQKPTbbjQAn2Fc99V2/8HHoNeX5D3IF4LCK+nVN3KlRw7JbkmF79Qz6qBvRJvgESujrQEW6Ya4ONrtTtzk+gY4+89gpc+Euqv2JUP7Mi7gKetZvntchOJXv6e72/bwb07ZG1oqWVuKsRsWpftrBITqEfxiEAAx87Y6WGjSySppraGYu0L74eatx7D5AT75cNFsF7YiP+UFITRKSQG5Ei2NpR01PV05/FlG5KK1xmPQs9TAgMBAAUCggEACTY5uGu6zxUqwg+qLkeOSVq57zAPJjElSdYdXTwgoEmJIjnZOZAypkvu73Ny+I1DpqL/9rrIlp3wUOFfefSHJ3OlndbT3nPDajUYJNpeGOkR6K8zL8D7HoAMGaLZJJQdn0iOQCLl4gH1GgA56Gn+bDkpcuNGZoRWfl+0xibDMvUAM3197j07Wx0ub6iXOqiuK6r9qsk2S3x5cC2/BrHLX/Ej1/PhDdB5R4wizakPA+XJCCi61oEO/FxvMa4y0MYeUv1R+8+bC8bYr0qCZLBTEEhr/2tLKe2yqsQ1895l/TvCJRgTZsYOoEKd9yKJn1+IHVrT/mKliWaiyg++XwTCxQKBgQDP3g9LZoxNiI2BTKvJSJyH5UC3Vq20q/URtPN/WfDGgyXupijKraVYBbULP6pSU6js75TxP4dr37KAq2ZG6v+LDVuraZlC386nAv5ROMFhGNn5VXCSnMAwb/0WDItDk9I/DyjQvbQ37CIWn9SOfFh27/ljN4g2KIZwFYXXWDuMuwKBgQDrsmjvt84HTZGX5M4kkvoe1SqC53TWlqy9fHoiD/0/fcFJiBFMdeNZVeNdpNdfpHq+V4q/8kq9MaKQjkmGZWY4gbaH4bT4OaCxI1QNZxXu3yPW85HmgdzGpDYWSlD4IjvoJOEIg8Lx/PJF2ywGNXMU6HOS2KSMa05yR+6EwQMqSQKBgQCkP7i/bZADBLUaf13S/e4cDLDgbHCt7ezHGiZYBw6M1aqxPH9VjIRF9UTCR8fknv0GKkPTQJ90NUQ4MFikl0RzP5IOne0yonZU0kl0J6Cp4x3v3cDcVuh8vE9E/BiwL0Lb3mNc4tgXaHf1oQkGW0rvpfvIaFvtYGs6Qh61DgPopQKBgBgIgk7eaPdr0Nyz8o24BE9tWaoG/iQnOqtRR/Hvfbqz0mG+qmJDHjZ2FNgVZddwlZ1a5IyqGtKS4eBqUGXVe+gZmbgMqO//WGk2NzQl3VxADexWys/WcO5A+YsYLpbUs4pjhsz3Rt3A4YQ+C2ANNRE5eiG31Ph02wCaWMvnnyeFAoGAFa4DQIEFbbG82YEswSImJsmRdo4X36jnhXtDsF4xNSLMTrKIaJgEYtz/6DYN8nU2cuLwojSH8m49UKvo0LsLaYk5ytlGQOJ0ItDbnOrFjVrIBtH09FVUJoHIV4QVM2V+uY6YCYDsRXo+4kZKDUJr271qPzz+X9Gnabky9jpw248="
}

fun main(args: Array<String>) {
    runApplication<EncryptorApplication>(*args)
}

//fun bcOaepParameterSpec() =
//        OAEPParameterSpec("SHA-256", "MGF1",
//                MGF1ParameterSpec.SHA256,
//                PSource.PSpecified.DEFAULT);
//    private val preprodPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArxnH8BRcfmGdJa1Eguzf2DKr6UTcPsUOOBcjcVRzu6yZljuwYdiUURZdK/ThIb49SRj+GXZa1qZqezlGvObspV392nNOPA95+RtgECLMKmLoj5TlAyDyjnjLEWiG0cXFVfYcw+PPD05rPLB3Ehs5ulEuk3uJan/gOA1wF6scH9jC041ISBzQXQorCreyfHKssaGLznTkJx/5ynmgTdzAmycw1q9DJFe0Wgb9lNPyZfKT/dlAdAz3gfbG4/pe8A0MNPEh0QBiulE/svT4+oHNx5NnZX9b8EOTjeHyzQeWhNMaVG2VUiCN5iHLsQM2K5QHnrvQZWhltSg2fURYiH+FtQIDAQAB"
//val preprodKey = publicKey(Base64.getDecoder().decode(encodedPublicKey))
//val preprodCipher = encryptingCipher(preprodKey)
//println("preprodCipher.provider: '${preprodCipher.provider}'.")
//println("preprodCipher.algorithm: '${preprodCipher.algorithm}'.")
//println("preprodCipher.parameters: '${preprodCipher.parameters}'.")
//
//val preprodEncrypted = preprodCipher.doFinal(secretKey.encoded)
//val preprodEncodedAndEncrypted = Base64.getEncoder().encode(preprodEncrypted)
//println("preprodEncodedAndEncrypted: '${String(preprodEncodedAndEncrypted)}'.")
//
//println("===")
//
//        val preprodKey = publicKey(Base64.getDecoder().decode(encodedPublicKey))
//        val preprodCipher = encryptingCipher(preprodKey)
//        println("preprodCipher.provider: '${preprodCipher.provider}'.")
//        println("preprodCipher.algorithm: '${preprodCipher.algorithm}'.")
//        println("preprodCipher.parameters: '${preprodCipher.parameters}'.")
//
//        val preprodEncrypted = preprodCipher.doFinal(secretKey.encoded)
//        val preprodEncodedAndEncrypted = Base64.getEncoder().encode(preprodEncrypted)
//        println("preprodEncodedAndEncrypted: '${String(preprodEncodedAndEncrypted)}'.")
//
//        println("===")


//@Override
//public byte[] encryptedKey(Integer wrappingKeyHandle, Key dataKey)
//throws CryptoImplementationSupplierException, MasterKeystoreException {
//    try {
//        LOGGER.info("wrappingKeyHande: '{}'.", wrappingKeyHandle);
//        byte[] keyAttribute = Util.getKeyAttributes(wrappingKeyHandle);
//        CaviumRSAPublicKey publicKey = new CaviumRSAPublicKey(wrappingKeyHandle,  new CaviumKeyAttributes(keyAttribute));
//        LOGGER.info("Public key bytes: '{}'.", new String(Base64.getEncoder().encode(publicKey.getEncoded())));
//        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
//        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "Cavium");
//        cipher.init(Cipher.WRAP_MODE, publicKey, spec);
//        return Base64.getEncoder().encode(cipher.wrap(dataKey));
//    }
//    catch (NoSuchAlgorithmException | NoSuchProviderException |
//    NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
//        throw new CryptoImplementationSupplierException(e);
//    }
//    catch (CFM2Exception e) {
//        String message = "Failed to encrypt key, retry will be attempted unless max attempts reached";
//        LOGGER.warn(message);
//        throw new MasterKeystoreException(message, e);
//    }
//}
//
//@Override
//public String decryptedKey(Integer decryptionKeyHandle, String ciphertextDataKey)
//throws CryptoImplementationSupplierException, MasterKeystoreException {
//    try {
//        LOGGER.info("decryptionKeyHandle: '{}'.", decryptionKeyHandle);
//        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256",
//                "MGF1",
//                MGF1ParameterSpec.SHA256,
//                PSource.PSpecified.DEFAULT);
//        byte[] privateKeyAttribute = Util.getKeyAttributes(decryptionKeyHandle);
//        CaviumKeyAttributes privateAttributes = new CaviumKeyAttributes(privateKeyAttribute);
//        CaviumRSAPrivateKey privateKey = new CaviumRSAPrivateKey(decryptionKeyHandle, privateAttributes);
//        Cipher cipher = Cipher.getInstance(cipherTransformation, CAVIUM_PROVIDER);
//        cipher.init(Cipher.UNWRAP_MODE, privateKey, spec);
//        byte[] decodedCipher = Base64.getDecoder().decode(ciphertextDataKey.getBytes());
//        Key unwrappedKey = cipher.unwrap(decodedCipher, "AES", Cipher.SECRET_KEY);
//        if (unwrappedKey != null) {
//            byte[] exportedUnwrappedKey = unwrappedKey.getEncoded();
//            if (exportedUnwrappedKey != null) {
//                LOGGER.debug("Removing unwrapped session key.");
//                cleanupKey(unwrappedKey);
//                return new String(Base64.getEncoder().encode(exportedUnwrappedKey));
//            }
//            else {
//                LOGGER.warn("Exported unwrapped key is null, unwrappedKey: '{}'", unwrappedKey);
//                throw new GarbledDataKeyException();
//            }
//        }
//        else {
//            LOGGER.warn("Unwrapped key is null.");
//            throw new GarbledDataKeyException();
//        }
//    }
//    catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
//        throw new CryptoImplementationSupplierException(e);
//    }
//    catch (InvalidKeyException e) {
//        LOGGER.warn("Invalid key: {}", e.getMessage(), e);
//        throw new GarbledDataKeyException();
//    }
//    catch (CFM2Exception e) {
//        String message = "Failed to decrypt key, retry will be attempted unless max attempts reached";
//        LOGGER.warn("Failed to decrypt key: '{}', '{}', '{}'", e.getMessage(), e.getStatus(), e.getClass().getSimpleName());
//        LOGGER.warn(message);
//        throw new MasterKeystoreException(message, e);
//    }
//}
