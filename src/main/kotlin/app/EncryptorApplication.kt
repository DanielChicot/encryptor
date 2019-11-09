package app

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import java.security.GeneralSecurityException
import java.security.Key
import java.security.KeyFactory
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

@SpringBootApplication
class EncryptorApplication: CommandLineRunner {

    init {
        Security.addProvider(BouncyCastleProvider());
    }

    override fun run(vararg args: String?) {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(128)
        val secretKey = keyGen.generateKey()
        val b64 = Base64.getEncoder().encode(secretKey.encoded)
        println("secretKey: '${String(b64)}'.")

        val publicKey = publicKey(Base64.getDecoder().decode(encodedPublicKey))
        val encryptingCipher = cipher(Cipher.ENCRYPT_MODE, publicKey, "BC")
        println("encryptingCipher: '$encryptingCipher'.")

        val encrypted = encryptingCipher.doFinal(secretKey.encoded)
        val encodedAndEncrypted = Base64.getEncoder().encode(encrypted)
        println("encodedAndEncrypted: '${String(encodedAndEncrypted)}'.")

        val privateKey = privateKey(Base64.getDecoder().decode(encodedPrivateKey))
        val decryptingCipher = cipher(Cipher.DECRYPT_MODE, privateKey, "BC")
        println("decryptingCipher: '$decryptingCipher'.")
//
        val decrypted = decryptingCipher.doFinal(encrypted)
        val decryptedAndEncoded = Base64.getEncoder().encode(decrypted)
        println("decryptedAndEncoded: '${String(decryptedAndEncoded)}'.")

    }

    private fun cipher(cipherMode: Int, key: Key, provider: String = "") =
        if (provider.isNullOrEmpty()) {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding").apply {
                init(cipherMode, key)
            }

        }
        else {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", provider).apply {
                init(cipherMode, key)
            }

        }

    fun publicKey(keyEncryptionKeyBytes: ByteArray) =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyEncryptionKeyBytes))

    fun privateKey(keyEncryptionKeyBytes: ByteArray) =
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyEncryptionKeyBytes))

    private val encodedPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2G1pbVWCVVCvId+NgBQsF2KasDySO1+b110ZHEWxbdaapL07HYPgaI1spP8J0DQd79ebVLle8ASMQKQAhpBCkAhPplYDcFgI46Nb6jgKUCj02240AJ9hXPfVdv/Bx6DXl+Q9yBeCwivp1TdypUcOyW5Jhe/UM+qgb0Sb4BEro60BFumGuDja7U7c5PoGOPvPYKXPhLqr9iVD+zIu4CnrWb57XITiV7+nu9v28G9O2RtaKllbirEbFqX7awSE6hH8YhAAMfO2Olho0skqaa2hmLtC++Hmrcew+QE++XDRbBe2Ij/lBSE0SkkBuRItjaUdNT1dOfxZRuSitcZj0LPUwIDAQAF"
    private val encodedPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/YbWltVYJVUK8h342AFCwXYpqwPJI7X5vXXRkcRbFt1pqkvTsdg+BojWyk/wnQNB3v15tUuV7wBIxApACGkEKQCE+mVgNwWAjjo1vqOApQKPTbbjQAn2Fc99V2/8HHoNeX5D3IF4LCK+nVN3KlRw7JbkmF79Qz6qBvRJvgESujrQEW6Ya4ONrtTtzk+gY4+89gpc+Euqv2JUP7Mi7gKetZvntchOJXv6e72/bwb07ZG1oqWVuKsRsWpftrBITqEfxiEAAx87Y6WGjSySppraGYu0L74eatx7D5AT75cNFsF7YiP+UFITRKSQG5Ei2NpR01PV05/FlG5KK1xmPQs9TAgMBAAUCggEACTY5uGu6zxUqwg+qLkeOSVq57zAPJjElSdYdXTwgoEmJIjnZOZAypkvu73Ny+I1DpqL/9rrIlp3wUOFfefSHJ3OlndbT3nPDajUYJNpeGOkR6K8zL8D7HoAMGaLZJJQdn0iOQCLl4gH1GgA56Gn+bDkpcuNGZoRWfl+0xibDMvUAM3197j07Wx0ub6iXOqiuK6r9qsk2S3x5cC2/BrHLX/Ej1/PhDdB5R4wizakPA+XJCCi61oEO/FxvMa4y0MYeUv1R+8+bC8bYr0qCZLBTEEhr/2tLKe2yqsQ1895l/TvCJRgTZsYOoEKd9yKJn1+IHVrT/mKliWaiyg++XwTCxQKBgQDP3g9LZoxNiI2BTKvJSJyH5UC3Vq20q/URtPN/WfDGgyXupijKraVYBbULP6pSU6js75TxP4dr37KAq2ZG6v+LDVuraZlC386nAv5ROMFhGNn5VXCSnMAwb/0WDItDk9I/DyjQvbQ37CIWn9SOfFh27/ljN4g2KIZwFYXXWDuMuwKBgQDrsmjvt84HTZGX5M4kkvoe1SqC53TWlqy9fHoiD/0/fcFJiBFMdeNZVeNdpNdfpHq+V4q/8kq9MaKQjkmGZWY4gbaH4bT4OaCxI1QNZxXu3yPW85HmgdzGpDYWSlD4IjvoJOEIg8Lx/PJF2ywGNXMU6HOS2KSMa05yR+6EwQMqSQKBgQCkP7i/bZADBLUaf13S/e4cDLDgbHCt7ezHGiZYBw6M1aqxPH9VjIRF9UTCR8fknv0GKkPTQJ90NUQ4MFikl0RzP5IOne0yonZU0kl0J6Cp4x3v3cDcVuh8vE9E/BiwL0Lb3mNc4tgXaHf1oQkGW0rvpfvIaFvtYGs6Qh61DgPopQKBgBgIgk7eaPdr0Nyz8o24BE9tWaoG/iQnOqtRR/Hvfbqz0mG+qmJDHjZ2FNgVZddwlZ1a5IyqGtKS4eBqUGXVe+gZmbgMqO//WGk2NzQl3VxADexWys/WcO5A+YsYLpbUs4pjhsz3Rt3A4YQ+C2ANNRE5eiG31Ph02wCaWMvnnyeFAoGAFa4DQIEFbbG82YEswSImJsmRdo4X36jnhXtDsF4xNSLMTrKIaJgEYtz/6DYN8nU2cuLwojSH8m49UKvo0LsLaYk5ytlGQOJ0ItDbnOrFjVrIBtH09FVUJoHIV4QVM2V+uY6YCYDsRXo+4kZKDUJr271qPzz+X9Gnabky9jpw248="
}

fun main(args: Array<String>) {
    runApplication<EncryptorApplication>(*args)
}
