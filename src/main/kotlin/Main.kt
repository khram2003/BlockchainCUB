import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.optional
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.security.*
import java.security.spec.EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher


fun generateRSAKeyPair(keySize: Int = 2048): KeyPair {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(keySize)
    return generator.generateKeyPair()
}

fun encrypt(fileBytes: ByteArray, publicKey: PublicKey): ByteArray {
    val encryptCipher = Cipher.getInstance("RSA")
    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey)
    return encryptCipher.doFinal(fileBytes)
}

fun decrypt(encryptedFileBytes: ByteArray, privateKey: PrivateKey): ByteArray {
    val decryptCipher = Cipher.getInstance("RSA")
    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey)
    return decryptCipher.doFinal(encryptedFileBytes)
}

fun recreatePublicKey(publicKeyBytes: ByteArray): PublicKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(publicKeyBytes)
    return keyFactory.generatePublic(publicKeySpec)
}

fun recreatePrivateKey(privateKeyBytes: ByteArray): PrivateKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKeySpec: EncodedKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
    return keyFactory.generatePrivate(privateKeySpec)
}

enum class Command {
    ENCRYPT,
    DECRYPT,
    KEYS
}

fun main(args: Array<String>) {
    val parser = ArgParser("example")
    val input by parser.argument(ArgType.String, description = "Input file name").optional()
    val output by parser.argument(ArgType.String, description = "Output file name").optional()
    val key by parser.argument(ArgType.String, description = "Private or public key").optional()
    val command by parser.option(
        ArgType.Choice<Command>(),
        shortName = "c",
        description = "Command: encrypt, decrypt, keys (generate keys)"
    )
    parser.parse(args)
    when (command) {
        Command.KEYS -> {
            val keyPair = generateRSAKeyPair()
            val publicKey = keyPair.public
            val privateKey = keyPair.private
            FileOutputStream("public.key").use { fos -> fos.write(publicKey.encoded) }
            println("Public key is written to public.key file.")
            FileOutputStream("private.key").use { fos -> fos.write(privateKey.encoded) }
            println("Private key is written to private.key file.")
        }
        Command.ENCRYPT -> {
            if (key == null) {
                throw IllegalArgumentException("Key file is not provided")
            }
            val keyFile = File(key!!)
            val keyByteArray = keyFile.readBytes()
            val publicKey = recreatePublicKey(keyByteArray)
            val inputFile = File(input!!)
            val fileBytes = Files.readAllBytes(inputFile.toPath())
            FileOutputStream(output!!).use { fos -> fos.write(encrypt(fileBytes, publicKey)) }
        }
        Command.DECRYPT -> {
            if (key == null) {
                throw IllegalArgumentException("Key is not provided")
            }
            val keyFile = File(key!!)
            val keyByteArray = keyFile.readBytes()
            val privateKey = recreatePrivateKey(keyByteArray)
            val inputFile = File(input!!)
            val fileBytes = Files.readAllBytes(inputFile.toPath())
            FileOutputStream(output!!).use { fos -> fos.write(decrypt(fileBytes, privateKey)) }
        }
        else -> {
            throw IllegalArgumentException("Unknown command")
        }
    }

}
