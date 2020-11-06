package com.example.encrypt

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.text.TextUtils
import android.util.Base64
import java.lang.Exception
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class EncryptManger private constructor() {


    companion object {

        const val SHARED_PREFERENCES_ENCRYPT_NAME = "SharedPreferencesEncrypt"
        const val SHARED_PREFERENCES_KEY_AES_SECRET_KEY = "SharedPreferencesKeyAESSecretKey"

        const val ANDROID_KEY_STORE = "AndroidKeyStore"

        const val AES_KEY = "AES_KEY_NAME"
        const val AES_ALGORITHM = "AES/CBC/PKCS7Padding"

        const val RSA_KEY = "RSA_KEY_NAME"
        const val RSA_ALGORITHM = "RSA/ECB/PKCS1Padding"

        val instance by lazy(mode = LazyThreadSafetyMode.SYNCHRONIZED) {
            EncryptManger()
        }
    }

    /**
     * base64编码
     */
    fun base64Encode(data: String): String {
        return Base64.encodeToString(data.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    /**
     * base64解码
     */
    fun base64Decode(data: String): String {
        return String(Base64.decode(data, Base64.NO_WRAP), Charsets.UTF_8)
    }

    /**
     * md5加密
     * md5是不可逆的，
     */
    fun md5Encode(data: String): String {
        val md = MessageDigest.getInstance("MD5")
        val byteArray = md.digest(data.toByteArray())
        var sb = StringBuilder()
        for (b in byteArray) {
            var temp = Integer.toHexString(b.toInt() and 0xff)
            if (temp.length == 1) {
                temp += "0"
            }
            sb.append(temp)
        }

        return sb.toString()
    }

    /**
     * AES加密
     */
    fun aesEncode(context: Context, data: String): String {
        val secretKey: SecretKey
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            secretKey = aesCreateKeyByKeyStore()
        } else {
            val aesKeyBytes = SecureRandom.getSeed(16)
            secretKey = SecretKeySpec(aesKeyBytes, "AES")

            val rsaEncodedAesKey = rsaEncode(context, Base64.encodeToString(aesKeyBytes, Base64.DEFAULT))

            SharedPreferencesHelper.putData(
                context,
                SHARED_PREFERENCES_ENCRYPT_NAME,
                SHARED_PREFERENCES_KEY_AES_SECRET_KEY,
                rsaEncodedAesKey
            )
        }

        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val ivBytes = SecureRandom.getSeed(16)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(ivBytes))

        var encodeBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        // 加密数组在头部拼接iv，用于解密使用
        encodeBytes = mergeByteAry(ivBytes, encodeBytes)

        return Base64.encodeToString(encodeBytes, Base64.DEFAULT)
    }

    /**
     * AES解密
     */
    fun aesDecode(context: Context, data: String): String {
        val dataWithIv = Base64.decode(data, Base64.DEFAULT)
        // 从加密字符串中分别解析出iv及加密数据的数组，iv在数组头部长度为16
        val ivBytes = ByteArray(16)
        val dataBytes = ByteArray(dataWithIv.size - 16)
        System.arraycopy(dataWithIv, 0, ivBytes, 0, 16)
        System.arraycopy(dataWithIv, 16, dataBytes, 0, dataBytes.size)

        val secretKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null)
            val secretKeyEntry = keyStore.getEntry(
                AES_KEY, null
            )
            if (secretKeyEntry != null) {
                (secretKeyEntry as KeyStore.SecretKeyEntry).secretKey
            } else {
                throw Exception("not find AES Key")
            }
        } else {
            val rsaEncodedAesKey = SharedPreferencesHelper.getData(
                context, SHARED_PREFERENCES_ENCRYPT_NAME,
                SHARED_PREFERENCES_KEY_AES_SECRET_KEY
            )
            if (TextUtils.isEmpty(rsaEncodedAesKey)) {
                throw Exception("not find RsaEncoded AES Key")
            }

            val aesKeyStr = rsaDecode(rsaEncodedAesKey!!)

            SecretKeySpec(Base64.decode(aesKeyStr, Base64.DEFAULT), "AES")
        }

        val cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(ivBytes))

        val decodeBytes = cipher.doFinal(dataBytes)

        return String(decodeBytes, Charsets.UTF_8)
    }

    /**
     * SDK >= 23，即Android6.0以上版本借助KeyStore生成AES秘钥
     */
    @TargetApi(Build.VERSION_CODES.M)
    fun aesCreateKeyByKeyStore(): SecretKey {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            AES_KEY,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setRandomizedEncryptionRequired(false)
            .build()

        keyGenerator.init(keyGenParameterSpec)

        return keyGenerator.generateKey()
    }

    /**
     * RSA公钥加密
     */
    fun rsaEncode(context: Context, data: String): String {
        // 创建RSA秘钥对
        rsaCreateKeyPair(context)

        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val publicKey = keyStore.getCertificate(RSA_KEY).publicKey

        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val encodeBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        return Base64.encodeToString(encodeBytes, Base64.NO_WRAP)
    }

    /**
     * RSA私钥解密
     */
    fun rsaDecode(data: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(RSA_KEY, null)

        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val decodeBytes = cipher.doFinal(Base64.decode(data, Base64.NO_WRAP))

        return String(decodeBytes, Charsets.UTF_8)
    }

    /**
     * 创建RSA秘钥对
     */
    private fun rsaCreateKeyPair(context: Context): KeyPair {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 1)

        var keyPair: KeyPair
        @Suppress("DEPRECATION")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            val keyPairGenParameterSpec = KeyPairGeneratorSpec.Builder(context)
                .setAlias(RSA_KEY)
                .setSubject(X500Principal("CN=$RSA_KEY"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()

            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE)
            keyPairGenerator.initialize(keyPairGenParameterSpec)

            keyPair = keyPairGenerator.generateKeyPair()
        } else {
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(RSA_KEY,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build()

            val keyPairGenerator = KeyPairGenerator.getInstance(RSA_KEY, ANDROID_KEY_STORE)
            keyPairGenerator.initialize(keyGenParameterSpec)

            keyPair = keyPairGenerator.generateKeyPair()
        }

        return keyPair
    }

    private fun mergeByteAry(byteAry1: ByteArray, byteAry2: ByteArray): ByteArray {
        val newByteAry = ByteArray(byteAry1.size + byteAry2.size)
        System.arraycopy(byteAry1, 0, newByteAry, 0, byteAry1.size)
        System.arraycopy(byteAry2, 0, newByteAry, byteAry1.size, byteAry2.size)
        return newByteAry
    }

}