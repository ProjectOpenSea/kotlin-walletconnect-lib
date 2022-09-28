package org.walletconnect.impls

import com.squareup.moshi.Moshi
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.komputing.khex.decode
import org.komputing.khex.extensions.toNoPrefixHexString
import org.walletconnect.Session
import java.security.SecureRandom

class MoshiPayloadEncryption(moshi: Moshi) : Session.PayloadEncryption {

    private val payloadAdapter = moshi.adapter(MoshiPayloadAdapter.EncryptedPayload::class.java)

    override fun encrypt(unencryptedPayloadJson: String, key: String): String {
        val bytesData = unencryptedPayloadJson.toByteArray()
        val hexKey = decode(key)
        val iv = createRandomBytes(16)

        val padding = PKCS7Padding()
        val aes = PaddedBufferedBlockCipher(
            CBCBlockCipher(AESEngine()),
            padding
        )
        aes.init(true, ParametersWithIV(KeyParameter(hexKey), iv))

        val minSize = aes.getOutputSize(bytesData.size)
        val outBuf = ByteArray(minSize)
        val length1 = aes.processBytes(bytesData, 0, bytesData.size, outBuf, 0)
        aes.doFinal(outBuf, length1)


        val hmac = HMac(SHA256Digest())
        hmac.init(KeyParameter(hexKey))

        val hmacResult = ByteArray(hmac.macSize)
        hmac.update(outBuf, 0, outBuf.size)
        hmac.update(iv, 0, iv.size)
        hmac.doFinal(hmacResult, 0)

        return payloadAdapter.toJson(
            MoshiPayloadAdapter.EncryptedPayload(
                outBuf.toNoPrefixHexString(),
                hmac = hmacResult.toNoPrefixHexString(),
                iv = iv.toNoPrefixHexString()
            )
        )
    }

    override fun decrypt(encryptedPayloadJson: String, key: String): String {
        val encryptedPayload = payloadAdapter.fromJson(encryptedPayloadJson) ?: throw IllegalArgumentException("Invalid json payload!")

        // TODO verify hmac

        val padding = PKCS7Padding()
        val aes = PaddedBufferedBlockCipher(
            CBCBlockCipher(AESEngine()),
            padding
        )
        val ivAndKey = ParametersWithIV(
            KeyParameter(decode(key)),
            decode(encryptedPayload.iv)
        )
        aes.init(false, ivAndKey)

        val encryptedData = decode(encryptedPayload.data)
        val minSize = aes.getOutputSize(encryptedData.size)
        val outBuf = ByteArray(minSize)
        var len = aes.processBytes(encryptedData, 0, encryptedData.size, outBuf, 0)
        len += aes.doFinal(outBuf, len)

        return String(outBuf.copyOf(len))
    }

    private fun createRandomBytes(i: Int) = ByteArray(i).also { SecureRandom().nextBytes(it) }
}