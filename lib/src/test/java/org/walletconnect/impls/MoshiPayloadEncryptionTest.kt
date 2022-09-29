package org.walletconnect.impls

import com.google.common.truth.Truth.assertThat
import com.squareup.moshi.Moshi
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.walletconnect.impls.MoshiPayloadAdapter.EncryptedPayload
import java.security.SecureRandom

class MoshiPayloadEncryptionTest {

    private val moshi = Moshi.Builder().build()
    private val payloadEncryption = MoshiPayloadEncryption(Moshi.Builder().build())
    private val encryptedPayloadAdapter = moshi.adapter(EncryptedPayload::class.java)

    @Test
    fun `happy path encryption + decryption`() {
        val key = generateKey()
        val payloadJson =
            """
                {
                    "id" : 123456,
                    "method" : "wc_sessionRequest",
                }
            """.trimIndent()
        val encryptedPayload = payloadEncryption.encrypt(payloadJson, key)

        val result = payloadEncryption.decrypt(encryptedPayload, key)

        assertThat(result).isEqualTo(payloadJson)
    }

    @Test
    fun `invalid hmac throws exception`() {
        val key = generateKey()
        // this is the original payload
        val payloadJson =
            """
                {
                    "id" : 123456,
                    "method" : "wc_sessionRequest",
                }
            """.trimIndent()
        val mutatedPayload = with(encryptedPayloadAdapter.fromJson(payloadEncryption.encrypt(payloadJson, key))) {
            requireNotNull(this)
            encryptedPayloadAdapter.toJson(copy(hmac = hmac.dropLast(4)+"1234"))
        }

        assertThrows<IllegalArgumentException> {
            payloadEncryption.decrypt(mutatedPayload, key)
        }
    }

    @Test
    fun `invalid iv throws exception`() {
        val key = generateKey()
        // this is the original payload
        val payloadJson =
            """
                {
                    "id" : 123456,
                    "method" : "wc_sessionRequest",
                }
            """.trimIndent()
        val mutatedPayload = with(encryptedPayloadAdapter.fromJson(payloadEncryption.encrypt(payloadJson, key))) {
            requireNotNull(this)
            encryptedPayloadAdapter.toJson(copy(iv = iv.dropLast(4)+"1234"))
        }

        assertThrows<IllegalArgumentException> {
            payloadEncryption.decrypt(mutatedPayload, key)
        }
    }

    @Test
    fun `invalid data throws exception`() {
        val key = generateKey()
        // this is the original payload
        val payloadJson =
            """
                {
                    "id" : 123456,
                    "method" : "wc_sessionRequest",
                }
            """.trimIndent()
        val mutatedPayload = with(encryptedPayloadAdapter.fromJson(payloadEncryption.encrypt(payloadJson, key))) {
            requireNotNull(this)
            encryptedPayloadAdapter.toJson(copy(data = data.dropLast(4)+"1234"))
        }

        assertThrows<IllegalArgumentException> {
            payloadEncryption.decrypt(mutatedPayload, key)
        }
    }

    private fun generateKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString(separator = "") { "%02x".format(it) }
}