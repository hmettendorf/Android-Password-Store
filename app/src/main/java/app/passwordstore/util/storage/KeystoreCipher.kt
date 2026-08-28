/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.storage

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Thrown when the Keystore key backing a store can no longer be used, because it was invalidated
 * (the user changed their device credential or re-enrolled biometrics) or because it is simply
 * gone. Either way the data it protected is unrecoverable.
 *
 * Callers decide what this means for their data: a cache can be cleared and re-populated, whereas
 * losing the key for an SSH private key must be surfaced to the user.
 */
class KeyUnusableException(message: String, cause: Throwable?) : Exception(message, cause)

/**
 * Thrown when the key is fine but the user's authentication has expired. Unlike
 * [KeyUnusableException] this is recoverable: prompt for authentication and retry.
 */
class KeyAuthenticationRequiredException(message: String, cause: Throwable?) :
  Exception(message, cause)

/**
 * AES-GCM encryption backed by a key held in the Android Keystore, replacing the deprecated
 * `androidx.security.crypto` `MasterKey`.
 *
 * The key never leaves the Keystore. Each store owns its own [alias] so that clearing or
 * invalidating one store cannot affect another.
 */
class KeystoreCipher(
  context: Context,
  private val alias: String,
  private val requireUserAuthentication: Boolean = false,
  private val authValidityDurationSeconds: Int = -1,
  private val preferStrongBox: Boolean = false,
) {

  private val appContext = context.applicationContext

  /** Encrypts [plaintext], returning a self-describing payload that [decrypt] can consume. */
  fun encrypt(plaintext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    try {
      cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw KeyUnusableException("Keystore key '$alias' was invalidated", e)
    } catch (e: UserNotAuthenticatedException) {
      throw KeyAuthenticationRequiredException("Keystore key '$alias' needs authentication", e)
    }
    val iv = cipher.iv
    require(iv.size == IV_LENGTH) { "Unexpected GCM IV length: ${iv.size}" }
    val ciphertext = cipher.doFinal(plaintext)
    return ByteArray(1 + IV_LENGTH + ciphertext.size).also { out ->
      out[0] = FORMAT_VERSION
      iv.copyInto(out, 1)
      ciphertext.copyInto(out, 1 + IV_LENGTH)
    }
  }

  /**
   * Reverses [encrypt].
   *
   * Deliberately never creates a key. A missing alias means this payload can never be read again,
   * and minting a replacement here would turn that into an authentication-tag failure that reads
   * like data corruption -- while leaving a plausible-looking key behind.
   */
  fun decrypt(payload: ByteArray): ByteArray {
    require(payload.isNotEmpty() && payload[0] == FORMAT_VERSION) { "Unrecognised payload format" }
    require(payload.size > 1 + IV_LENGTH) { "Payload too short to contain a GCM IV" }
    val key =
      existingKey() ?: throw KeyUnusableException("Keystore key '$alias' no longer exists", null)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    val spec = GCMParameterSpec(TAG_LENGTH_BITS, payload, 1, IV_LENGTH)
    return try {
      cipher.init(Cipher.DECRYPT_MODE, key, spec)
      cipher.doFinal(payload, 1 + IV_LENGTH, payload.size - 1 - IV_LENGTH)
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw KeyUnusableException("Keystore key '$alias' was invalidated", e)
    } catch (e: UserNotAuthenticatedException) {
      throw KeyAuthenticationRequiredException("Keystore key '$alias' needs authentication", e)
    }
  }

  /** Removes the backing key. Any data encrypted with it becomes permanently unreadable. */
  fun deleteKey() {
    keyStore.deleteEntry(alias)
  }

  /** Whether a key for this store already exists, without creating one as a side effect. */
  fun keyExists(): Boolean = keyStore.containsAlias(alias)

  /** The stored key, or null if this store has never had one (or it is beyond recovery). */
  private fun existingKey(): SecretKey? =
    try {
      keyStore.getKey(alias, null) as? SecretKey
    } catch (e: UnrecoverableKeyException) {
      throw KeyUnusableException("Keystore key '$alias' cannot be recovered", e)
    }

  private fun getOrCreateKey(): SecretKey =
    existingKey() ?: generateKey(withStrongBox = preferStrongBox && isStrongBoxAvailable())

  private fun generateKey(withStrongBox: Boolean): SecretKey {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    return try {
      generator.init(buildSpec(withStrongBox))
      generator.generateKey()
    } catch (e: StrongBoxUnavailableException) {
      // The device advertised StrongBox but refused the key. Fall back rather than fail: the key
      // is still hardware-backed by the TEE.
      if (!withStrongBox) throw e
      generateKey(withStrongBox = false)
    }
  }

  private fun buildSpec(withStrongBox: Boolean): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      )
      .apply {
        setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        setKeySize(KEY_SIZE_BITS)
        if (requireUserAuthentication) {
          setUserAuthenticationRequired(true)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(
              authValidityDurationSeconds,
              KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
          } else {
            // Replaced by setUserAuthenticationParameters in API 30; still required for API 26-29.
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(authValidityDurationSeconds)
          }
        }
        if (withStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(true)
        }
      }
      .build()

  private fun isStrongBoxAvailable(): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

  companion object {

    /**
     * Whether [payload] looks like something [encrypt] produced, as opposed to a legacy plaintext
     * file left over from before a store was encrypted.
     */
    fun isEncryptedPayload(payload: ByteArray): Boolean =
      payload.isNotEmpty() && payload[0] == FORMAT_VERSION

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_SIZE_BITS = 256
    private const val TAG_LENGTH_BITS = 128
    private const val IV_LENGTH = 12

    /** First byte of every payload; lets a legacy plaintext file be told apart from ciphertext. */
    private const val FORMAT_VERSION: Byte = 1

    private val keyStore: KeyStore by lazy {
      KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }
  }
}
