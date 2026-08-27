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
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Thrown when the Keystore key backing a store can no longer be used, for example because the user
 * changed their device credential or re-enrolled biometrics.
 *
 * Callers decide what this means for their data: a cache can be cleared and re-populated, whereas
 * losing the key for an SSH private key is unrecoverable and must be surfaced to the user.
 */
class KeyUnusableException(message: String, cause: Throwable?) : Exception(message, cause)

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
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    val iv = cipher.iv
    require(iv.size == IV_LENGTH) { "Unexpected GCM IV length: ${iv.size}" }
    val ciphertext = cipher.doFinal(plaintext)
    return ByteArray(1 + IV_LENGTH + ciphertext.size).also { out ->
      out[0] = FORMAT_VERSION
      iv.copyInto(out, 1)
      ciphertext.copyInto(out, 1 + IV_LENGTH)
    }
  }

  /** Reverses [encrypt]. Throws [KeyUnusableException] if the backing key is gone. */
  fun decrypt(payload: ByteArray): ByteArray {
    require(payload.isNotEmpty() && payload[0] == FORMAT_VERSION) { "Unrecognised payload format" }
    require(payload.size > 1 + IV_LENGTH) { "Payload too short to contain a GCM IV" }
    val cipher = Cipher.getInstance(TRANSFORMATION)
    val spec = GCMParameterSpec(TAG_LENGTH_BITS, payload, 1, IV_LENGTH)
    return runCatching {
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), spec)
        cipher.doFinal(payload, 1 + IV_LENGTH, payload.size - 1 - IV_LENGTH)
      }
      .getOrElse { error ->
        if (error is KeyPermanentlyInvalidatedException) {
          throw KeyUnusableException("Keystore key '$alias' was invalidated", error)
        }
        throw error
      }
  }

  /** Removes the backing key. Any data encrypted with it becomes permanently unreadable. */
  fun deleteKey() {
    keyStore.deleteEntry(alias)
  }

  /** Whether a key for this store already exists, without creating one as a side effect. */
  fun keyExists(): Boolean = keyStore.containsAlias(alias)

  private fun getOrCreateKey(): SecretKey {
    (keyStore.getKey(alias, null) as? SecretKey)?.let {
      return it
    }
    return generateKey(withStrongBox = preferStrongBox && isStrongBoxAvailable())
  }

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

  private companion object {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_SIZE_BITS = 256
    private const val TAG_LENGTH_BITS = 128
    private const val IV_LENGTH = 12
    private const val FORMAT_VERSION: Byte = 1

    private val keyStore: KeyStore by lazy {
      KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }
  }
}
