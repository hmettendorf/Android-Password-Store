/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import app.passwordstore.Application
import app.passwordstore.R
import app.passwordstore.injection.prefs.PreferenceEntryPoint
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.settings.PreferenceKeys
import app.passwordstore.util.storage.KeystoreCipher
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.LogPriority.INFO
import logcat.asLog
import logcat.logcat
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.userauth.keyprovider.KeyProvider

private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
private const val KEYSTORE_ALIAS = "sshkey"
private const val ANDROIDX_SECURITY_KEYSET_PREF_NAME = "androidx_sshkey_keyset_prefs"

/**
 * Wrapping key for [SshKey.Type.KeystoreWrappedEd25519]. Deliberately distinct from
 * [KEYSTORE_ALIAS]: during migration the legacy MasterKey still lives under that alias, and
 * generating the replacement there would destroy the only means of reading the old key.
 */
private const val KEYSTORE_WRAP_ALIAS = "sshkey_wrap"

/**
 * Wrapping key for [SshKey.Type.Imported] and [SshKey.Type.LegacyGenerated] keys. Separate from
 * [KEYSTORE_WRAP_ALIAS] so that re-importing a key cannot disturb a generated one, and vice versa.
 */
private const val KEYSTORE_IMPORTED_WRAP_ALIAS = "sshkey_imported_wrap"

/** Matches the validity window the legacy wrapping MasterKey was created with. */
private const val WRAP_KEY_AUTH_VALIDITY_SECONDS = 15

/** Replacement key material is staged here so a failure never destroys the only copy. */
private const val STAGING_KEY_FILE_NAME = ".ssh_key.migrating"

private val androidKeystore: KeyStore by unsafeLazy {
  KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE).apply { load(null) }
}

private val KeyStore.sshPrivateKey
  get() = getKey(KEYSTORE_ALIAS, null) as? PrivateKey

private val KeyStore.sshPublicKey
  get() = getCertificate(KEYSTORE_ALIAS)?.publicKey

fun parseSshPublicKey(sshPublicKey: String): PublicKey? {
  val sshKeyParts = sshPublicKey.split("""\s+""".toRegex())
  if (sshKeyParts.size < 2) return null
  return Buffer.PlainBuffer(Base64.decode(sshKeyParts[1], Base64.NO_WRAP)).readPublicKey()
}

fun toSshPublicKey(publicKey: PublicKey): String {
  val rawPublicKey = Buffer.PlainBuffer().putPublicKey(publicKey).compactData
  val keyType = KeyType.fromKey(publicKey)
  return "$keyType ${Base64.encodeToString(rawPublicKey, Base64.NO_WRAP)}"
}

object SshKey {

  val sshPublicKey
    get() = if (publicKeyFile.exists()) publicKeyFile.readText() else null

  val canShowSshPublicKey
    get() = type in listOf(Type.LegacyGenerated, Type.KeystoreNative, Type.KeystoreWrappedEd25519)

  val exists
    get() = type != null

  val mustAuthenticate: Boolean
    get() {
      return runCatching {
          if (type !in listOf(Type.KeystoreNative, Type.KeystoreWrappedEd25519)) return false
          val alias =
            if (type == Type.KeystoreWrappedEd25519 && !legacyWrappedKeyInUse()) KEYSTORE_WRAP_ALIAS
            else KEYSTORE_ALIAS
          when (val key = androidKeystore.getKey(alias, null)) {
            is PrivateKey -> {
              val factory = KeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
              return factory.getKeySpec(key, KeyInfo::class.java).isUserAuthenticationRequired
            }
            is SecretKey -> {
              val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
              (factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo).isUserAuthenticationRequired
            }
            else -> throw IllegalStateException("SSH key does not exist in Keystore")
          }
        }
        .getOrElse { error ->
          // It is fine to swallow the exception here since it will reappear when the key
          // is
          // used for SSH authentication and can then be shown in the UI.
          logcat { error.asLog() }
          false
        }
    }

  private val context: Context
    get() = Application.instance.applicationContext

  private val privateKeyFile
    get() = File(context.filesDir, ".ssh_key")

  private val publicKeyFile
    get() = File(context.filesDir, ".ssh_key.pub")

  private var type: Type?
    get() = Type.fromValue(context.sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_KEY_TYPE))
    set(value) =
      context.sharedPrefs.edit { putString(PreferenceKeys.GIT_REMOTE_KEY_TYPE, value?.value) }

  private val isStrongBoxSupported by unsafeLazy {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    else false
  }

  private enum class Type(val value: String) {
    Imported("imported"),
    KeystoreNative("keystore_native"),
    KeystoreWrappedEd25519("keystore_wrapped_ed25519"),

    // Behaves like `Imported`, but allows to view the public key.
    LegacyGenerated("legacy_generated");

    companion object {

      fun fromValue(value: String?): Type? = entries.associateBy { it.value }[value]
    }
  }

  enum class Algorithm(
    val algorithm: String,
    val applyToSpec: KeyGenParameterSpec.Builder.() -> Unit,
  ) {
    Rsa(
      KeyProperties.KEY_ALGORITHM_RSA,
      {
        setKeySize(3072)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setDigests(
          KeyProperties.DIGEST_SHA1,
          KeyProperties.DIGEST_SHA256,
          KeyProperties.DIGEST_SHA512,
        )
      },
    ),
    Ecdsa(
      KeyProperties.KEY_ALGORITHM_EC,
      {
        setKeySize(256)
        setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
        setDigests(KeyProperties.DIGEST_SHA256)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(isStrongBoxSupported)
        }
      },
    ),
  }

  private fun delete() {
    androidKeystore.deleteEntry(KEYSTORE_ALIAS)
    androidKeystore.deleteEntry(KEYSTORE_WRAP_ALIAS)
    androidKeystore.deleteEntry(KEYSTORE_IMPORTED_WRAP_ALIAS)
    File(context.filesDir, STAGING_KEY_FILE_NAME).delete()
    // Remove Tink key set used by AndroidX's EncryptedFile.
    context.getSharedPreferences(ANDROIDX_SECURITY_KEYSET_PREF_NAME, Context.MODE_PRIVATE).edit {
      clear()
    }
    if (privateKeyFile.isFile) {
      privateKeyFile.delete()
    }
    if (publicKeyFile.isFile) {
      publicKeyFile.delete()
    }
    PreferenceEntryPoint.gitPreferences(context).edit {
      remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)
    }
    type = null
  }

  fun import(uri: Uri) {
    // First check whether the content at uri is likely an SSH private key.
    val fileSize =
      context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use {
        cursor ->
        // Cursor returns only a single row.
        cursor.moveToFirst()
        cursor.getInt(0)
      } ?: throw IOException(context.getString(R.string.ssh_key_does_not_exist))

    // We assume that an SSH key's ideal size is > 0 bytes && < 100 kilobytes.
    if (fileSize > 100_000 || fileSize == 0)
      throw IllegalArgumentException(
        context.getString(R.string.ssh_key_import_error_not_an_ssh_key_message)
      )

    val sshKeyInputStream =
      context.contentResolver.openInputStream(uri)
        ?: throw IOException(context.getString(R.string.ssh_key_does_not_exist))
    val lines = sshKeyInputStream.use { `is` -> `is`.bufferedReader().readLines() }

    // The file must have more than 2 lines, and the first and last line must have private key
    // markers.
    if (
      lines.size < 2 ||
        !Regex("BEGIN .* PRIVATE KEY").containsMatchIn(lines.first()) ||
        !Regex("END .* PRIVATE KEY").containsMatchIn(lines.last())
    )
      throw IllegalArgumentException(
        context.getString(R.string.ssh_key_import_error_not_an_ssh_key_message)
      )

    // At this point, we are reasonably confident that we have actually been provided a private
    // key and delete the old key.
    delete()
    // Canonicalize line endings to '\n'.
    writeImportedPrivateKey(lines.joinToString("\n"))

    type = Type.Imported
  }

  @Deprecated("To be used only in Migrations.kt")
  fun useLegacyKey(isGenerated: Boolean) {
    type = if (isGenerated) Type.LegacyGenerated else Type.Imported
  }

  private fun wrappingCipher(requireAuthentication: Boolean) =
    KeystoreCipher(
      context = context,
      alias = KEYSTORE_WRAP_ALIAS,
      requireUserAuthentication = requireAuthentication,
      authValidityDurationSeconds = WRAP_KEY_AUTH_VALIDITY_SECONDS,
      preferStrongBox = true,
    )

  /** Encrypts [seed] to [target] with the Keystore wrapping key. */
  private fun writeWrappedPrivateKey(
    seed: ByteArray,
    requireAuthentication: Boolean,
    target: File,
  ) {
    target.writeBytes(wrappingCipher(requireAuthentication).encrypt(seed))
  }

  /** Reverses [writeWrappedPrivateKey]. */
  private fun readWrappedPrivateKey(source: File = privateKeyFile): ByteArray =
    wrappingCipher(requireAuthentication = false).decrypt(source.readBytes())

  /** Wrapping key for imported and legacy-generated keys, which are stored verbatim. */
  private fun importedKeyCipher() =
    KeystoreCipher(context = context, alias = KEYSTORE_IMPORTED_WRAP_ALIAS, preferStrongBox = true)

  /** Encrypts an imported private key, which is held as text rather than as a raw seed. */
  private fun writeImportedPrivateKey(contents: String, target: File = privateKeyFile) {
    target.writeBytes(importedKeyCipher().encrypt(contents.toByteArray()))
  }

  /**
   * Returns the imported private key, encrypting it at rest first if it predates that.
   *
   * Imported keys used to be written to disk verbatim while generated ones were Keystore-wrapped. A
   * key that arrived under the old behaviour is re-written on first use so both kinds end up
   * equally protected.
   */
  private fun readImportedPrivateKey(): String {
    val stored = privateKeyFile.readBytes()
    if (KeystoreCipher.isEncryptedPayload(stored)) {
      return importedKeyCipher().decrypt(stored).decodeToString()
    }
    val contents = stored.decodeToString()
    encryptImportedPrivateKey(contents)
    return contents
  }

  /**
   * Re-writes a plaintext imported key as ciphertext.
   *
   * Every failure path here is non-destructive: the plaintext file is not touched until the
   * replacement has been written and read back, so an interrupted attempt simply runs again.
   */
  private fun encryptImportedPrivateKey(contents: String) {
    val staging = File(context.filesDir, STAGING_KEY_FILE_NAME)
    runCatching {
        androidKeystore.deleteEntry(KEYSTORE_IMPORTED_WRAP_ALIAS)
        writeImportedPrivateKey(contents, staging)
        check(importedKeyCipher().decrypt(staging.readBytes()).decodeToString() == contents) {
          "Encrypted SSH key did not read back identically"
        }
        check(staging.renameTo(privateKeyFile)) { "Could not replace the private key file" }
        logcat(INFO) { "Encrypted the imported SSH key at rest" }
      }
      .onErr { error ->
        staging.delete()
        androidKeystore.deleteEntry(KEYSTORE_IMPORTED_WRAP_ALIAS)
        logcat(ERROR) { "Could not encrypt the imported SSH key, leaving it: ${error.asLog()}" }
      }
  }

  /** True while the Tink key set for the legacy `EncryptedFile` is still present. */
  private fun legacyWrappedKeyExists() =
    context
      .getSharedPreferences(ANDROIDX_SECURITY_KEYSET_PREF_NAME, Context.MODE_PRIVATE)
      .all
      .isNotEmpty()

  /**
   * True while the private key on disk is *actually* still in the legacy `EncryptedFile` format.
   *
   * The file itself is the only trustworthy record. The Tink key set outlives a crash between
   * swapping the file and clearing it, and trusting the key set alone would send a key that has
   * already been converted back through a migration that cannot succeed.
   */
  private fun legacyWrappedKeyInUse() =
    privateKeyFile.isFile &&
      !KeystoreCipher.isEncryptedPayload(privateKeyFile.readBytes()) &&
      legacyWrappedKeyExists()

  // androidx.security:security-crypto is deprecated; this is the read side of the migration away
  // from it and is deleted once the deprecation window closes.
  @Suppress("DEPRECATION")
  private fun legacyEncryptedFile(): EncryptedFile =
    EncryptedFile.Builder(
        context,
        privateKeyFile,
        MasterKey.Builder(context, KEYSTORE_ALIAS)
          .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
          .setRequestStrongBoxBacked(true)
          .setUserAuthenticationRequired(false, 15)
          .build(),
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
      )
      .setKeysetPrefName(ANDROIDX_SECURITY_KEYSET_PREF_NAME)
      .build()

  /** Whether the legacy wrapping MasterKey was created with user authentication required. */
  private fun legacyWrapKeyRequiresAuth(): Boolean =
    runCatching {
        val key =
          androidKeystore.getKey(KEYSTORE_ALIAS, null) as? SecretKey ?: return@runCatching false
        val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
        (factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo).isUserAuthenticationRequired
      }
      .getOrElse { false }

  /**
   * Re-wraps a keystore-wrapped ed25519 key from the deprecated `EncryptedFile` onto the Keystore
   * cipher.
   *
   * The replacement is written to a staging file and read back before it replaces the original, so
   * a failure before the swap leaves the legacy key intact and the next attempt can retry. After
   * the swap the new wrapping key is the only thing that can read the key material, so nothing past
   * that point may delete it -- losing it is unrecoverable, and the user would have to generate a
   * new key and re-register it with their git host.
   */
  private fun migrateWrappedEd25519Key() {
    if (type != Type.KeystoreWrappedEd25519 || !privateKeyFile.isFile) return
    if (!legacyWrappedKeyInUse()) {
      // Either there was never anything to migrate, or a previous run swapped the file and was
      // interrupted before it could clean up. Both are finished as far as the key is concerned.
      discardLegacyWrappingKey()
      return
    }

    val seed =
      runCatching {
          val bytes = legacyEncryptedFile().openFileInput().use { it.readBytes() }
          // Refuse to proceed unless the bytes really are a usable ed25519 key.
          EdDSAPrivateKey(EdDSAPrivateKeySpec(bytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
          bytes
        }
        .getOrElse { error ->
          logcat(ERROR) { "Could not read the legacy ed25519 key, keeping it: ${error.asLog()}" }
          return
        }

    val staging = File(context.filesDir, STAGING_KEY_FILE_NAME)
    val prepared =
      runCatching {
          val requiresAuth = legacyWrapKeyRequiresAuth()
          androidKeystore.deleteEntry(KEYSTORE_WRAP_ALIAS)
          writeWrappedPrivateKey(seed, requiresAuth, staging)
          check(readWrappedPrivateKey(staging).contentEquals(seed)) {
            "Re-wrapped ed25519 key did not read back identically"
          }
        }
        .onErr { error ->
          // The swap has not happened, so the legacy key is still the only copy and the
          // half-built replacement is worth nothing. Safe to discard both.
          staging.delete()
          androidKeystore.deleteEntry(KEYSTORE_WRAP_ALIAS)
          logcat(ERROR) {
            "Could not re-wrap ed25519 key, keeping the legacy key: ${error.asLog()}"
          }
        }
    if (prepared.isErr) return

    if (!staging.renameTo(privateKeyFile)) {
      // Still before the swap: the legacy key is untouched, so rolling back is safe.
      staging.delete()
      androidKeystore.deleteEntry(KEYSTORE_WRAP_ALIAS)
      logcat(ERROR) { "Could not replace the private key file, keeping the legacy key" }
      return
    }

    // Past the point of no return. Anything that fails from here leaves a usable key behind and
    // is retried on the next call, so no failure may reach back and delete KEYSTORE_WRAP_ALIAS.
    discardLegacyWrappingKey()
    logcat(INFO) { "Re-wrapped ed25519 SSH key onto the Keystore cipher" }
  }

  /**
   * Drops the Tink key set and MasterKey behind the deprecated `EncryptedFile`, once the key
   * material they protected has been re-wrapped. Never touches [KEYSTORE_WRAP_ALIAS].
   */
  private fun discardLegacyWrappingKey() {
    runCatching {
        if (legacyWrappedKeyExists()) {
          context
            .getSharedPreferences(ANDROIDX_SECURITY_KEYSET_PREF_NAME, Context.MODE_PRIVATE)
            .edit { clear() }
        }
        androidKeystore.deleteEntry(KEYSTORE_ALIAS)
      }
      .onErr { error ->
        // Cosmetic leftovers. The key itself is already safe on the new wrapping key.
        logcat(ERROR) { "Could not clear the legacy wrapping key: ${error.asLog()}" }
      }
  }

  suspend fun generateKeystoreWrappedEd25519Key(requireAuthentication: Boolean) =
    withContext(Dispatchers.IO) {
      delete()

      // Generate the ed25519 key pair and encrypt the private key.
      val keyPair = net.i2p.crypto.eddsa.KeyPairGenerator().generateKeyPair()
      writeWrappedPrivateKey(
        (keyPair.private as EdDSAPrivateKey).seed,
        requireAuthentication,
        privateKeyFile,
      )

      // Write public key in SSH format to .ssh_key.pub.
      publicKeyFile.writeText(toSshPublicKey(keyPair.public))

      type = Type.KeystoreWrappedEd25519
    }

  fun generateKeystoreNativeKey(algorithm: Algorithm, requireAuthentication: Boolean) {
    delete()

    // Generate Keystore-backed private key.
    val parameterSpec =
      KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN).run {
        apply(algorithm.applyToSpec)
        if (requireAuthentication) {
          setUserAuthenticationRequired(true)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(30, KeyProperties.AUTH_DEVICE_CREDENTIAL)
          } else {
            @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(30)
          }
        }
        build()
      }
    val keyPair =
      KeyPairGenerator.getInstance(algorithm.algorithm, PROVIDER_ANDROID_KEY_STORE).run {
        initialize(parameterSpec)
        generateKeyPair()
      }

    // Write public key in SSH format to .ssh_key.pub.
    publicKeyFile.writeText(toSshPublicKey(keyPair.public))

    type = Type.KeystoreNative
  }

  fun provide(client: SSHClient, passphraseFinder: InteractivePasswordFinder): KeyProvider? =
    when (type) {
      // Loaded from memory rather than by path: the file is ciphertext now, and sshj would
      // otherwise be handed a payload it cannot parse.
      Type.LegacyGenerated,
      Type.Imported -> client.loadKeys(readImportedPrivateKey(), null, passphraseFinder)
      Type.KeystoreNative -> KeystoreNativeKeyProvider
      Type.KeystoreWrappedEd25519 -> KeystoreWrappedEd25519KeyProvider
      null -> null
    }

  private object KeystoreNativeKeyProvider : KeyProvider {

    override fun getPublic(): PublicKey =
      runCatching { androidKeystore.sshPublicKey!! }
        .getOrElse { error ->
          logcat { error.asLog() }
          throw IOException(
            "Failed to get public key '$KEYSTORE_ALIAS' from Android Keystore",
            error,
          )
        }

    override fun getPrivate(): PrivateKey =
      runCatching { androidKeystore.sshPrivateKey!! }
        .getOrElse { error ->
          logcat { error.asLog() }
          throw IOException(
            "Failed to access private key '$KEYSTORE_ALIAS' from Android Keystore",
            error,
          )
        }

    override fun getType(): KeyType = KeyType.fromKey(public)
  }

  private object KeystoreWrappedEd25519KeyProvider : KeyProvider {

    override fun getPublic(): PublicKey =
      runCatching { parseSshPublicKey(sshPublicKey!!)!! }
        .getOrElse { error ->
          logcat { error.asLog() }
          throw IOException("Failed to get the public key for wrapped ed25519 key", error)
        }

    override fun getPrivate(): PrivateKey =
      runCatching {
          // Keys written before the move off androidx.security still need re-wrapping. This is
          // a no-op once done, and leaves the legacy key untouched if it cannot complete.
          migrateWrappedEd25519Key()
          val rawPrivateKey = readWrappedPrivateKey()
          EdDSAPrivateKey(
            EdDSAPrivateKeySpec(rawPrivateKey, EdDSANamedCurveTable.ED_25519_CURVE_SPEC)
          )
        }
        .getOrElse { error ->
          logcat { error.asLog() }
          throw IOException("Failed to unwrap wrapped ed25519 key", error)
        }

    override fun getType(): KeyType = KeyType.fromKey(public)
  }
}
