/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.Context
import androidx.core.content.edit
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.storage.EncryptedPreferences
import app.passwordstore.util.storage.EncryptedStoreMigration
import app.passwordstore.util.storage.KeyUnusableException
import app.passwordstore.util.storage.KeystoreCipher
import javax.inject.Inject
import kotlinx.coroutines.withContext
import logcat.LogPriority.INFO
import logcat.logcat

/**
 * A rudimentary cache for GPG passphrases, encrypted with an authentication-bound Android Keystore
 * key.
 *
 * The key requires user authentication and stays usable for [AUTH_VALIDITY_SECONDS] afterwards,
 * matching the `MasterKey` this replaced.
 *
 * Because this is only ever a cache it is never migrated: the legacy store is discarded on first
 * use, and an invalidated key clears the cache instead of surfacing an error. The cost of being
 * wrong here is one extra passphrase prompt.
 */
class PGPPassphraseCache @Inject constructor(private val dispatcherProvider: DispatcherProvider) {

  @Volatile private var store: EncryptedPreferences? = null

  suspend fun cachePassphrase(context: Context, identifier: PGPIdentifier, passphrase: String) {
    withContext(dispatcherProvider.io()) {
      recoveringFromInvalidKey(context) { it.edit { putString(identifier.toString(), passphrase) } }
    }
  }

  suspend fun retrieveCachedPassphrase(context: Context, identifier: PGPIdentifier): String? {
    return withContext(dispatcherProvider.io()) {
      recoveringFromInvalidKey(context) { it.getString(identifier.toString()) }
    }
  }

  suspend fun clearCachedPassphrase(context: Context, identifier: PGPIdentifier) {
    withContext(dispatcherProvider.io()) {
      recoveringFromInvalidKey(context) { it.edit { remove(identifier.toString()) } }
    }
  }

  suspend fun clearAllCachedPassphrases(context: Context) {
    withContext(dispatcherProvider.io()) {
      recoveringFromInvalidKey(context) { it.edit { clear() } }
    }
  }

  /**
   * Runs [block] against the cache; on [KeyUnusableException] drops the cache and retries once.
   *
   * The key is invalidated whenever the user changes their device credential or re-enrolls
   * biometrics. For a cache that is a routine event, not an error.
   */
  private fun <T> recoveringFromInvalidKey(
    context: Context,
    block: (EncryptedPreferences) -> T,
  ): T =
    try {
      block(getStore(context))
    } catch (e: KeyUnusableException) {
      logcat(INFO) { "Passphrase cache key was invalidated, starting a fresh cache" }
      resetStore(context)
      block(getStore(context))
    }

  private fun getStore(context: Context): EncryptedPreferences =
    store
      ?: synchronized(this) {
        store
          ?: createStore(context).also {
            EncryptedStoreMigration.discard(context, LEGACY_STORE_NAME)
            store = it
          }
      }

  private fun resetStore(context: Context) {
    synchronized(this) {
      KeystoreCipher(context, KEY_ALIAS).deleteKey()
      store = null
    }
  }

  private fun createStore(context: Context) =
    EncryptedPreferences(
      context = context,
      storeName = STORE_NAME,
      cipher =
        KeystoreCipher(
          context = context,
          alias = KEY_ALIAS,
          requireUserAuthentication = true,
          authValidityDurationSeconds = AUTH_VALIDITY_SECONDS,
          preferStrongBox = true,
        ),
    )

  private companion object {

    private const val STORE_NAME = "pgp_passphrase_cache"
    private const val KEY_ALIAS = "aps_passphrase_cache"
    private const val AUTH_VALIDITY_SECONDS = 60

    /** The `EncryptedSharedPreferences` file this cache used to live in. */
    private const val LEGACY_STORE_NAME = "androidx_passphrase_keyset_prefs"
  }
}
