/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.injection.prefs

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.content.SharedPreferences
import app.passwordstore.BuildConfig
import app.passwordstore.util.storage.EncryptedPreferences
import app.passwordstore.util.storage.EncryptedStoreMigration
import app.passwordstore.util.storage.KeystoreCipher
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
class PreferenceModule {

  /**
   * Opens an [EncryptedPreferences] for [fileName], migrating the legacy
   * `EncryptedSharedPreferences` store of the same name on first use.
   *
   * Singleton rather than Reusable: each instance owns an in-memory cache and a DataStore handle,
   * and DataStore throws if two instances are created for the same file.
   */
  private fun encryptedPreferences(context: Context, fileName: String): SharedPreferences {
    val store =
      EncryptedPreferences(
        context = context,
        storeName = fileName,
        cipher = KeystoreCipher(context = context, alias = "aps_store_$fileName"),
      )
    EncryptedStoreMigration.migrate(context, fileName, store)
    return store
  }

  /**
   * Password generator settings hold no secrets -- word count, separator, character classes -- so
   * they live in ordinary preferences. Values are carried over from the encrypted store they used
   * to occupy; losing them would only restore defaults.
   */
  @[Provides PasswordGeneratorPreferences Singleton]
  fun providePwgenPreferences(@ApplicationContext context: Context): SharedPreferences {
    val prefs = context.getSharedPreferences(PWGEN_PREFERENCES, MODE_PRIVATE)
    EncryptedStoreMigration.migrateToPlain(context, LEGACY_PWGEN_PREFERENCES, prefs)
    return prefs
  }

  @[Provides SettingsPreferences Singleton]
  fun provideSettingsPreferences(@ApplicationContext context: Context): SharedPreferences {
    return context.getSharedPreferences("${BuildConfig.APPLICATION_ID}_preferences", MODE_PRIVATE)
  }

  @[Provides GitPreferences Singleton]
  fun provideGitPreferences(@ApplicationContext context: Context): SharedPreferences {
    return encryptedPreferences(context, GIT_PREFERENCES)
  }

  @[Provides ProxyPreferences Singleton]
  fun provideProxyPreferences(@ApplicationContext context: Context): SharedPreferences {
    return encryptedPreferences(context, PROXY_PREFERENCES)
  }

  companion object {

    /** Distinct from the legacy name so the plain file cannot alias the encrypted one. */
    const val PWGEN_PREFERENCES = "pwgen_settings"

    private const val LEGACY_PWGEN_PREFERENCES = "pwgen_preferences"
    const val GIT_PREFERENCES = "git_operation"
    const val PROXY_PREFERENCES = "http_proxy"
  }
}
