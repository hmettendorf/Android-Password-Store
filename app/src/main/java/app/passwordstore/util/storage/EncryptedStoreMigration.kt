/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import logcat.LogPriority.ERROR
import logcat.LogPriority.INFO
import logcat.asLog
import logcat.logcat

/**
 * One-time copy of a store from the deprecated `androidx.security.crypto`
 * `EncryptedSharedPreferences` into an [EncryptedPreferences] backed by DataStore and the Android
 * Keystore.
 *
 * Each migration is idempotent and safe to re-run: it is a no-op once the legacy file is gone, and
 * the legacy file is only deleted after the copied values have been read back successfully. A
 * failure leaves the legacy data in place so the next launch can retry.
 */
object EncryptedStoreMigration {

  /**
   * Copies [storeName] from the legacy encrypted store into [target].
   *
   * Returns true if a migration ran, false if there was nothing to do.
   */
  fun migrate(context: Context, storeName: String, target: EncryptedPreferences): Boolean {
    if (!legacyFileExists(context, storeName)) return false

    return runCatching {
        val legacy = openLegacy(context, storeName)
        val entries = legacy.all
        if (entries.isEmpty()) {
          deleteLegacy(context, storeName)
          return@runCatching true
        }

        target.edit {
          entries.forEach { (key, value) ->
            when (value) {
              is String -> putString(key, value)
              is Int -> putInt(key, value)
              is Long -> putLong(key, value)
              is Float -> putFloat(key, value)
              is Boolean -> putBoolean(key, value)
              is Set<*> -> putStringSet(key, value.filterIsInstance<String>().toSet())
              else -> logcat(ERROR) { "Skipping '$key': unsupported type ${value?.javaClass}" }
            }
          }
        }

        // Only drop the old copy once the new one reads back with the same number of entries.
        val migrated = target.all
        check(migrated.size >= entries.size) {
          "Migrated ${migrated.size} of ${entries.size} entries for '$storeName'"
        }
        legacy.edit { clear() }
        deleteLegacy(context, storeName)
        logcat(INFO) { "Migrated ${entries.size} entries from legacy store '$storeName'" }
        true
      }
      .getOrElse { error ->
        // Leave the legacy file alone so the next launch retries rather than losing the data.
        logcat(ERROR) { "Migration of '$storeName' failed, will retry: ${error.asLog()}" }
        false
      }
  }

  /**
   * Copies a legacy encrypted store into ordinary [target] preferences, for data that never needed
   * encrypting. [target] must not be backed by the same file as [storeName].
   */
  fun migrateToPlain(context: Context, storeName: String, target: SharedPreferences): Boolean {
    if (!legacyFileExists(context, storeName)) return false

    return runCatching {
        val entries = openLegacy(context, storeName).all
        target.edit {
          entries.forEach { (key, value) ->
            when (value) {
              is String -> putString(key, value)
              is Int -> putInt(key, value)
              is Long -> putLong(key, value)
              is Float -> putFloat(key, value)
              is Boolean -> putBoolean(key, value)
              is Set<*> -> putStringSet(key, value.filterIsInstance<String>().toSet())
              else -> logcat(ERROR) { "Skipping '$key': unsupported type ${value?.javaClass}" }
            }
          }
        }
        deleteLegacy(context, storeName)
        logcat(INFO) { "Migrated ${entries.size} entries from '$storeName' to plain preferences" }
        true
      }
      .getOrElse { error ->
        // These are defaults, not secrets. Drop the unreadable file rather than retrying forever.
        logcat(ERROR) { "Could not migrate '$storeName', dropping: ${error.asLog()}" }
        deleteLegacy(context, storeName)
        false
      }
  }

  /**
   * Discards a legacy store without copying it. Used for caches, where re-populating costs the user
   * one prompt and is cheaper than carrying migration code.
   */
  fun discard(context: Context, storeName: String) {
    if (!legacyFileExists(context, storeName)) return
    runCatching {
        openLegacy(context, storeName).edit { clear() }
        deleteLegacy(context, storeName)
        logcat(INFO) { "Discarded legacy cache store '$storeName'" }
      }
      .onFailure { error ->
        // The file is unreadable, which for a cache is not worth recovering from -- drop it.
        logcat(ERROR) { "Could not open legacy '$storeName', deleting: ${error.asLog()}" }
        deleteLegacy(context, storeName)
      }
  }

  // androidx.security:security-crypto is deprecated; this is the read side of the migration away
  // from it and is deleted once the deprecation window closes.
  @Suppress("DEPRECATION")
  private fun openLegacy(context: Context, storeName: String): SharedPreferences {
    val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    return EncryptedSharedPreferences.create(
      context,
      storeName,
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
  }

  private fun legacyFile(context: Context, storeName: String) =
    java.io.File(context.applicationInfo.dataDir, "shared_prefs/$storeName.xml")

  private fun legacyFileExists(context: Context, storeName: String) =
    legacyFile(context, storeName).isFile

  private fun deleteLegacy(context: Context, storeName: String) {
    legacyFile(context, storeName).delete()
  }
}
