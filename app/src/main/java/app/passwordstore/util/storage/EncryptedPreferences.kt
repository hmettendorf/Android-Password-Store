/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

/**
 * A [SharedPreferences] backed by DataStore, with every value encrypted by a Keystore-held AES-GCM
 * key. Replaces `androidx.security.crypto`'s `EncryptedSharedPreferences`.
 *
 * Presenting the [SharedPreferences] interface is deliberate: the app reads these settings
 * synchronously from property getters and view binding, and converting every one of those call
 * sites to a suspending API would spread this change across the UI layer. Persistence and
 * consistency come from DataStore; a warm in-memory snapshot serves the synchronous reads.
 *
 * **Key names are stored in plaintext.** The previous implementation encrypted them with AES-SIV.
 * Values -- the actual secrets -- remain encrypted. The names are structural (`proxy_password`,
 * `https_password`) rather than secret, and the store lives in app-private storage with
 * `android:allowBackup="false"`.
 */
class EncryptedPreferences(
  context: Context,
  storeName: String,
  private val cipher: KeystoreCipher,
  private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) : SharedPreferences {

  private val appContext = context.applicationContext
  private val name = storeName

  private val dataStore: DataStore<Preferences> =
    PreferenceDataStoreFactory.create(scope = scope) {
      appContext.preferencesDataStoreFile(storeName)
    }

  /** Decoded values, keyed by preference name. Authoritative for reads once warmed. */
  private val cache = ConcurrentHashMap<String, String>()

  @Volatile private var warmed = false

  init {
    scope.launch { warm() }
  }

  /**
   * Loads and decrypts the store into memory. Safe to call repeatedly. Synchronous readers block on
   * this only if they arrive before the background warm-up finishes.
   *
   * A failure that might succeed later -- the key is fine but the user's authentication window has
   * closed -- leaves the store un-warmed so the next read tries again. Only a permanent failure
   * settles the store into whatever could be read.
   */
  @Synchronized
  fun warm() {
    if (warmed) return
    val stored =
      runCatching { runBlocking { dataStore.data.first() } }
        .getOrElse { error ->
          logcat(ERROR) { "Failed to load encrypted store '$name': ${error.asLog()}" }
          return
        }

    val decoded = HashMap<String, String>(stored.asMap().size)
    val unreadable = mutableListOf<String>()
    for ((key, value) in stored.asMap()) {
      val encoded = value as? String ?: continue
      try {
        decoded[key.name] = decode(encoded)
      } catch (e: KeyAuthenticationRequiredException) {
        // Retryable. Warming now would cache an empty store for the life of the process.
        logcat(ERROR) { "Store '$name' is locked, deferring load: ${e.asLog()}" }
        return
      } catch (e: Throwable) {
        // A single unreadable entry must not take the whole store down with it.
        logcat(ERROR) { "Dropping unreadable entry '${key.name}': ${e.asLog()}" }
        unreadable += key.name
      }
    }

    cache.clear()
    cache.putAll(decoded)
    warmed = true
    if (unreadable.isNotEmpty()) {
      lostEntries = unreadable.toList()
      // Loud on purpose: these are credentials the user set and will now be silently asked for
      // again, which is otherwise indistinguishable from never having set them.
      logcat(ERROR) {
        "Store '$name' lost ${unreadable.size} entries to an unusable key: ${unreadable.joinToString()}"
      }
    }
  }

  /** Names of entries that existed but could not be decrypted during the last [warm]. */
  @Volatile
  var lostEntries: List<String> = emptyList()
    private set

  private fun ensureWarm() {
    if (!warmed) warm()
  }

  private fun encode(typed: String): String =
    Base64.encodeToString(cipher.encrypt(typed.toByteArray()), Base64.NO_WRAP)

  private fun decode(encoded: String): String =
    String(cipher.decrypt(Base64.decode(encoded, Base64.NO_WRAP)))

  private fun read(key: String, type: Char): String? {
    ensureWarm()
    val raw = cache[key] ?: return null
    return if (raw.length > 1 && raw[0] == type) raw.substring(1) else null
  }

  override fun getAll(): Map<String, *> {
    ensureWarm()
    return cache.mapValues { (_, raw) -> raw.drop(1) }
  }

  override fun getString(key: String, defValue: String?): String? =
    read(key, TYPE_STRING) ?: defValue

  override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
    read(key, TYPE_STRING_SET)?.let { raw ->
      if (raw.isEmpty()) emptySet() else raw.split(SET_SEPARATOR).toSet()
    } ?: defValues

  override fun getInt(key: String, defValue: Int): Int =
    read(key, TYPE_INT)?.toIntOrNull() ?: defValue

  override fun getLong(key: String, defValue: Long): Long =
    read(key, TYPE_LONG)?.toLongOrNull() ?: defValue

  override fun getFloat(key: String, defValue: Float): Float =
    read(key, TYPE_FLOAT)?.toFloatOrNull() ?: defValue

  override fun getBoolean(key: String, defValue: Boolean): Boolean =
    read(key, TYPE_BOOLEAN)?.toBooleanStrictOrNull() ?: defValue

  override fun contains(key: String): Boolean {
    ensureWarm()
    return cache.containsKey(key)
  }

  override fun edit(): SharedPreferences.Editor = Editor()

  /** No consumer of an encrypted store registers a listener; dispatching one would be a no-op. */
  override fun registerOnSharedPreferenceChangeListener(
    listener: SharedPreferences.OnSharedPreferenceChangeListener
  ) = Unit

  override fun unregisterOnSharedPreferenceChangeListener(
    listener: SharedPreferences.OnSharedPreferenceChangeListener
  ) = Unit

  /** Removes every value and the Keystore key behind them. */
  suspend fun destroy() {
    cache.clear()
    dataStore.edit { it.clear() }
    cipher.deleteKey()
  }

  private inner class Editor : SharedPreferences.Editor {

    private val puts = LinkedHashMap<String, String>()
    private val removes = LinkedHashSet<String>()
    private var clearRequested = false

    private fun put(key: String, type: Char, value: String) = apply {
      puts[key] = "$type$value"
      removes.remove(key)
    }

    override fun putString(key: String, value: String?) =
      if (value == null) remove(key) else put(key, TYPE_STRING, value)

    override fun putStringSet(key: String, values: Set<String>?) =
      if (values == null) remove(key)
      else put(key, TYPE_STRING_SET, values.joinToString(SET_SEPARATOR))

    override fun putInt(key: String, value: Int) = put(key, TYPE_INT, value.toString())

    override fun putLong(key: String, value: Long) = put(key, TYPE_LONG, value.toString())

    override fun putFloat(key: String, value: Float) = put(key, TYPE_FLOAT, value.toString())

    override fun putBoolean(key: String, value: Boolean) = put(key, TYPE_BOOLEAN, value.toString())

    override fun remove(key: String) = apply {
      removes.add(key)
      puts.remove(key)
    }

    override fun clear() = apply { clearRequested = true }

    override fun apply() {
      applyToCache()
      scope.launch { persist() }
    }

    override fun commit(): Boolean {
      applyToCache()
      return runCatching { runBlocking { persist() } }
        .onFailure { error ->
          logcat(ERROR) { "Failed to commit encrypted store: ${error.asLog()}" }
        }
        .isSuccess
    }

    /** Reads must observe the write immediately, exactly as SharedPreferences does. */
    private fun applyToCache() {
      ensureWarm()
      if (clearRequested) cache.clear()
      removes.forEach { cache.remove(it) }
      puts.forEach { (key, typed) -> cache[key] = typed }
    }

    private suspend fun persist() {
      dataStore.edit { prefs ->
        if (clearRequested) prefs.clear()
        removes.forEach { prefs.remove(stringPreferencesKey(it)) }
        puts.forEach { (key, typed) -> prefs[stringPreferencesKey(key)] = encode(typed) }
      }
    }
  }

  private companion object {

    private const val TYPE_STRING = 'S'
    private const val TYPE_STRING_SET = 'X'
    private const val TYPE_INT = 'I'
    private const val TYPE_LONG = 'L'
    private const val TYPE_FLOAT = 'F'
    private const val TYPE_BOOLEAN = 'B'

    /** Unit separator; cannot appear in a value that came from a text field. */
    private const val SET_SEPARATOR = "\u001F"
  }
}
