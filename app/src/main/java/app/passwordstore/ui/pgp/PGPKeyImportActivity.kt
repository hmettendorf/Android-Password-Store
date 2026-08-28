/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package app.passwordstore.ui.pgp

import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils.splitKeyring
import app.passwordstore.crypto.KeyUtils.tryGetId
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.errors.InvalidKeyException
import app.passwordstore.crypto.errors.KeyAlreadyExistsException
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrapError
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.runBlocking

@AndroidEntryPoint
class PGPKeyImportActivity : AppCompatActivity() {

  /**
   * A [ByteArray] containing the contents of the previously selected file. This is necessary for
   * the replacement case where we do not want users to have to pick the file again.
   */
  private var lastBytes: ByteArray? = null

  /** Error from a key that was skipped while others imported, reported alongside the successes. */
  private var pendingError: Throwable? = null
  @Inject lateinit var keyManager: PGPKeyManager

  private val pgpKeyImportAction =
    registerForActivityResult(OpenDocument()) { uri ->
      runCatching {
          if (uri == null) {
            return@runCatching null
          }
          val keyInputStream =
            contentResolver.openInputStream(uri)
              ?: throw IllegalStateException("Failed to open selected file")
          val bytes = keyInputStream.use { `is` -> `is`.readBytes() }
          importKeys(bytes, false)
        }
        .run(::handleImportResult)
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    pgpKeyImportAction.launch(arrayOf("*/*"))
  }

  override fun onDestroy() {
    lastBytes = null
    pendingError = null
    super.onDestroy()
  }

  /**
   * Imports every key in the selected file.
   *
   * `gpg --export` emits the keys it was asked for as one concatenated block, so a file frequently
   * holds several. Handing the whole block to [PGPKeyManager] as a single [PGPKey] stored it under
   * the first key's ID and left the rest unreachable, which looked like a successful import of one
   * key rather than the partial import it was.
   */
  private fun importKeys(bytes: ByteArray, replace: Boolean): List<PGPKey>? {
    lastBytes = bytes
    val keys = splitKeyring(PGPKey(bytes))
    if (keys.isEmpty()) throw InvalidKeyException
    val imported = mutableListOf<PGPKey>()
    var firstError: Throwable? = null
    keys.forEach { key ->
      val (importedKey, error) = runBlocking { keyManager.addKey(key, replace = replace) }
      when {
        importedKey != null -> imported.add(importedKey)
        // Keep going: one key already being present should not hide the others, and the
        // replace prompt is offered once for the whole file.
        error != null && firstError == null -> firstError = error
      }
    }
    if (replace) {
      lastBytes = null
    }
    // Only fail the import outright if nothing landed; a partial success is reported as one.
    if (imported.isEmpty()) throw firstError ?: InvalidKeyException
    pendingError = firstError
    return imported
  }

  private fun handleImportResult(result: Result<List<PGPKey>?, Throwable>) {
    if (result.isOk) {
      val keys = result.getOrThrow()
      if (keys == null) {
        setResult(RESULT_CANCELED)
        finish()
        // This return convinces Kotlin that the control flow for `keys == null` definitely
        // terminates here and allows for a smart cast below.
        return
      }
      val keyIds = keys.joinToString(separator = "\n") { key -> "${tryGetId(key)}" }
      val skipped = pendingError
      pendingError = null
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_import_succeeded))
        .setMessage(
          if (skipped != null) {
            getString(
              R.string.pgp_key_import_partial_message,
              keys.size,
              keyIds,
              skipped.message ?: skipped.javaClass.simpleName,
            )
          } else {
            getString(R.string.pgp_key_import_succeeded_message, keyIds)
          }
        )
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_OK)
          finish()
        }
        .setCancelable(false)
        .show()
    } else {
      val error = result.unwrapError()
      if (error is KeyAlreadyExistsException && lastBytes != null) {
        MaterialAlertDialogBuilder(this)
          .setTitle(getString(R.string.pgp_key_import_failed))
          .setMessage(getString(R.string.pgp_key_import_failed_replace_message))
          .setPositiveButton(R.string.dialog_yes) { _, _ ->
            handleImportResult(runCatching { importKeys(lastBytes!!, replace = true) })
          }
          .setNegativeButton(R.string.dialog_no) { _, _ -> finish() }
          .setCancelable(false)
          .show()
      } else {
        MaterialAlertDialogBuilder(this)
          .setTitle(getString(R.string.pgp_key_import_failed))
          .setMessage(error.message)
          .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
          .setCancelable(false)
          .show()
      }
    }
  }
}
