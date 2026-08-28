/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.crypto.errors.MissingRecipientKeysException
import app.passwordstore.util.coroutines.DispatcherProvider
import com.github.ivanshafran.sharedpreferencesmock.SPMockBuilder
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.rules.TemporaryFolder

@OptIn(ExperimentalCoroutinesApi::class)
class CryptoRepositoryTest {

  @get:Rule val tempFolder = TemporaryFolder()

  private val dispatcher = UnconfinedTestDispatcher()
  private val dispatcherProvider =
    object : DispatcherProvider {
      override fun main(): CoroutineDispatcher = dispatcher

      override fun mainImmediate(): CoroutineDispatcher = dispatcher

      override fun default(): CoroutineDispatcher = dispatcher

      override fun io(): CoroutineDispatcher = dispatcher

      override fun unconfined(): CoroutineDispatcher = dispatcher
    }

  /** The fixture key's primary ID; its ring is the only one the repository will know about. */
  private val knownKey = KeyId(0x08edf7567183ce27)
  private val unknownKey = KeyId(0x0123456789abcdef)

  private fun fixtureKey() =
    PGPKey(
      checkNotNull(CryptoRepositoryTest::class.java.getResourceAsStream("/public_key")).use {
        it.readBytes()
      }
    )

  /** A repository whose key manager holds the fixture key, and nothing else. */
  private suspend fun repositoryWithFixtureKey(): CryptoRepository {
    val keyManager = PGPKeyManager(tempFolder.root.path, dispatcher)
    keyManager.addKey(fixtureKey()).unwrap()
    return CryptoRepository(
      keyManager,
      PGPainlessCryptoHandler(),
      dispatcherProvider,
      SPMockBuilder().createSharedPreferences(),
    )
  }

  @Test
  fun encryptRefusesWhenARecipientCannotBeResolved() =
    runTest(dispatcher) {
      val repository = repositoryWithFixtureKey()

      val error =
        repository
          .encrypt(
            listOf(knownKey, unknownKey),
            "encryption worthy content".byteInputStream(),
            ByteArrayOutputStream(),
          )
          .unwrapError()

      // Encrypting to the subset that did resolve would look like a successful save while
      // locking the missing recipient out of the file.
      assertIs<MissingRecipientKeysException>(error)
      assertEquals(listOf(unknownKey.toString()), error.recipients)
    }

  @Test
  fun encryptWritesNothingWhenARecipientCannotBeResolved() =
    runTest(dispatcher) {
      val repository = repositoryWithFixtureKey()
      val out = ByteArrayOutputStream()

      repository
        .encrypt(listOf(knownKey, unknownKey), "content".byteInputStream(), out)
        .unwrapError()

      assertEquals(0, out.size())
    }

  @Test
  fun encryptSucceedsWhenEveryRecipientResolves() =
    runTest(dispatcher) {
      val repository = repositoryWithFixtureKey()
      val out = ByteArrayOutputStream()

      repository.encrypt(listOf(knownKey), "content".byteInputStream(), out).unwrap()

      assertEquals(true, out.size() > 0)
    }
}
