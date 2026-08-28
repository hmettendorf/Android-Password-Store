/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import org.bouncycastle.openpgp.PGPKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.key.parsing.KeyRingReader

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {
  /**
   * Attempts to parse a [PGPKeyRing] from a given [key]. The key is first tried as a secret key and
   * then as a public one before the method gives up and returns null.
   */
  public fun tryParseKeyring(key: PGPKey): PGPKeyRing? {
    return runCatching { KeyRingReader.readKeyRing(key.contents.inputStream()) }.get()
  }

  /** Parses a [PGPKeyRing] from the given [key] and calculates its long key ID */
  public fun tryGetId(key: PGPKey): KeyId? {
    val keyRing = tryParseKeyring(key) ?: return null
    return KeyId(keyRing.publicKey.keyID)
  }

  /**
   * Splits [key] into one [PGPKey] per keyring it contains.
   *
   * `gpg --export` concatenates every key it was asked for into a single block, so a file picked
   * for import routinely holds several. [tryParseKeyring] reads only the first keyring in a stream,
   * which would import one key and drop the rest without saying so.
   */
  public fun splitKeyring(key: PGPKey): List<PGPKey> {
    val collection =
      runCatching { KeyRingReader.readKeyRingCollection(key.contents.inputStream(), true) }.get()
        ?: return emptyList()
    val keyRings = buildList {
      collection.getPGPSecretKeyRingCollection().forEach { ring -> add(ring) }
      collection.getPgpPublicKeyRingCollection().forEach { ring -> add(ring) }
    }
    return keyRings.map { keyRing -> PGPKey(keyRing.encoded) }
  }

  /**
   * Every key ID in [key]'s ring: the primary key's, and each subkey's.
   *
   * `pass` and `gopass` write `.gpg-id` entries through from GnuPG verbatim, and GnuPG names
   * whichever key the user pinned -- frequently an encryption subkey rather than the primary. A
   * lookup that only compares [tryGetId] therefore fails to find keys that are in fact present.
   */
  public fun tryGetAllIds(key: PGPKey): List<KeyId> {
    val keyRing = tryParseKeyring(key) ?: return emptyList()
    return keyRing.publicKeys.asSequence().map { publicKey -> KeyId(publicKey.keyID) }.toList()
  }

  /**
   * Attempts to parse the given [PGPKey] into a [PGPKeyRing] and obtains the [UserId] of the
   * corresponding public key.
   */
  public fun tryGetEmail(key: PGPKey): UserId? {
    val keyRing = tryParseKeyring(key) ?: return null
    return UserId(keyRing.publicKey.userIDs.next())
  }

  /**
   * Tests if the given [key] can be used for encryption, which is a bare minimum necessity for the
   * app.
   *
   * A sign-only key -- an Ed25519 primary with no encryption subkey, say -- is not usable here: no
   * password can ever be encrypted to it, so accepting one only defers the failure to decryption
   * time where it is far harder to explain.
   */
  public fun isKeyUsable(key: PGPKey): Boolean {
    val keyRing = tryParseKeyring(key) ?: return false
    return runCatching { PGPainless.inspectKeyRing(keyRing).isUsableForEncryption }.get() == true
  }
}
