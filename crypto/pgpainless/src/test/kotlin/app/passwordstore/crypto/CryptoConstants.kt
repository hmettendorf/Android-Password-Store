/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

object CryptoConstants {
  const val KEY_PASSPHRASE = "hunter2"
  const val PLAIN_TEXT = "encryption worthy content"
  const val KEY_NAME = "John Doe"
  const val KEY_EMAIL = "john.doe@example.com"
  const val KEY_ID = 0x08edf7567183ce27

  /**
   * Primary key ID of the multiple-identities fixture, the second key in `multiple_public_keys`.
   */
  const val MULTIPLE_IDENTITIES_KEY_ID = -0x46af51d7ec7bea7bL // 0xb950ae2813841585

  /** The encryption subkey of the same ring, which `.gpg-id` files may name directly. */
  const val SUBKEY_ID = -0x304a91db5c65bdddL // 0xcfb56e24a39a4223
}
