/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PGPIdentifierTest {

  @Test
  fun parseHexKeyIdWithout0xPrefix() {
    val identifier = PGPIdentifier.fromString("79E8208280490C77")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.KeyId }
  }

  @Test
  fun parseHexKeyId() {
    val identifier = PGPIdentifier.fromString("0x79E8208280490C77")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.KeyId }
  }

  @Test
  fun parseValidEmail() {
    val identifier = PGPIdentifier.fromString("john.doe@example.org")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.UserId }
  }

  @Test
  fun parseEmailWithoutTLD() {
    val identifier = PGPIdentifier.fromString("john.doe@example")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.UserId }
  }

  @Test
  fun parseHexKeyIdWithExactKeyMarker() {
    // GnuPG's "use exactly this key" suffix, which `pass init` writes into .gpg-id verbatim.
    val identifier = PGPIdentifier.fromString("0xCA14231C6693C21B!")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.KeyId }
    assertEquals(PGPIdentifier.fromString("0xCA14231C6693C21B"), identifier)
  }

  @Test
  fun parseHexKeyIdWithExactKeyMarkerAndNoPrefix() {
    val identifier = PGPIdentifier.fromString("CA14231C6693C21B!")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.KeyId }
  }

  @Test
  fun parseFingerprintWithExactKeyMarker() {
    val identifier = PGPIdentifier.fromString("0x664A43D961C06C46C722954F116A520B0F5E7BBA!")
    assertNotNull(identifier)
    assertTrue { identifier is PGPIdentifier.KeyId }
    assertEquals(PGPIdentifier.fromString("0x664A43D961C06C46C722954F116A520B0F5E7BBA"), identifier)
  }

  @Test
  fun exactKeyMarkerDoesNotRescueAMalformedId() {
    // Stripping the marker must not turn a 15-digit id into a valid one.
    assertNull(PGPIdentifier.fromString("0xCA14231C6693C2!"))
  }

  @Test
  fun userIdIsNotAffectedByExactKeyMarkerHandling() {
    val identifier = PGPIdentifier.fromString("john.doe@example.org")
    assertNotNull(identifier)
    assertEquals(PGPIdentifier.UserId("john.doe@example.org"), identifier)
  }
}
