/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
plugins {
  id("com.github.android-password-store.git-hooks")
  id("com.github.android-password-store.kotlin-common")
  id("com.github.android-password-store.spotless")
  id("com.github.android-password-store.versions")
  alias(libs.plugins.dokka)
}

// The root project owns the aggregated publication: each module below contributes its own
// module docs, and Dokka stitches them into one cross-linked site under build/dokka/html.
// :app is an application rather than a published surface, and :sentry-stub only mirrors a
// third-party API, so neither is documented.
dependencies {
  dokka(projects.autofillParser)
  dokka(projects.coroutineUtils)
  dokka(projects.crypto.common)
  dokka(projects.crypto.pgpainless)
  dokka(projects.format.common)
  dokka(projects.passgen.diceware)
  dokka(projects.passgen.random)
}

dokka { moduleName.set("Android Password Store") }
