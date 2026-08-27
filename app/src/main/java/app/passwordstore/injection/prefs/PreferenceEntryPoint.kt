/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.injection.prefs

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent

/**
 * Reaches the injected preference stores from objects Hilt cannot construct, such as `SshKey`.
 *
 * This exists so that every reader of a store goes through the single provider in
 * [PreferenceModule]. Opening a second, independently configured instance of an encrypted store is
 * how data ends up half-migrated.
 */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface PreferenceEntryPoint {

  @GitPreferences fun gitPreferences(): SharedPreferences

  companion object {

    fun gitPreferences(context: Context): SharedPreferences =
      EntryPointAccessors.fromApplication(
          context.applicationContext,
          PreferenceEntryPoint::class.java,
        )
        .gitPreferences()
  }
}
