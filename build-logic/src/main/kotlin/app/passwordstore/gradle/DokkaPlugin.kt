/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.gradle

import java.net.URI
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure
import org.jetbrains.dokka.gradle.DokkaExtension

/**
 * Applies Dokka to a library module and points every documented symbol back at its source on
 * GitHub. Applied to the modules aggregated by the root project's Dokka publication; the app is
 * deliberately not among them.
 */
@Suppress("Unused")
class DokkaPlugin : Plugin<Project> {

  override fun apply(project: Project) {
    project.pluginManager.apply("org.jetbrains.dokka")
    project.extensions.configure<DokkaExtension> {
      dokkaSourceSets.configureEach {
        // Undocumented declarations are still listed, so the site shows the real API
        // surface rather than only the parts that happen to carry KDoc.
        reportUndocumented.set(false)
        skipDeprecated.set(false)
        sourceLink {
          localDirectory.set(project.layout.projectDirectory.dir("src"))
          remoteUrl.set(
            URI(
              "$REPO_URL/tree/$SOURCE_LINK_REF/${project.path.removePrefix(":").replace(':', '/')}/src"
            )
          )
          remoteLineSuffix.set("#L")
        }
      }
    }
  }

  companion object {

    private const val REPO_URL = "https://github.com/hmettendorf/Android-Password-Store"

    /**
     * Branch the source links point at. A tag would pin links to the documented revision, but the
     * site is rebuilt from the branch on every push, so the branch is what actually matches.
     */
    private const val SOURCE_LINK_REF = "main"
  }
}
