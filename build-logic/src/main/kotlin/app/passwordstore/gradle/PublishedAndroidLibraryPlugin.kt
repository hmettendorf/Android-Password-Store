/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:Suppress("UnstableApiUsage")

package app.passwordstore.gradle

import com.vanniktech.maven.publish.AndroidMultiVariantLibrary
import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.MavenPublishBasePlugin
import me.tylerbwong.gradle.metalava.extension.MetalavaExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure

@Suppress("Unused")
class PublishedAndroidLibraryPlugin : Plugin<Project> {

  override fun apply(project: Project) {
    project.plugins.run {
      apply(LibraryPlugin::class)
      apply(MavenPublishBasePlugin::class)
      apply("me.tylerbwong.gradle.metalava")
    }
    project.extensions.configure<MavenPublishBaseExtension> {
      publishToMavenCentral(true)
      if (project.providers.environmentVariable("CI").isPresent) {
        signAllPublications()
      }
      configure(AndroidMultiVariantLibrary(sourcesJar = true, publishJavadocJar = true))
      pomFromGradleProperties()
    }
    project.extensions.configure<MetalavaExtension> {
      inputKotlinNulls.set(true)
      // reportLintsAsErrors is not set: it passes --lints-as-errors, which metalava dropped by
      // 1.0.0-alpha14 (the version this plugin resolves). --warnings-as-errors still covers the
      // lints that are reported as warnings.
      reportWarningsAsErrors.set(true)
    }
  }
}
