/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:Suppress("UnstableApiUsage")

package app.passwordstore.gradle

import app.passwordstore.gradle.flavors.FlavorDimensions
import app.passwordstore.gradle.flavors.ProductFlavors
import app.passwordstore.gradle.signing.configureBuildSigning
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.gradle.AppPlugin
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure

@Suppress("Unused")
class ApplicationPlugin : Plugin<Project> {

  override fun apply(project: Project) {
    project.pluginManager.apply(AppPlugin::class)
    AndroidCommon.configure(project)
    val minifySwitch = project.providers.environmentVariable("DISABLE_MINIFY")
    project.extensions.configure<ApplicationExtension> {
      dependenciesInfo {
        includeInBundle = false
        includeInApk = false
      }

      buildFeatures {
        viewBinding = true
        buildConfig = true
      }

      buildTypes {
        named("release") {
          isMinifyEnabled = !minifySwitch.isPresent
          setProguardFiles(
            listOf(
              "proguard-android-optimize.txt",
              "proguard-rules.pro",
              "proguard-rules-missing-classes.pro",
            )
          )
          buildConfigField("boolean", "ENABLE_DEBUG_FEATURES", "${project.isSnapshot()}")
        }
        named("debug") {
          applicationIdSuffix = ".debug"
          versionNameSuffix = "-debug"
          isMinifyEnabled = false
          buildConfigField("boolean", "ENABLE_DEBUG_FEATURES", "true")
        }
      }

      flavorDimensions.add(FlavorDimensions.FREE)
      productFlavors {
        register(ProductFlavors.FREE) {}
        register(ProductFlavors.NON_FREE) {}
      }

      project.configureBuildSigning()
    }
  }

  /**
   * Whether this is a snapshot build, which ships debug features in a release-type build.
   *
   * Deliberately keyed off an explicit opt-in only. This used to also trigger on GITHUB_WORKFLOW,
   * which GitHub Actions sets for every job -- so any release build produced by any workflow
   * silently enabled debug logging.
   */
  private fun Project.isSnapshot(): Boolean = providers.environmentVariable("SNAPSHOT").isPresent
}
