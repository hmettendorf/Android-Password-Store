/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.proxy

import app.passwordstore.util.settings.GitSettings
import java.io.IOException
import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

/** Utility class for [Proxy] handling. */
@Singleton
class ProxyUtils @Inject constructor(private val gitSettings: GitSettings) {

  /** Set the default [Proxy] and [Authenticator] for the app based on user provided settings. */
  fun setDefaultProxy() {
    ProxySelector.setDefault(
      object : ProxySelector() {
        override fun select(uri: URI?): MutableList<Proxy> {
          val host = gitSettings.proxyHost
          val port = gitSettings.proxyPort
          return if (host == null || port == -1) {
            mutableListOf(Proxy.NO_PROXY)
          } else {
            mutableListOf(Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port)))
          }
        }

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) {
          require(uri == null || sa == null || ioe == null) { "Arguments can't be null." }
        }
      }
    )
    // The credentials are deliberately not mirrored into the http.proxyUser and
    // http.proxyPassword system properties. Those are process-global, outlive the setting that
    // produced them, and put the password somewhere every library in the process -- and every
    // heap dump -- can read it. The Authenticator below covers the same ground. Clearing them
    // here also cleans up after versions of the app that did set them.
    System.clearProperty(HTTP_PROXY_USER_PROPERTY)
    System.clearProperty(HTTP_PROXY_PASSWORD_PROPERTY)

    Authenticator.setDefault(
      object : Authenticator() {
        // Read on demand rather than captured, so the credentials are not held for the lifetime
        // of the process and a settings change takes effect immediately.
        override fun getPasswordAuthentication(): PasswordAuthentication? {
          if (requestorType != RequestorType.PROXY) return null
          val host = gitSettings.proxyHost ?: return null
          val port = gitSettings.proxyPort
          // Answer only for the proxy we were actually configured with. The default
          // Authenticator is consulted for every proxy any code in this process talks to.
          if (!host.equals(requestingHost, ignoreCase = true)) return null
          if (port != -1 && port != requestingPort) return null
          val user = gitSettings.proxyUsername?.takeIf { it.isNotEmpty() } ?: return null
          val password = gitSettings.proxyPassword?.takeIf { it.isNotEmpty() } ?: return null
          return PasswordAuthentication(user, password.toCharArray())
        }
      }
    )
  }

  companion object {
    private const val HTTP_PROXY_USER_PROPERTY = "http.proxyUser"
    private const val HTTP_PROXY_PASSWORD_PROPERTY = "http.proxyPassword"
  }
}
