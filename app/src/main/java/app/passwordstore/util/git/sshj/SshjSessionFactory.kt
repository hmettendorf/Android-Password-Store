/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.git.operation.CredentialFinder
import app.passwordstore.util.settings.AuthMode
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.PublicKey
import java.util.Collections
import java.util.concurrent.TimeUnit
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.runBlocking
import logcat.LogPriority.WARN
import logcat.logcat
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer.PlainBuffer
import net.schmizz.sshj.common.DisconnectReason
import net.schmizz.sshj.common.SSHException
import net.schmizz.sshj.common.SSHRuntimeException
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.FingerprintVerifier
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.method.AuthPassword
import net.schmizz.sshj.userauth.method.AuthPublickey
import net.schmizz.sshj.userauth.password.PasswordFinder
import net.schmizz.sshj.userauth.password.Resource
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.RemoteSession
import org.eclipse.jgit.transport.SshSessionFactory
import org.eclipse.jgit.transport.URIish
import org.eclipse.jgit.util.FS

sealed class SshAuthMethod(val activity: AppCompatActivity) {
  class Password(activity: AppCompatActivity) : SshAuthMethod(activity)

  class SshKey(activity: AppCompatActivity) : SshAuthMethod(activity)
}

abstract class InteractivePasswordFinder(private val dispatcherProvider: DispatcherProvider) :
  PasswordFinder {

  private var isRetry = false

  abstract fun askForPassword(cont: Continuation<String?>, isRetry: Boolean)

  override fun reqPassword(resource: Resource<*>?): CharArray {
    val password =
      runBlocking(dispatcherProvider.main()) {
        suspendCoroutine { cont -> askForPassword(cont, isRetry) }
      }
    isRetry = true
    return password?.toCharArray() ?: throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
  }

  final override fun shouldRetry(resource: Resource<*>?) = true
}

class SshjSessionFactory(
  private val authMethod: SshAuthMethod,
  private val hostKeyFile: File,
  private val dispatcherProvider: DispatcherProvider,
) : SshSessionFactory() {

  private var currentSession: SshjSession? = null

  override fun getSession(
    uri: URIish,
    credentialsProvider: CredentialsProvider?,
    fs: FS?,
    tms: Int,
  ): RemoteSession {
    return currentSession
      ?: SshjSession(uri, uri.user, authMethod, hostKeyFile, dispatcherProvider).connect().also {
        logcat { "New SSH connection created" }
        currentSession = it
      }
  }

  fun close() {
    currentSession?.close()
  }
}

/**
 * Asks the user to vouch for a host key the app has never seen before.
 *
 * Trust-on-first-use is only as good as that first use: whatever answers the very first connection
 * is pinned for every one that follows, so an attacker in the middle at that moment becomes the
 * server forever after. Showing the fingerprint is what turns that from a silent decision into one
 * the user actually makes.
 */
private suspend fun confirmHostKey(
  activity: AppCompatActivity,
  hostname: String?,
  port: Int,
  fingerprint: String,
): Boolean = suspendCoroutine { cont ->
  var resumed = false
  fun resumeOnce(trusted: Boolean) {
    if (!resumed) {
      resumed = true
      cont.resume(trusted)
    }
  }
  val host = if (port in 1..65535 && port != 22) "$hostname:$port" else "$hostname"
  MaterialAlertDialogBuilder(activity)
    .setTitle(R.string.host_key_verification_title)
    .setMessage(activity.getString(R.string.host_key_verification_message, host, fingerprint))
    .setPositiveButton(R.string.host_key_verification_trust) { _, _ -> resumeOnce(true) }
    .setNegativeButton(R.string.dialog_cancel) { _, _ -> resumeOnce(false) }
    .setOnCancelListener { resumeOnce(false) }
    .setOnDismissListener { resumeOnce(false) }
    .show()
}

private fun makeTofuHostKeyVerifier(
  hostKeyFile: File,
  authMethod: SshAuthMethod,
  dispatcherProvider: DispatcherProvider,
): HostKeyVerifier {
  if (!hostKeyFile.exists()) {
    return object : HostKeyVerifier {
      override fun verify(hostname: String?, port: Int, key: PublicKey?): Boolean {
        val digest =
          runCatching { SecurityUtils.getMessageDigest("SHA-256") }
            .getOrElse { e -> throw SSHRuntimeException(e) }
        digest.update(PlainBuffer().putPublicKey(key).compactData)
        val digestData = digest.digest()
        val hostKeyEntry = "SHA256:${Base64.encodeToString(digestData, Base64.NO_WRAP)}"
        val trusted =
          runBlocking(dispatcherProvider.main()) {
            confirmHostKey(authMethod.activity, hostname, port, hostKeyEntry)
          }
        if (!trusted) {
          logcat(SshjSessionFactory::class.java.simpleName, WARN) {
            "User declined unknown host key: $hostKeyEntry"
          }
          return false
        }
        logcat(SshjSessionFactory::class.java.simpleName) {
          "Trusting host key on first use: $hostKeyEntry"
        }
        hostKeyFile.writeText(hostKeyEntry)
        return true
      }

      override fun findExistingAlgorithms(hostname: String?, port: Int): MutableList<String> {
        return Collections.emptyList()
      }
    }
  } else {
    val hostKeyEntry = hostKeyFile.readText()
    logcat(SshjSessionFactory::class.java.simpleName) { "Pinned host key: $hostKeyEntry" }
    return FingerprintVerifier.getInstance(hostKeyEntry)
  }
}

private class SshjSession(
  uri: URIish,
  private val username: String,
  private val authMethod: SshAuthMethod,
  private val hostKeyFile: File,
  private val dispatcherProvider: DispatcherProvider,
) : RemoteSession {

  private lateinit var ssh: SSHClient
  private var currentCommand: Session? = null

  private val uri =
    if (uri.host.contains('@')) {
      // URIish's String constructor cannot handle '@' in the user part of the URI and the URL
      // constructor can't be used since Java's URL does not recognize the ssh scheme. We thus
      // need to patch everything up ourselves.
      logcat { "Before fixup: user=${uri.user}, host=${uri.host}" }
      val userPlusHost = "${uri.user}@${uri.host}"
      val realUser = userPlusHost.substringBeforeLast('@')
      val realHost = userPlusHost.substringAfterLast('@')
      uri.setUser(realUser).setHost(realHost).also {
        logcat { "After fixup: user=${it.user}, host=${it.host}" }
      }
    } else {
      uri
    }

  fun connect(): SshjSession {
    ssh = SSHClient(SshjConfig())
    ssh.addHostKeyVerifier(makeTofuHostKeyVerifier(hostKeyFile, authMethod, dispatcherProvider))
    ssh.connect(uri.host, uri.port.takeUnless { it == -1 } ?: 22)
    if (!ssh.isConnected) throw IOException()
    val passwordAuth =
      AuthPassword(CredentialFinder(authMethod.activity, AuthMode.Password, dispatcherProvider))
    when (authMethod) {
      is SshAuthMethod.Password -> {
        ssh.auth(username, passwordAuth)
      }
      is SshAuthMethod.SshKey -> {
        val pubkeyAuth =
          AuthPublickey(
            SshKey.provide(
              ssh,
              CredentialFinder(authMethod.activity, AuthMode.SshKey, dispatcherProvider),
            )
          )
        ssh.auth(username, pubkeyAuth, passwordAuth)
      }
    }
    return this
  }

  override fun exec(commandName: String?, timeout: Int): Process {
    if (currentCommand != null) {
      logcat(WARN) { "Killing old command" }
      disconnect()
    }
    val session = ssh.startSession()
    currentCommand = session
    return SshjProcess(session.exec(commandName), timeout.toLong())
  }

  /**
   * Kills the current command if one is running and returns the session into a state where `exec`
   * can be called.
   *
   * Note that this does *not* disconnect the session. Unfortunately, the function has to be called
   * `disconnect` to override the corresponding abstract function in `RemoteSession`.
   */
  override fun disconnect() {
    currentCommand?.close()
    currentCommand = null
  }

  fun close() {
    disconnect()
    ssh.close()
  }
}

private class SshjProcess(private val command: Session.Command, private val timeout: Long) :
  Process() {

  override fun waitFor(): Int {
    command.join(timeout, TimeUnit.SECONDS)
    command.close()
    return exitValue()
  }

  override fun destroy() = command.close()

  override fun getOutputStream(): OutputStream = command.outputStream

  override fun getErrorStream(): InputStream = command.errorStream

  override fun exitValue(): Int = command.exitStatus

  override fun getInputStream(): InputStream = command.inputStream
}
