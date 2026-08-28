# Password Store

[![CI](https://github.com/hmettendorf/Android-Password-Store/actions/workflows/ci.yml/badge.svg)](https://github.com/hmettendorf/Android-Password-Store/actions/workflows/ci.yml)

## About this fork

This is a fork of [android-password-store/Android-Password-Store](https://github.com/android-password-store/Android-Password-Store), the Android client for [pass](https://www.passwordstore.org/). The original project [stopped development in October 2024](https://github.com/android-password-store/Android-Password-Store/discussions/3260) and its repository is archived. Everything here up to that point is the work of the original authors, under the same GPL-3.0 licence; this fork continues from where they left off.

It is an independent continuation, not an official successor, and it is not endorsed by or affiliated with the original maintainers. Please bring issues here rather than to the upstream repository — nobody is reading them there.

**It is signed with a different key than the original app.** Android will refuse to install it over an existing Password Store installation, and the two cannot be upgraded into one another. To switch, export your passwords first, or simply keep using your existing Git remote: this fork stores exactly the same GPG-encrypted files in exactly the same layout, so a fresh install can clone your store and carry on.

## What's new in this fork

Upstream development stopped in October 2024. This fork picks the project back up; the changes so far:

### Autofill

* **/e/OS Browser support.** `foundation.e.browser` is now a trusted browser, so Autofill matches on the site being visited instead of falling back to the browser's own package name.

### Git

* **Auto push.** Saving a password offers to push it to the remote straight away, instead of leaving the commit sitting locally until you next sync by hand. It covers edits as well as new entries, and applies wherever an entry is saved from — the password list, the decrypt screen, or an Autofill save prompt.

  **The push is always confirmed first** — publishing to a remote is not something the app does behind your back. The setting decides whether the offer is made at all: it is **on by default**, and can be turned off under **Settings → Passwords → Auto push**.

  Pushing uses the Git remote and authentication you have already configured, so an SSH key that asks for biometric unlock will still ask. Nothing happens if the store has no remote — a local-only store is left alone rather than reporting an error.

  A push that fails never costs you the entry. The password is committed before the push is attempted, so the commit simply stays local and goes out with your next push or sync; the error is shown so you know it is still pending. Declining a biometric prompt is treated as a decision, not a failure, and passes without a dialog.

### Encryption and storage

* **Jetpack Security replaced with the Android Keystore.** `androidx.security:security-crypto` is deprecated in full and pinned to a long-outdated Tink. Encrypted storage now sits on AES-GCM keys held directly in the Android Keystore, with DataStore for persistence, optional user-authentication binding and optional StrongBox. Existing data is migrated on first launch: the legacy store is only discarded after the new copy has been read back, and the keystore-wrapped SSH key is re-wrapped under a separate alias so a failure leaves the original untouched.
* **Passwords are encrypted for every recipient, or not at all.** Recipients in `.gpg-id` whose keys were not imported used to be dropped silently, producing an entry only the phone could read — and, on an edit, quietly revoking access others already had. Saving now fails with the missing recipients named. Entries naming a subkey rather than a primary key resolve correctly too, and importing a key file adds every key in it instead of only the first.
* **`.gpg-id` files using GnuPG's exact-key marker now work.** An entry such as `0xCA14231C6693C21B!` no longer invalidates the whole file and discards the other recipients in it.
* **Fewer latent crashes on empty input.** Password, OTP and git-credential fields no longer throw on a null editable; empty input is now read as an empty string.

### Build and tooling

* **Toolchain and dependencies brought forward.** Gradle 9.5.1, AGP 8.13.2, Kotlin 2.2.21, `compileSdk` 36, BouncyCastle 1.85, plus current AndroidX, Compose, Hilt and coroutines. `targetSdk` deliberately stays at 34, so there are no runtime behaviour changes from the upgrade itself.
* **API documentation, generated and published.** Dokka 2.2.0 aggregates the library modules -- `autofill-parser`, `coroutine-utils`, `crypto`, `format` and `passgen` -- into one cross-linked site, with every symbol linking back to its source line on GitHub. `docs.yml` builds it on each push and deploys to GitHub Pages through the artifact flow, so there is no `gh-pages` branch and no token to manage. Pull requests build the docs without deploying, so a broken build surfaces on the PR.
* **Dependency updates run themselves again.** Upstream's Renovate config was left behind without a bot to execute it. `renovate.yml` runs Renovate on a schedule from the repository itself, and validates the config on every PR that touches it. The config has been migrated to current Renovate, which removed `config:base`, `matchPackagePatterns` and `regexManagers`. Requires a `RENOVATE_TOKEN` secret.
* **CI that runs on a fork.** Every workflow used to depend on a reusable workflow in the now-archived upstream repository. `ci.yml` inlines those steps and runs Spotless, the unit tests, the API compatibility check and both debug APK builds without needing any secrets. Workflows that require upstream secrets are kept but no longer trigger automatically.

## Documentation

### API reference

The library modules -- `autofill-parser`, `coroutine-utils`, `crypto`, `format` and `passgen` -- have generated API documentation at **<https://hmettendorf.github.io/Android-Password-Store/>**, rebuilt and published on every push to `main`. Every symbol links back to the line of source it came from in this repository.

To build the same site locally:

```shell
./gradlew dokkaGenerate
```

It is written to `build/dokka/html`; open `index.html` from there.

### User documentation

The prose documentation is the original project's and has not been touched since it was archived: the [documentation site](https://docs.passwordstore.app), and the older [wiki](https://github.com/android-password-store/Android-Password-Store/wiki/). Both still describe how the app works, since this fork has not changed any of its concepts, but neither of them covers anything listed under [What's new in this fork](#whats-new-in-this-fork).

## Contributing

Want to contribute? See if you can [find an issue](https://github.com/android-password-store/Android-Password-Store/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc) you are interested in, then send a PR. Consult the [contribution](CONTRIBUTING.md) docs

Interested in helping to translate Password Store? Contribute [here](https://crowdin.com/project/android-password-store)!

Wanna test development builds to find bugs and offer feedback? Read the [release channels](https://docs.passwordstore.app/docs/Users/release-channels) documentation to get access!

<sub>Google Play and the Google Play logo are trademarks of Google LLC.</sub>
