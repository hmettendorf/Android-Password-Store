# Password Store

[![GitHub workflow](https://github.com/android-password-store/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/android-password-store/Android-Password-Store/actions)
![Backers on Open Collective](https://opencollective.com/Android-Password-Store/backers/badge.svg) ![Sponsors on Open Collective](https://opencollective.com/Android-Password-Store/sponsors/badge.svg)

## What's new in this fork

Upstream development stopped in October 2024. This fork picks the project back up; the changes so far:

### Autofill

* **/e/OS Browser support.** `foundation.e.browser` is now a trusted browser, so Autofill matches on the site being visited instead of falling back to the browser's own package name.

### Git

* **Auto push.** Saving a password pushes it to the remote straight away, instead of leaving the commit sitting locally until you next sync by hand. It covers edits as well as new entries, and applies wherever an entry is saved from — the password list, the decrypt screen, or an Autofill save prompt.

  It is **on by default**, and can be turned off under **Settings → Passwords → Auto push**.

  Pushing uses the Git remote and authentication you have already configured, so an SSH key that asks for biometric unlock will still ask. Nothing happens if the store has no remote — a local-only store is left alone rather than reporting an error.

  A push that fails never costs you the entry. The password is committed before the push is attempted, so the commit simply stays local and goes out with your next push or sync; the error is shown so you know it is still pending. Declining a biometric prompt is treated as a decision, not a failure, and passes without a dialog.

### Encryption and storage

* **Jetpack Security replaced with the Android Keystore.** `androidx.security:security-crypto` is deprecated in full and pinned to a long-outdated Tink. Encrypted storage now sits on AES-GCM keys held directly in the Android Keystore, with DataStore for persistence, optional user-authentication binding and optional StrongBox. Existing data is migrated on first launch: the legacy store is only discarded after the new copy has been read back, and the keystore-wrapped SSH key is re-wrapped under a separate alias so a failure leaves the original untouched.
* **`.gpg-id` files using GnuPG's exact-key marker now work.** An entry such as `0xCA14231C6693C21B!` no longer invalidates the whole file and discards the other recipients in it.
* **Fewer latent crashes on empty input.** Password, OTP and git-credential fields no longer throw on a null editable; empty input is now read as an empty string.

### Build and tooling

* **Toolchain and dependencies brought forward.** Gradle 9.5.1, AGP 8.13.2, Kotlin 2.2.21, `compileSdk` 36, BouncyCastle 1.85, plus current AndroidX, Compose, Hilt and coroutines. `targetSdk` deliberately stays at 34, so there are no runtime behaviour changes from the upgrade itself.
* **API documentation, generated and published.** Dokka 2.2.0 aggregates the library modules -- `autofill-parser`, `coroutine-utils`, `crypto`, `format` and `passgen` -- into one cross-linked site, with every symbol linking back to its source line on GitHub. `docs.yml` builds it on each push and deploys to GitHub Pages through the artifact flow, so there is no `gh-pages` branch and no token to manage. Pull requests build the docs without deploying, so a broken build surfaces on the PR.
* **Dependency updates run themselves again.** Upstream's Renovate config was left behind without a bot to execute it. `renovate.yml` runs Renovate on a schedule from the repository itself, and validates the config on every PR that touches it. The config has been migrated to current Renovate, which removed `config:base`, `matchPackagePatterns` and `regexManagers`. Requires a `RENOVATE_TOKEN` secret.
* **CI that runs on a fork.** Every workflow used to depend on a reusable workflow in the now-archived upstream repository. `ci.yml` inlines those steps and runs Spotless, the unit tests, the API compatibility check and both debug APK builds without needing any secrets. Workflows that require upstream secrets are kept but no longer trigger automatically.

## Download

See https://docs.passwordstore.app/docs/users/release-channels/

## Documentation

We're in the process of rewriting our documentation from scratch, and the work-in-progress state can be seen [here](https://docs.passwordstore.app). See the [wiki](https://github.com/android-password-store/Android-Password-Store/wiki/) for the old documentation.

## Contributing

Want to contribute? See if you can [find an issue](https://github.com/android-password-store/Android-Password-Store/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc) you are interested in, then send a PR. Consult the [contribution](CONTRIBUTING.md) docs 

Interested in helping to translate Password Store? Contribute [here](https://crowdin.com/project/android-password-store)!

Wanna test development builds to find bugs and offer feedback? Read the [release channels](https://docs.passwordstore.app/docs/Users/release-channels) documentation to get access!

## Community

Ways to get in touch:

* [Github issues](https://github.com/android-password-store/Android-Password-Store/issues): Use it if you have a bug report, or you want to submit a feature request.
* [GitHub Discussions](https://github.com/android-password-store/Android-Password-Store/discussions): Use it if you do not understand something, or want to discuss a feature request in more detail with all community members before pitching it to maintainers.

## Donations

The project accepts financial contributions through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)

<sub>Google Play and the Google Play logo are trademarks of Google LLC.</sub>
