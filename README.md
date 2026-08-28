# Password Store

[![GitHub workflow](https://github.com/android-password-store/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/android-password-store/Android-Password-Store/actions)
![Backers on Open Collective](https://opencollective.com/Android-Password-Store/backers/badge.svg) ![Sponsors on Open Collective](https://opencollective.com/Android-Password-Store/sponsors/badge.svg)

## What's new in this fork

Upstream development stopped in October 2024. This fork picks the project back up; the changes so far:

### Autofill

* **/e/OS Browser support.** `foundation.e.browser` is now a trusted browser, so Autofill matches on the site being visited instead of falling back to the browser's own package name.

### Encryption and storage

* **Jetpack Security replaced with the Android Keystore.** `androidx.security:security-crypto` is deprecated in full and pinned to a long-outdated Tink. Encrypted storage now sits on AES-GCM keys held directly in the Android Keystore, with DataStore for persistence, optional user-authentication binding and optional StrongBox. Existing data is migrated on first launch: the legacy store is only discarded after the new copy has been read back, and the keystore-wrapped SSH key is re-wrapped under a separate alias so a failure leaves the original untouched.
* **`.gpg-id` files using GnuPG's exact-key marker now work.** An entry such as `0xCA14231C6693C21B!` no longer invalidates the whole file and discards the other recipients in it.
* **Fewer latent crashes on empty input.** Password, OTP and git-credential fields no longer throw on a null editable; empty input is now read as an empty string.

### Build and tooling

* **Toolchain and dependencies brought forward.** Gradle 9.5.1, AGP 8.13.2, Kotlin 2.2.21, `compileSdk` 36, BouncyCastle 1.85, plus current AndroidX, Compose, Hilt and coroutines. `targetSdk` deliberately stays at 34, so there are no runtime behaviour changes from the upgrade itself.
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
