# Samples

This directory contains the active sample applications for the `crypto` project.

## Layout

- `composeApp`
  Shared Compose Multiplatform UI and feature code.
- `androidApp`
  Android launcher app for the shared Compose sample.
- `iosApp`
  Xcode host app that embeds the shared Compose framework.

## Architecture

The active sample app is built around:

- Compose Multiplatform UI in `samples/composeApp`
- Orbit for app and feature state
- Koin for dependency injection
- common Kotlin source sets for the sample feature logic

The current migrated sample feature is `cryptohash`.

## Gradle modules

The main build includes:

- `:samples:composeApp`
- `:samples:androidApp`

The shared crypto implementation is consumed from:

- `:cryptohash`

## Running the samples

### Android

Build the Android debug app with:

```bash
./gradlew :samples:androidApp:assembleDebug
```

Open or run the launcher app from Android Studio using the `samples/androidApp` module.

### iOS

Open the Xcode project:

- `samples/iosApp/iosApp.xcodeproj`

Then run the `iosApp` scheme on a simulator.

If you prefer the command line:

```bash
xcodebuild \
  -project samples/iosApp/iosApp.xcodeproj \
  -scheme iosApp \
  -destination 'platform=iOS Simulator,name=iPhone 16' \
  build
```

### Shared module checks

Useful shared build commands:

```bash
./gradlew :samples:composeApp:build
./gradlew :samples:composeApp:compileCommonMainKotlinMetadata
```

## Tests

Run the compose sample test suite with:

```bash
./gradlew :samples:composeApp:allTests
```

Run the Android sample unit tests with:

```bash
./gradlew :samples:androidApp:testDebugUnitTest
```

## Notes

- The Android sample enables edge-to-edge rendering and the shared UI applies safe drawing insets.
- Compose previews live in `samples/composeApp/src/commonMain/kotlin/com/appmattus/crypto/sample/ui`.
- Android preview rendering depends on `ui-tooling-preview` in `commonMain` and `ui-tooling` in `androidMain`.
