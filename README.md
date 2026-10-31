# NestSigner

A small Android app that makes `.jks` signing keys for Android apps. No terminal, no Android Studio, no permissions.

You fill in a file name, a password, an alias and your name, tap **Create keystore**, pick where to save, and you're done. It also shows the SHA-1 and SHA-256 fingerprints (handy for Firebase, Google sign-in and similar services) with a copy button.

## What it makes

| Setting | Value |
|---|---|
| Format | JKS (Java KeyStore) |
| Key | RSA 2048-bit |
| Certificate | Self-signed X.509 v3, SHA256withRSA, with a Subject Key Identifier |
| Validity | 30 years by default (Google Play needs 25+) |
| Alias | Saved in lowercase, the same as `keytool` does |

Files work with `keytool`, `jarsigner`, `apksigner`, Gradle `signingConfigs`, Android Studio, and APK editors like MT Manager and APK Editor Studio.

Everything runs on the device. Nothing is uploaded, and the app has no internet permission.

## Building the APK

### Option A: Android Studio (easiest)

1. Install Android Studio. On Nobara: `flatpak install flathub com.google.AndroidStudio`
2. Open Android Studio and choose **Open**, then pick the `NestSigner` folder.
3. Wait for the Gradle sync to finish. If it offers to upgrade the Android Gradle Plugin, it's safe to accept.
4. Go to **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.
5. When it finishes, click **locate** in the popup. The APK is at `app/build/outputs/apk/debug/app-debug.apk`.
6. Copy the APK to your phone or tablet and open it to install. Allow "install unknown apps" for your file manager if asked.

### Option B: GitHub Actions (no installs on your computer)

The project already contains `.github/workflows/build.yml`.

1. Put the project in any GitHub repo.
2. Open the repo's **Actions** tab. A build starts on every push, or press **Run workflow**.
3. When it's green, open the run and download **NestSigner-debug** from the Artifacts section.

## Signing a release build of NestSigner

The debug APK installs fine and is OK to share. For a proper release, sign NestSigner with a key made by NestSigner:

1. Install the debug APK and make a keystore with it, for example `nestsigner-release.jks`.
2. Copy that file into the project folder, next to `settings.gradle`.
3. Create `keystore.properties` in the same folder:

   ```properties
   storeFile=nestsigner-release.jks
   storePassword=YOUR_KEYSTORE_PASSWORD
   keyAlias=upload
   keyPassword=YOUR_KEY_PASSWORD
   ```

4. Build with **Build → Generate Signed App Bundle / APK** in Android Studio, or run `./gradlew assembleRelease`.

`keystore.properties` and `*.jks` are in `.gitignore`, so they won't be committed by accident.

## Project layout

```
app/src/main/java/io/github/techynature/nestsigner/
├── MainActivity.java          The single screen: form, validation, save
└── core/
    ├── KeystoreFactory.java   Generates the key, certificate and file in one call
    ├── CertInfo.java          Certificate name fields and their validation
    ├── CertBuilder.java       Builds the self-signed X.509 certificate
    ├── JksWriter.java         Writes the JKS file format
    └── Der.java               Tiny ASN.1/DER encoder
```

Android has no built-in JKS support, so `JksWriter` writes the format directly. It matches the JDK's own implementation byte for byte in structure, and was tested by loading the output with the JDK's `KeyStore`, `keytool -list -v`, `keytool -importkeystore`, and by signing and verifying a JAR with `jarsigner`.

There are no third-party dependencies.

## A word to users

Back up the `.jks` file and write down the keystore password, key password and alias. If any of them is lost, apps signed with that key can't be updated with the same signature.
