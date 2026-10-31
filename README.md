# NestSigner

A small Android app that makes `.jks` signing keys **and signs APKs** with them. No terminal, no Android Studio, and no permissions required.

## Download

**[Download NestSigner.apk](https://github.com/Techy-Nature/NestSigner/releases/latest/download/NestSigner.apk)**, then open it on your Android device to install. You may need to allow your browser or file manager to install unknown apps.

This link always points to the newest build.

## Make a key

Fill in a file name, a password, an alias and your name, tap **Create keystore**, and pick where to save. NestSigner shows the SHA-1 and SHA-256 fingerprints (handy for Firebase, Google sign-in and similar services) with a copy button.

| Setting | Value |
|---|---|
| Format | JKS (Java KeyStore) |
| Key | RSA 2048-bit |
| Certificate | Self-signed X.509 v3, SHA256withRSA, with a Subject Key Identifier |
| Validity | 30 years by default (Google Play needs 25+) |
| Alias | Saved in lowercase, the same as `keytool` does |

## Sign an APK

1. Switch to **Sign an APK**.
2. Choose the APK, **or** an unzipped APK folder (see below).
3. Choose a keystore and type its password, then tap **Unlock keystore**.
4. Pick the key (if the keystore has more than one) and enter its password if it's different.
5. Tap **Sign APK** and pick where to save the signed copy. The original APK isn't changed.

### Unzipped APK folders

If you unzipped an APK and edited files inside (assets, images, and so on), tap **Unzipped folder…** and pick that folder. NestSigner zips it back up, aligns it and signs it in one step:

- `resources.arsc`, native libraries (`.so`) and media files are stored uncompressed, which Android needs to install and run them.
- Old signature files in `META-INF` are dropped.
- If you pick the folder *containing* the APK folder, NestSigner finds the APK folder inside.
- For big folders (games with thousands of files), tap **Allow All files access**. NestSigner then reads the folder directly, which is much faster and more reliable than going through Android's file picker service. It's optional and can be turned off in Settings at any time.

This is for **unzipped** APKs, which have a binary `AndroidManifest.xml`. A **decompiled** apktool project (readable XML, `smali` folders, `apktool.yml`) needs recompiling with `apktool b` first; NestSigner will tell you if you pick one.

A `.zip` holding a single APK also works: NestSigner signs the APK inside.

Signing uses Google's [apksig](https://android.googlesource.com/platform/tools/apksig/) library, the same engine as the SDK's `apksigner` and Android Studio. APKs are zip-aligned and get v1 (JAR), v2 and v3 signatures, and the result is verified before it's saved.

Keystores it can open: **JKS** (from NestSigner, `keytool`, Android Studio and others), **PKCS12** (`.p12`, `.pfx`, and modern `.keystore` files) and **BKS**. JCEKS isn't supported.

Everything runs on the device. Nothing is uploaded, and the app has no internet permission. The only permission it can ask for is the optional All files access described above.

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
3. When it's green, the APK is published to the repo's **Releases** page as `NestSigner.apk`.

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
├── MainActivity.java          Mode switch and the "Make a key" screen
├── SignScreen.java            The "Sign an APK" screen
├── SafFolder.java             Lists files in a folder picked with the system picker
├── Ui.java                    Shared view helpers
└── core/
    ├── KeystoreFactory.java   Generates the key, certificate and file in one call
    ├── CertInfo.java          Certificate name fields and their validation
    ├── CertBuilder.java       Builds the self-signed X.509 certificate
    ├── JksWriter.java         Writes the JKS file format
    ├── JksReader.java         Reads JKS files (Android can't on its own)
    ├── KeystoreLoader.java    Opens JKS / PKCS12 / BKS and unlocks a key
    ├── KeystoreException.java Friendly errors (wrong password, unsupported file…)
    ├── ApkSigning.java        Aligns, signs and verifies APKs with apksig
    ├── FolderPacker.java      Packs an unzipped APK folder back into an APK
    └── Der.java               Tiny ASN.1/DER encoder
```

Android has no built-in JKS support, so `JksWriter` and `JksReader` handle the format directly. It matches the JDK's own implementation byte for byte in structure, and was tested by loading the output with the JDK's `KeyStore`, `keytool -list -v`, `keytool -importkeystore`, and by signing and verifying a JAR with `jarsigner`.

The only dependency is Google's `apksig`.

## A word to users

Back up the `.jks` file and write down the keystore password, key password and alias. If any of them is lost, apps signed with that key can't be updated with the same signature.
