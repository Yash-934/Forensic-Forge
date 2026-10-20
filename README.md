# Forensic-Forge
Recover Deleted files0

## Files Recovery - Photo & Video (Clone Project)

Clean-room re-implementation of the **Files Recovery - Photo & Video** app
(original package `com.cov.re.phone`, v1.0.7), built from a REA
(Reverse Engineer Anything) + JADX analysis of the original APK.
No original code, assets, ad SDKs or protected (PairIP) binaries are included -
every file here is a fresh implementation of the same feature set.

## How to build

1. Open this folder in **Android Studio** (Ladybug or newer).
2. Let Gradle sync (internet needed once), then **Build -> Build APK(s)**
	 or run `./gradlew assembleDebug`.
3. Debug APK appears in `app/build/outputs/apk/debug/`.

- Package (change it before publishing): `com.clone.filesrecovery`
- Min SDK 24 - Target/Compile SDK 35 - Kotlin 2.0 - Jetpack Compose Material 3

## Feature map (original -> clone)

| Original screen / route | Clone |
|---|---|
| Guide + Language selection | `GuideScreen`, `LanguageScreen` |
| Home (MainRoute) | `HomeScreen` dashboard |
| AllFilePermissionRoute | `PermissionScreen` (All Files Access flow) |
| RecoveryScanRoute | `ScanScreen` (deep storage walk + progress) |
| RecoverySelect/Result routes | `ResultScreen` (grid for photo/video, list for audio/docs, folder + size + date, multi-select) |
| FileDetail / PreviewPlayer | `DetailScreen` (image viewer, video player, audio player, document opener) |
| ResultOngoing / ResultCompleted | Recover progress + completion dialog, files copied to public `FilesRecovery/<Type>` folder |
| RecoveryFileRoute (recovered files) | `RecoveredScreen` + JSON history store (`AppStore`) |
| Contact backup / deleted contacts | `ContactsScreen` - list, **.vcf backup to Downloads**, **.vcf restore/import** |
| Notification Recovery (Media/Message tabs) | `NotificationRecorderService` + `NotificationsScreen` with All/Media/Message tabs |
| JunkCleaner / ScreenshotCleaner / duplicates | `JunkCleanerScreen` - screenshots, duplicate photos (size+MD5), large files, temp/log files |
| MediaStorage / Uninstall routes | `StorageScreen` - storage stats + installed-apps uninstaller |
| Setting / Rate / FeedBack | `SettingsScreen` |

## Deliberately NOT cloned

- **Ads** (AdMob, Facebook Audience Network, AppLovin, Mintegral, Adjust
	attribution) - the original is ad-funded; add your own ad SDK if you want it.
- **Nag/marketing notifications** and the Firebase backend - not needed for the
	recovery features to work.
- Google PairIP protection used by the original binary.

## Honest limitation (same as the original)

Without root, no Android app can truly undelete file sectors. Like the
original, this app deep-scans shared storage for files that still exist but are
"lost" to the user (hidden folders, app folders, `.nomedia` dirs, messaging
folders, trash folders) and **recovers = copies** them into a visible public
folder. Files already overwritten on disk cannot be brought back by any app.

## Analysis evidence

Full REA evidence (package info, manifest, class inventory, feature routes)
was captured during the analysis session - package `com.cov.re.phone`,
30,450 classes, Kotlin + Compose Material 3, Room DB, per-type rule-check
classes (`ImageFileRuleCheck`, `VideoFileRuleCheck`, ...) which this clone
expresses as the `FileCategory` enum in `data/Models.kt`.
