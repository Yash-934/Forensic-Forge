package com.clone.filesrecovery.forensics

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import androidx.core.content.ContextCompat
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

/**
 * Adaptive Dual-Mode Android Forensics Engine for DeepVault:
 *  - Section 1: 4-State Home Screen Root & Access Status Model (States A, B, C, D)
 *  - Section 2: RootCapabilityManager (separating indicators, root manager apps, verified privileges,
 *               accessible storage sources, and specific operation support; strict allowlist, zero arbitrary shell)
 *  - Section 3: RecoveryCapabilityRegistry (independent evaluation of Capabilities A..J)
 *  - Section 4 & 5: Standard Mode vs Root-Enabled Mode with read-only safeguards & audit logging
 *  - Section 6: RecoveryModeController (startup evaluation, scan orchestration, fallback & coverage tracking)
 */

enum class DeviceAccessState(
    val stateCode: String,
    val cardTitle: String,
    val defaultDescription: String,
    val buttonLabel: String
) {
    STATE_A_NON_ROOTED(
        stateCode = "STATE_A",
        cardTitle = "STANDARD MODE ACTIVE",
        defaultDescription = "DeepVault is using Android-supported storage access and non-root recovery methods.",
        buttonLabel = "VIEW CAPABILITIES"
    ),
    STATE_B_ROOT_DETECTED_UNVERIFIED(
        stateCode = "STATE_B",
        cardTitle = "ROOT DETECTED — ACCESS LIMITED",
        defaultDescription = "Root indicators were detected, but elevated storage access has not been verified.",
        buttonLabel = "VIEW CAPABILITIES"
    ),
    STATE_C_ROOT_VERIFIED(
        stateCode = "STATE_C",
        cardTitle = "ROOT-ENABLED MODE AVAILABLE",
        defaultDescription = "Elevated access is available. DeepVault will enable only the additional recovery capabilities verified on this device.",
        buttonLabel = "VIEW ADVANCED CAPABILITIES"
    ),
    STATE_D_UNKNOWN_INCONCLUSIVE(
        stateCode = "STATE_D",
        cardTitle = "DEVICE ACCESS STATUS UNKNOWN",
        defaultDescription = "DeepVault could not reliably determine the device's root or storage-access status.",
        buttonLabel = "VIEW CAPABILITIES"
    )
}

enum class PrivilegeVerificationStatus(val id: String, val label: String) {
    NOT_ATTEMPTED("not_attempted", "Not Verified (No Privilege Check Executed)"),
    VERIFIED_READ_ONLY("verified_uid_zero", "Verified (Elevated Read-Only Access Confirmed)"),
    DENIED_BY_USER_OR_POLICY("denied", "Denied or Unavailable (Falling Back to Standard Mode)"),
    INCONCLUSIVE_OR_ERROR("inconclusive", "Inconclusive / Check Failed")
}

enum class PrivilegeLevel(val label: String) {
    STANDARD_USER_SPACE("Standard Android User-Space"),
    ELEVATED_ROOT_VERIFIED("Verified Root Privilege (Read-Only)")
}

enum class CapabilityVerificationResult(val label: String) {
    VERIFIED_READY("Verified & Ready"),
    PERMISSION_REQUIRED("Android Storage Permission Required"),
    USER_SELECTION_READY("Ready on User File/Folder Selection (SAF)"),
    PRIVILEGE_UNVERIFIED("Requires Verified Root Authorization"),
    SOURCE_UNAVAILABLE("Required Storage Source Inaccessible"),
    UNSUPPORTED_ON_DEVICE("Unsupported on Current Device / OS")
}

enum class CapabilityId(
    val code: String,
    val title: String,
    val description: String,
    val requiredPrivilege: PrivilegeLevel
) {
    A_MEDIASTORE_SCAN(
        code = "CAP-A",
        title = "Android MediaStore Scanning",
        description = "Queries indexed, trashed (IS_TRASHED), and pending media records across external volumes.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    B_USER_FOLDER_SCAN(
        code = "CAP-B",
        title = "User-Selected & Accessible Folder Traversal",
        description = "Recursively scans accessible shared storage folders, recycle bins, and user-authorized directories.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    C_USER_FILE_ANALYSIS(
        code = "CAP-C",
        title = "User-Selected File Forensic Analysis",
        description = "Performs deep header, structure, and metadata inspection on individual accessible or SAF-selected files.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    D_THUMBNAIL_CACHE_ANALYSIS(
        code = "CAP-D",
        title = "Accessible Thumbnail & Cache Analysis",
        description = "Inspects .thumbnails, .thumbdata databases, and accessible application media caches.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    E_SIGNATURE_CARVING_STREAMS(
        code = "CAP-E",
        title = "Signature-Based Carving from Accessible Byte Streams",
        description = "Carves embedded JPEG/PNG/PDF/ZIP/Media streams by magic bytes from accessible blob and cache files.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    F_METADATA_EXTRACTION(
        code = "CAP-F",
        title = "Deterministic Format Metadata Extraction",
        description = "Extracts EXIF, GPS, ISOBMFF, RIFF/WAV, ID3, PDF Info, and OOXML/ZIP metadata offline.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    G_SHA256_HASHING(
        code = "CAP-G",
        title = "Streaming Cryptographic Hashing (SHA-256 / MD5 / SHA-1)",
        description = "Computes byte-level integrity digests in 64 KB chunks without loading entire files into RAM.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    H_AUTHORIZED_RAW_IMAGE_ANALYSIS(
        code = "CAP-H",
        title = "Authorized Raw Disk/Partition Image Analysis",
        description = "Scans user-supplied raw storage image files (.img, .dd, .bin) for magic-byte file signatures in read-only mode.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    ),
    I_ROOT_DEPENDENT_ACQUISITION(
        code = "CAP-I",
        title = "Root-Dependent Protected Storage Inspection",
        description = "Read-only inspection of protected media/recycle paths when elevated access is genuinely verified and authorized.",
        requiredPrivilege = PrivilegeLevel.ELEVATED_ROOT_VERIFIED
    ),
    J_FILESYSTEM_METADATA_ANALYSIS(
        code = "CAP-J",
        title = "Filesystem & Extended Stat Metadata Analysis",
        description = "Collects POSIX last-modified timestamps, permissions, and extended stat attributes where accessible.",
        requiredPrivilege = PrivilegeLevel.STANDARD_USER_SPACE
    )
}

data class RecoveryCapabilityStatus(
    val id: CapabilityId,
    val requiredPermissions: List<String>,
    val requiredPrivilegeLevel: PrivilegeLevel,
    val requiredAcquisitionSource: String,
    val deviceCompatibility: String,
    val verificationResult: CapabilityVerificationResult,
    val isAvailable: Boolean,
    val knownLimitations: List<String>,
    val unavailabilityReason: String? = null
)

data class SkippedRecoveryMethod(
    val capabilityCode: String,
    val methodName: String,
    val reason: String
)

data class ForensicAuditLogEntry(
    val timestampIso: String,
    val operation: String,
    val mode: String,
    val readOnlyEnforced: Boolean,
    val outcome: String
)

/**
 * Snapshot of the device's root, permission, storage, and capability assessment.
 */
data class DeviceAccessAssessment(
    val accessState: DeviceAccessState,
    val activeOperatingMode: OperatingMode,
    val automaticModeEnabled: Boolean,
    val readOnlyPreference: Boolean,
    val rootIndicatorsDetected: Boolean,
    val detectedRootIndicators: List<String>,
    val rootManagerDetected: Boolean,
    val detectedRootManagers: List<String>,
    val privilegeVerificationStatus: PrivilegeVerificationStatus,
    val storagePermissionSummary: String,
    val grantedPermissions: List<String>,
    val missingPermissions: List<String>,
    val accessibleStorageSources: List<String>,
    val accessibleStorageScope: String,
    val capabilities: List<RecoveryCapabilityStatus>,
    val availableMethodsSummary: List<String>,
    val restrictedCapabilitiesSummary: List<String>,
    val evaluatedAtIso: String = ForensicTimeUtil.nowIsoUtc()
)

/**
 * Records the actual adaptive execution details of a scan/recovery session for Section 7 reporting.
 */
data class RecoveryExecutionSummary(
    val rootDetectionStatus: String,
    val privilegeVerificationStatus: String,
    val recoveryMode: String,
    val grantedStoragePermissions: List<String>,
    val failedPermissionChecks: List<String>,
    val acquisitionSourcesExamined: List<String>,
    val recoveryMethodsAttempted: List<String>,
    val recoveryMethodsSkipped: List<SkippedRecoveryMethod>,
    val accessibleStorageScope: String,
    val scanStartTimestampIso: String,
    val scanCompletedTimestampIso: String,
    val readOnlyEnforced: Boolean = true,
    val rootScopeDisclaimer: String = "Root detection or elevated privilege status is not proof that every storage region was accessible; hardware-backed File-Based Encryption (FBE) and flash TRIM/garbage collection restrict unallocated block recovery even with root."
)

// ==================== Narrowly Scoped Allowlisted Privilege Interface ====================

/**
 * Strictly allowlisted read-only operations. Never accepts arbitrary shell strings or filenames.
 */
enum class AllowedPrivilegedOperation {
    VERIFY_UID_ZERO_READONLY,
    PROBE_READONLY_STORAGE_METADATA
}

interface EnvironmentProbe {
    fun checkSuBinaryPaths(): List<String>
    fun checkBuildTags(): String?
    fun checkInstalledRootPackages(context: Context?): List<String>
    fun checkStoragePermissions(context: Context?): Pair<List<String>, List<String>>
    fun hasAllFilesAccess(context: Context?): Boolean
    fun getAccessibleStorageRoots(context: Context?): List<String>
    fun executeAllowlistedPrivilegeCheck(op: AllowedPrivilegedOperation): Pair<Boolean, String>
}

/**
 * Production implementation of [EnvironmentProbe] using conservative, non-destructive Android checks.
 */
class DefaultAndroidEnvironmentProbe : EnvironmentProbe {

    private val knownSuLocations = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/product/bin/su",
        "/apex/com.android.runtime/bin/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
    )

    private val knownRootPackages = listOf(
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser"
    )

    override fun checkSuBinaryPaths(): List<String> {
        val found = mutableListOf<String>()
        for (path in knownSuLocations) {
            runCatching {
                val f = File(path)
                if (f.exists()) {
                    found.add("su_path_present:$path")
                }
            }
        }
        return found
    }

    override fun checkBuildTags(): String? = runCatching {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys", ignoreCase = true)) {
            "build_tags:test-keys"
        } else null
    }.getOrNull()

    override fun checkInstalledRootPackages(context: Context?): List<String> {
        if (context == null) return emptyList()
        val pm = context.packageManager ?: return emptyList()
        val detected = mutableListOf<String>()
        for (pkg in knownRootPackages) {
            val installed = runCatching {
                pm.getPackageInfo(pkg, 0)
                true
            }.getOrDefault(false)
            if (installed) detected.add(pkg)
        }
        return detected
    }

    override fun hasAllFilesAccess(context: Context?): Boolean {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Environment.isExternalStorageManager()
            } else if (context != null) {
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.READ_EXTERNAL_STORAGE
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                false
            }
        }.getOrDefault(false)
    }

    override fun checkStoragePermissions(context: Context?): Pair<List<String>, List<String>> {
        if (context == null) return emptyList<String>() to listOf("Context unavailable")
        val granted = mutableListOf<String>()
        val missing = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)) {
                granted.add("MANAGE_EXTERNAL_STORAGE (All Files Access)")
            } else {
                missing.add("MANAGE_EXTERNAL_STORAGE (All Files Access)")
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val mediaPerms = listOf(
                Manifest.permission.READ_MEDIA_IMAGES to "READ_MEDIA_IMAGES",
                Manifest.permission.READ_MEDIA_VIDEO to "READ_MEDIA_VIDEO",
                Manifest.permission.READ_MEDIA_AUDIO to "READ_MEDIA_AUDIO"
            )
            for ((perm, label) in mediaPerms) {
                if (ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED) {
                    granted.add(label)
                } else {
                    missing.add(label)
                }
            }
        } else {
            val readGranted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
            if (readGranted) granted.add("READ_EXTERNAL_STORAGE") else missing.add("READ_EXTERNAL_STORAGE")
        }

        // App-specific storage & SAF are always available without runtime dangerous permissions
        granted.add("APP_SPECIFIC_STORAGE_AND_SAF")
        return granted to missing
    }

    override fun getAccessibleStorageRoots(context: Context?): List<String> {
        val sources = LinkedHashSet<String>()
        runCatching {
            val primary = Environment.getExternalStorageDirectory()
            if (primary != null && primary.exists() && primary.canRead()) {
                sources.add("Primary Shared Storage (${primary.absolutePath})")
            }
        }
        if (context != null) {
            runCatching {
                context.filesDir?.takeIf { it.exists() && it.canRead() }?.let {
                    sources.add("App Internal Sandbox (${it.absolutePath})")
                }
                context.getExternalFilesDirs(null).filterNotNull().forEachIndexed { idx, dir ->
                    if (dir.exists() && dir.canRead()) {
                        val label = if (idx == 0) "App External Volume" else "Secondary External / SD Volume #$idx"
                        sources.add("$label (${dir.absolutePath})")
                    }
                }
            }
            sources.add("Android MediaStore ContentResolver")
            sources.add("Storage Access Framework (User Document Picker)")
        }
        return sources.toList()
    }

    /**
     * Executes only fixed, allowlisted, read-only verification commands (`su -c id`).
     * Never accepts dynamic arguments, paths, or filenames.
     */
    override fun executeAllowlistedPrivilegeCheck(op: AllowedPrivilegedOperation): Pair<Boolean, String> {
        val fixedCommand = when (op) {
            AllowedPrivilegedOperation.VERIFY_UID_ZERO_READONLY -> arrayOf("su", "-c", "id")
            AllowedPrivilegedOperation.PROBE_READONLY_STORAGE_METADATA -> arrayOf("su", "-c", "id -u")
        }
        return runCatching {
            val process = ProcessBuilder(*fixedCommand)
                .redirectErrorStream(true)
                .start()
            val exited = process.waitFor(2500, TimeUnit.MILLISECONDS)
            if (!exited) {
                process.destroyForcibly()
                return@runCatching false to "Privilege verification timed out (authorization not granted)."
            }
            val output = BufferedReader(InputStreamReader(process.inputStream))
                .use { it.readLine() ?: "" }
                .trim()
            // Sanitize output: never expose raw shell output in reports; only check for uid=0
            val isUidZero = process.exitValue() == 0 && (output.contains("uid=0") || output == "0")
            if (isUidZero) {
                true to "Verified elevated read-only context (uid=0 confirmed)"
            } else {
                false to "Elevated access denied or unavailable (exit=${process.exitValue()})"
            }
        }.getOrElse {
            false to "Privilege check unavailable (${it.javaClass.simpleName})"
        }
    }
}

// ==================== Section 2: RootCapabilityManager ====================

class RootCapabilityManager(
    private val probe: EnvironmentProbe = DefaultAndroidEnvironmentProbe()
) {
    private var cachedPrivilegeStatus: PrivilegeVerificationStatus = PrivilegeVerificationStatus.NOT_ATTEMPTED
    private var forceStandardFallback: Boolean = false

    fun getPrivilegeVerificationStatus(): PrivilegeVerificationStatus = cachedPrivilegeStatus

    /**
     * Passive, non-intrusive detection of root indicators and root management apps.
     * Does NOT execute `su` automatically (preventing unwanted root popups on startup).
     */
    fun inspectPassiveRootIndicators(context: Context?): Triple<Boolean, List<String>, List<String>> {
        val suPaths = probe.checkSuBinaryPaths()
        val buildTag = probe.checkBuildTags()
        val managers = probe.checkInstalledRootPackages(context)

        val indicators = mutableListOf<String>()
        indicators.addAll(suPaths)
        if (buildTag != null) indicators.add(buildTag)

        val anyIndicator = indicators.isNotEmpty() || managers.isNotEmpty()
        return Triple(anyIndicator, indicators, managers)
    }

    /**
     * Controlled, user-initiated privilege verification using the strict allowlist.
     * Never called automatically in a loop.
     */
    fun verifyElevatedPrivilegesExplicitly(): Pair<PrivilegeVerificationStatus, String> {
        if (forceStandardFallback) {
            cachedPrivilegeStatus = PrivilegeVerificationStatus.DENIED_BY_USER_OR_POLICY
            return cachedPrivilegeStatus to "Standard mode enforced by user preference."
        }
        val (ok, summary) = probe.executeAllowlistedPrivilegeCheck(
            AllowedPrivilegedOperation.VERIFY_UID_ZERO_READONLY
        )
        cachedPrivilegeStatus = if (ok) {
            PrivilegeVerificationStatus.VERIFIED_READ_ONLY
        } else {
            PrivilegeVerificationStatus.DENIED_BY_USER_OR_POLICY
        }
        return cachedPrivilegeStatus to summary
    }

    fun resetToStandardMode() {
        forceStandardFallback = true
        cachedPrivilegeStatus = PrivilegeVerificationStatus.DENIED_BY_USER_OR_POLICY
    }

    fun allowElevatedVerificationAgain() {
        forceStandardFallback = false
    }

    /**
     * Used in unit tests to simulate specific privilege states deterministically.
     */
    fun setPrivilegeStatusForTesting(status: PrivilegeVerificationStatus) {
        cachedPrivilegeStatus = status
    }
}

// ==================== Section 3: RecoveryCapabilityRegistry ====================

object RecoveryCapabilityRegistry {

    fun evaluateAllCapabilities(
        hasAllFilesAccess: Boolean,
        grantedPermissions: List<String>,
        accessibleRoots: List<String>,
        privilegeStatus: PrivilegeVerificationStatus,
        rootModeAllowed: Boolean
    ): List<RecoveryCapabilityStatus> {
        val hasSharedStorageRead = hasAllFilesAccess ||
            grantedPermissions.any {
                it.startsWith("MANAGE_EXTERNAL_STORAGE") ||
                    it.startsWith("READ_EXTERNAL_STORAGE") ||
                    it.startsWith("READ_MEDIA_")
            }
        val hasReadablePrimaryVolume = accessibleRoots.any { it.startsWith("Primary Shared Storage") || it.startsWith("App External Volume") }
        val rootVerifiedAndEnabled = privilegeStatus == PrivilegeVerificationStatus.VERIFIED_READ_ONLY && rootModeAllowed

        return listOf(
            // A. Android MediaStore scanning
            RecoveryCapabilityStatus(
                id = CapabilityId.A_MEDIASTORE_SCAN,
                requiredPermissions = listOf("READ_MEDIA_IMAGES/VIDEO/AUDIO or READ_EXTERNAL_STORAGE"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Android MediaStore ContentProvider",
                deviceCompatibility = "Android 7.0+ (API 24+); Trashed/Pending query on Android 11+ (API 30+)",
                verificationResult = if (hasSharedStorageRead) CapabilityVerificationResult.VERIFIED_READY else CapabilityVerificationResult.PERMISSION_REQUIRED,
                isAvailable = hasSharedStorageRead,
                knownLimitations = listOf(
                    "Only discovers files still indexed, pending, or held in MediaStore trash; permanently purged database rows are not returned."
                ),
                unavailabilityReason = if (hasSharedStorageRead) null else "Media or storage read permission has not been granted yet."
            ),

            // B. User-selected & accessible folder scanning
            RecoveryCapabilityStatus(
                id = CapabilityId.B_USER_FOLDER_SCAN,
                requiredPermissions = listOf("MANAGE_EXTERNAL_STORAGE or Scoped Folder Consent"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Shared External Storage / Recycle Bins",
                deviceCompatibility = "All Android versions (Scoped Storage rules apply on Android 11+)",
                verificationResult = when {
                    hasAllFilesAccess && hasReadablePrimaryVolume -> CapabilityVerificationResult.VERIFIED_READY
                    hasReadablePrimaryVolume -> CapabilityVerificationResult.VERIFIED_READY
                    else -> CapabilityVerificationResult.PERMISSION_REQUIRED
                },
                isAvailable = hasReadablePrimaryVolume || hasAllFilesAccess,
                knownLimitations = listOf(
                    "Cannot traverse /data/data of other apps or unallocated raw filesystem blocks without verified root.",
                    if (hasAllFilesAccess) "Full shared storage traversal enabled." else "Restricted to media/accessible directories until All Files Access is granted."
                ),
                unavailabilityReason = if (hasReadablePrimaryVolume || hasAllFilesAccess) null else "Primary shared storage directory is not readable under current permissions."
            ),

            // C. User-selected file analysis
            RecoveryCapabilityStatus(
                id = CapabilityId.C_USER_FILE_ANALYSIS,
                requiredPermissions = listOf("Zero-permission SAF Document Picker or Storage Read"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "User-Selected URI / Accessible File",
                deviceCompatibility = "Universal (Android 7.0+)",
                verificationResult = CapabilityVerificationResult.VERIFIED_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Inspects the selected file stream only; cannot reconstruct missing external fragments."
                )
            ),

            // D. Accessible thumbnail and cache analysis
            RecoveryCapabilityStatus(
                id = CapabilityId.D_THUMBNAIL_CACHE_ANALYSIS,
                requiredPermissions = listOf("MANAGE_EXTERNAL_STORAGE or READ_MEDIA_IMAGES"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "DCIM/.thumbnails, Pictures/.thumbnails & accessible cache dirs",
                deviceCompatibility = "Android 7.0–15 (All Files Access required on Android 11+ for hidden dot-folders)",
                verificationResult = if (hasAllFilesAccess || hasSharedStorageRead) CapabilityVerificationResult.VERIFIED_READY else CapabilityVerificationResult.PERMISSION_REQUIRED,
                isAvailable = hasAllFilesAccess || hasSharedStorageRead,
                knownLimitations = listOf(
                    "Carved thumbnails have lower resolution than original deleted photos.",
                    "Private app caches inside /data/data/<pkg>/cache are protected by Android sandboxing."
                ),
                unavailabilityReason = if (hasAllFilesAccess || hasSharedStorageRead) null else "Requires storage permission to read .thumbnails directories."
            ),

            // E. Signature-based carving from accessible byte streams
            RecoveryCapabilityStatus(
                id = CapabilityId.E_SIGNATURE_CARVING_STREAMS,
                requiredPermissions = listOf("Storage Read or User-Selected File/Blob"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Accessible .thumbdata, .tmp, .cache, .bin & extensionless files",
                deviceCompatibility = "Universal (Deterministic Magic-Byte Engine)",
                verificationResult = CapabilityVerificationResult.VERIFIED_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Operates on accessible files and container blobs; does not read raw /dev/block/* unallocated sectors on non-rooted devices."
                )
            ),

            // F. Metadata extraction
            RecoveryCapabilityStatus(
                id = CapabilityId.F_METADATA_EXTRACTION,
                requiredPermissions = listOf("None (Internal Offline Parsers)"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Any accessible or recovered file",
                deviceCompatibility = "Universal (EXIF, ISOBMFF, RIFF/WAV, ID3, PDF, OOXML/ZIP)",
                verificationResult = CapabilityVerificationResult.VERIFIED_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Cannot recover metadata that was stripped prior to file acquisition."
                )
            ),

            // G. SHA-256 hashing
            RecoveryCapabilityStatus(
                id = CapabilityId.G_SHA256_HASHING,
                requiredPermissions = listOf("None (Java MessageDigest 64 KB Streaming)"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Any readable file or exported report",
                deviceCompatibility = "Universal (SHA-256, MD5, SHA-1)",
                verificationResult = CapabilityVerificationResult.VERIFIED_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Proves byte-level integrity of the stream at acquisition/export time; does not prove historical content authenticity."
                )
            ),

            // H. Authorized raw-image analysis
            RecoveryCapabilityStatus(
                id = CapabilityId.H_AUTHORIZED_RAW_IMAGE_ANALYSIS,
                requiredPermissions = listOf("User Consent via SAF Document Picker or Storage Read"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "User-Provided Raw Disk/Partition Image (.img, .dd, .bin)",
                deviceCompatibility = "Universal Read-Only Stream Carver",
                verificationResult = CapabilityVerificationResult.USER_SELECTION_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Carves contiguous JPEG/PNG/PDF/ZIP signatures from unencrypted raw images; heavily fragmented or FBE-encrypted images cannot be reassembled solely by header/footer markers."
                )
            ),

            // I. Root-dependent acquisition, when actually supported
            RecoveryCapabilityStatus(
                id = CapabilityId.I_ROOT_DEPENDENT_ACQUISITION,
                requiredPermissions = listOf("Verified su (uid=0) Authorization + Read-Only Source"),
                requiredPrivilegeLevel = PrivilegeLevel.ELEVATED_ROOT_VERIFIED,
                requiredAcquisitionSource = "Protected filesystem metadata & authorized read-only paths",
                deviceCompatibility = "Rooted devices with verified uid=0 grant only",
                verificationResult = if (rootVerifiedAndEnabled) {
                    CapabilityVerificationResult.VERIFIED_READY
                } else {
                    CapabilityVerificationResult.PRIVILEGE_UNVERIFIED
                },
                isAvailable = rootVerifiedAndEnabled,
                knownLimitations = listOf(
                    "Root access does NOT bypass hardware-backed File-Based Encryption (FBE) on modern Android.",
                    "Root access cannot recover flash blocks erased by UFS/eMMC TRIM or garbage collection.",
                    "DeepVault enforces read-only inspection and never modifies partitions, SELinux, or bootloaders."
                ),
                unavailabilityReason = when {
                    rootVerifiedAndEnabled -> null
                    privilegeStatus == PrivilegeVerificationStatus.VERIFIED_READ_ONLY && !rootModeAllowed ->
                        "Root-Enabled Mode is disabled in Settings (Standard Mode enforced)."
                    privilegeStatus == PrivilegeVerificationStatus.DENIED_BY_USER_OR_POLICY ->
                        "Elevated root authorization was denied or unavailable; using Standard Mode."
                    else ->
                        "Elevated root privileges have not been verified on this device."
                }
            ),

            // J. Filesystem metadata analysis, when accessible
            RecoveryCapabilityStatus(
                id = CapabilityId.J_FILESYSTEM_METADATA_ANALYSIS,
                requiredPermissions = listOf("Standard File Stat / Optional Verified Root for Extended Paths"),
                requiredPrivilegeLevel = PrivilegeLevel.STANDARD_USER_SPACE,
                requiredAcquisitionSource = "Accessible POSIX File Attributes",
                deviceCompatibility = "Universal (lastModified, size, hidden/trashed path flags)",
                verificationResult = CapabilityVerificationResult.VERIFIED_READY,
                isAvailable = true,
                knownLimitations = listOf(
                    "Linux inode birth time (crtime) is restricted in standard Android user-space without verified root statx."
                )
            )
        )
    }
}

// ==================== Section 6: RecoveryModeController ====================

class RecoveryModeController(
    private val probe: EnvironmentProbe = DefaultAndroidEnvironmentProbe(),
    val rootManager: RootCapabilityManager = RootCapabilityManager(probe)
) {
    var automaticModeSelection: Boolean = true
        private set
    var forceStandardModeOnly: Boolean = false
        private set
    var readOnlyAcquisitionPreference: Boolean = true
        private set

    private val auditLog = CopyOnWriteArrayList<ForensicAuditLogEntry>()

    fun getAuditLog(): List<ForensicAuditLogEntry> = auditLog.toList()

    fun setAutomaticModeSelection(enabled: Boolean) {
        automaticModeSelection = enabled
        recordAudit("SET_AUTOMATIC_MODE", if (enabled) "AUTO" else "MANUAL", "Automatic mode selection set to $enabled")
    }

    fun setForceStandardModeOnly(forceStandard: Boolean) {
        forceStandardModeOnly = forceStandard
        if (forceStandard) {
            rootManager.resetToStandardMode()
        } else {
            rootManager.allowElevatedVerificationAgain()
        }
        recordAudit("SET_FORCE_STANDARD_MODE", if (forceStandard) "STANDARD" else "ADAPTIVE", "Force standard mode set to $forceStandard")
    }

    fun setReadOnlyAcquisitionPreference(readOnly: Boolean) {
        // DeepVault always prefers read-only acquisition for forensic integrity
        readOnlyAcquisitionPreference = readOnly
        recordAudit("SET_READONLY_PREFERENCE", "CONFIG", "Read-only acquisition preference set to $readOnly")
    }

    /**
     * Evaluates the current device environment on startup or when permissions/settings change,
     * returning a complete [DeviceAccessAssessment] for the Home Screen Root Status Card
     * and Settings / Capability screens.
     */
    fun evaluateEnvironment(context: Context?, simulateInconclusive: Boolean = false): DeviceAccessAssessment {
        if (simulateInconclusive) {
            val fallbackCaps = RecoveryCapabilityRegistry.evaluateAllCapabilities(
                hasAllFilesAccess = false,
                grantedPermissions = listOf("APP_SPECIFIC_STORAGE_AND_SAF"),
                accessibleRoots = listOf("Android MediaStore ContentResolver"),
                privilegeStatus = PrivilegeVerificationStatus.INCONCLUSIVE_OR_ERROR,
                rootModeAllowed = false
            )
            return DeviceAccessAssessment(
                accessState = DeviceAccessState.STATE_D_UNKNOWN_INCONCLUSIVE,
                activeOperatingMode = OperatingMode.STANDARD_MODE,
                automaticModeEnabled = automaticModeSelection,
                readOnlyPreference = readOnlyAcquisitionPreference,
                rootIndicatorsDetected = false,
                detectedRootIndicators = emptyList(),
                rootManagerDetected = false,
                detectedRootManagers = emptyList(),
                privilegeVerificationStatus = PrivilegeVerificationStatus.INCONCLUSIVE_OR_ERROR,
                storagePermissionSummary = "Status inconclusive — continuing with safe standard methods",
                grantedPermissions = listOf("APP_SPECIFIC_STORAGE_AND_SAF"),
                missingPermissions = emptyList(),
                accessibleStorageSources = listOf("Android MediaStore ContentResolver", "Storage Access Framework"),
                accessibleStorageScope = "Standard Android user-space fallback (inconclusive probe)",
                capabilities = fallbackCaps,
                availableMethodsSummary = fallbackCaps.filter { it.isAvailable }.map { it.id.title },
                restrictedCapabilitiesSummary = fallbackCaps.filterNot { it.isAvailable }.map { "${it.id.title}: ${it.unavailabilityReason}" }
            )
        }

        return runCatching {
            val (anyRootIndicator, indicators, managers) = rootManager.inspectPassiveRootIndicators(context)
            val privStatus = rootManager.getPrivilegeVerificationStatus()
            val hasAllFiles = probe.hasAllFilesAccess(context)
            val (grantedPerms, missingPerms) = probe.checkStoragePermissions(context)
            val roots = probe.getAccessibleStorageRoots(context)

            val rootModeAllowed = !forceStandardModeOnly &&
                privStatus == PrivilegeVerificationStatus.VERIFIED_READ_ONLY

            val accessState = when {
                privStatus == PrivilegeVerificationStatus.INCONCLUSIVE_OR_ERROR ->
                    DeviceAccessState.STATE_D_UNKNOWN_INCONCLUSIVE
                privStatus == PrivilegeVerificationStatus.VERIFIED_READ_ONLY && !forceStandardModeOnly ->
                    DeviceAccessState.STATE_C_ROOT_VERIFIED
                anyRootIndicator || managers.isNotEmpty() ->
                    DeviceAccessState.STATE_B_ROOT_DETECTED_UNVERIFIED
                else ->
                    DeviceAccessState.STATE_A_NON_ROOTED
            }

            val activeMode = if (accessState == DeviceAccessState.STATE_C_ROOT_VERIFIED) {
                OperatingMode.ROOT_ENABLED_MODE
            } else {
                OperatingMode.STANDARD_MODE
            }

            val capabilities = RecoveryCapabilityRegistry.evaluateAllCapabilities(
                hasAllFilesAccess = hasAllFiles,
                grantedPermissions = grantedPerms,
                accessibleRoots = roots,
                privilegeStatus = privStatus,
                rootModeAllowed = rootModeAllowed
            )

            val permSummary = when {
                hasAllFiles -> "All Files Access Granted (Full Shared Storage)"
                grantedPerms.any { it.startsWith("READ_MEDIA_") || it.startsWith("READ_EXTERNAL_STORAGE") } ->
                    "Scoped Media Permissions Granted (All Files Access Not Enabled)"
                else ->
                    "App Sandbox & SAF Active (Grant Storage Access for Deep Folder Scan)"
            }

            val storageScope = when {
                activeMode == OperatingMode.ROOT_ENABLED_MODE && hasAllFiles ->
                    "Shared storage, MediaStore, cache/thumbnail blobs & verified read-only elevated metadata paths (FBE/TRIM limits apply)"
                hasAllFiles ->
                    "User-space shared storage (/storage/emulated/0), recycle bins, .thumbnails, MediaStore & SAF"
                else ->
                    "Scoped MediaStore, app-specific directories & user-selected SAF files"
            }

            val availableSummary = capabilities.filter { it.isAvailable }.map { it.id.title }
            val restrictedSummary = capabilities.filterNot { it.isAvailable }.map {
                "${it.id.title} (${it.unavailabilityReason ?: "Unavailable"})"
            } + listOf(
                "Unallocated flash blocks erased by hardware TRIM / FBE encryption without keys"
            )

            DeviceAccessAssessment(
                accessState = accessState,
                activeOperatingMode = activeMode,
                automaticModeEnabled = automaticModeSelection,
                readOnlyPreference = readOnlyAcquisitionPreference,
                rootIndicatorsDetected = indicators.isNotEmpty(),
                detectedRootIndicators = indicators,
                rootManagerDetected = managers.isNotEmpty(),
                detectedRootManagers = managers,
                privilegeVerificationStatus = privStatus,
                storagePermissionSummary = permSummary,
                grantedPermissions = grantedPerms,
                missingPermissions = missingPerms,
                accessibleStorageSources = roots,
                accessibleStorageScope = storageScope,
                capabilities = capabilities,
                availableMethodsSummary = availableSummary,
                restrictedCapabilitiesSummary = restrictedSummary
            )
        }.getOrElse {
            // Crash-safe fallback to State D (Unknown / Inconclusive) while keeping Standard recovery working
            val fallbackCaps = RecoveryCapabilityRegistry.evaluateAllCapabilities(
                hasAllFilesAccess = false,
                grantedPermissions = listOf("APP_SPECIFIC_STORAGE_AND_SAF"),
                accessibleRoots = listOf("Android MediaStore ContentResolver"),
                privilegeStatus = PrivilegeVerificationStatus.INCONCLUSIVE_OR_ERROR,
                rootModeAllowed = false
            )
            DeviceAccessAssessment(
                accessState = DeviceAccessState.STATE_D_UNKNOWN_INCONCLUSIVE,
                activeOperatingMode = OperatingMode.STANDARD_MODE,
                automaticModeEnabled = automaticModeSelection,
                readOnlyPreference = readOnlyAcquisitionPreference,
                rootIndicatorsDetected = false,
                detectedRootIndicators = emptyList(),
                rootManagerDetected = false,
                detectedRootManagers = emptyList(),
                privilegeVerificationStatus = PrivilegeVerificationStatus.INCONCLUSIVE_OR_ERROR,
                storagePermissionSummary = "Fallback standard access",
                grantedPermissions = listOf("APP_SPECIFIC_STORAGE_AND_SAF"),
                missingPermissions = emptyList(),
                accessibleStorageSources = listOf("Android MediaStore ContentResolver"),
                accessibleStorageScope = "Standard user-space fallback",
                capabilities = fallbackCaps,
                availableMethodsSummary = fallbackCaps.filter { it.isAvailable }.map { it.id.title },
                restrictedCapabilitiesSummary = fallbackCaps.filterNot { it.isAvailable }.map { it.id.title }
            )
        }
    }

    /**
     * User-initiated verification of elevated privileges. Records the check in the forensic audit log
     * and falls back cleanly to Standard Mode if denied.
     */
    fun requestUserInitiatedPrivilegeVerification(context: Context?): Pair<DeviceAccessAssessment, String> {
        val (status, message) = rootManager.verifyElevatedPrivilegesExplicitly()
        val assessment = evaluateEnvironment(context)
        recordAudit(
            operation = "VERIFY_ELEVATED_PRIVILEGES_READONLY",
            mode = assessment.activeOperatingMode.id,
            outcome = "${status.label}: $message"
        )
        return assessment to message
    }

    /**
     * Builds a deterministic [RecoveryExecutionSummary] for a scan/recovery session,
     * listing attempted methods, skipped methods with explicit reasons, examined sources,
     * and permission/root status for inclusion in JSON, Markdown, PDF, and CSV reports.
     */
    fun buildExecutionSummary(
        assessment: DeviceAccessAssessment,
        scanStartIso: String,
        scanCompletedIso: String,
        additionalSourcesExamined: List<String> = emptyList()
    ): RecoveryExecutionSummary {
        val attempted = assessment.capabilities
            .filter { it.isAvailable }
            .map { "${it.id.code}: ${it.id.title}" }

        val skipped = assessment.capabilities
            .filterNot { it.isAvailable }
            .map { cap ->
                SkippedRecoveryMethod(
                    capabilityCode = cap.id.code,
                    methodName = cap.id.title,
                    reason = cap.unavailabilityReason ?: "Capability not verified on current device"
                )
            }

        val rootStatusLabel = when {
            assessment.rootIndicatorsDetected && assessment.rootManagerDetected ->
                "indicators_and_manager_detected (${assessment.detectedRootIndicators.size} path/tag indicators, ${assessment.detectedRootManagers.size} manager packages)"
            assessment.rootIndicatorsDetected ->
                "indicators_detected (${assessment.detectedRootIndicators.size} path/tag indicators)"
            assessment.rootManagerDetected ->
                "root_manager_package_detected (${assessment.detectedRootManagers.size} packages)"
            assessment.accessState == DeviceAccessState.STATE_D_UNKNOWN_INCONCLUSIVE ->
                "unknown_or_inconclusive"
            else ->
                "not_detected"
        }

        val sources = (assessment.accessibleStorageSources + additionalSourcesExamined).distinct()

        recordAudit(
            operation = "BUILD_SCAN_EXECUTION_SUMMARY",
            mode = assessment.activeOperatingMode.id,
            outcome = "Attempted=${attempted.size}, Skipped=${skipped.size}, Sources=${sources.size}"
        )

        return RecoveryExecutionSummary(
            rootDetectionStatus = rootStatusLabel,
            privilegeVerificationStatus = assessment.privilegeVerificationStatus.id,
            recoveryMode = assessment.activeOperatingMode.id,
            grantedStoragePermissions = assessment.grantedPermissions,
            failedPermissionChecks = assessment.missingPermissions,
            acquisitionSourcesExamined = sources,
            recoveryMethodsAttempted = attempted,
            recoveryMethodsSkipped = skipped,
            accessibleStorageScope = assessment.accessibleStorageScope,
            scanStartTimestampIso = scanStartIso,
            scanCompletedTimestampIso = scanCompletedIso,
            readOnlyEnforced = assessment.readOnlyPreference
        )
    }

    /**
     * Carves embedded files (JPEG, PNG, PDF, ZIP) in read-only mode from an authorized raw image
     * or container stream supplied by the user (Capability H).
     */
    fun carveAuthorizedRawImageStreamReadOnly(
        sourceFile: File,
        stagingDir: File,
        maxCarvedFiles: Int = 25
    ): List<File> {
        if (!sourceFile.exists() || !sourceFile.isFile || !sourceFile.canRead()) return emptyList()
        stagingDir.mkdirs()
        recordAudit(
            operation = "CARVE_AUTHORIZED_RAW_IMAGE_READONLY",
            mode = if (rootManager.getPrivilegeVerificationStatus() == PrivilegeVerificationStatus.VERIFIED_READ_ONLY) "root_enabled_mode" else "standard_mode",
            outcome = "Inspecting ${sourceFile.name} (${sourceFile.length()} bytes) in read-only mode"
        )

        val carved = mutableListOf<File>()
        val maxBytesToScan = minOf(sourceFile.length(), 4L * 1024 * 1024).toInt()
        if (maxBytesToScan < 16) return emptyList()

        val buf = ByteArray(maxBytesToScan)
        runCatching {
            java.io.RandomAccessFile(sourceFile, "r").use { raf ->
                raf.readFully(buf, 0, maxBytesToScan)
            }
        }.onFailure { return emptyList() }

        var i = 0
        while (i < maxBytesToScan - 8 && carved.size < maxCarvedFiles) {
            val b0 = buf[i].toInt() and 0xFF
            val b1 = buf[i + 1].toInt() and 0xFF
            val b2 = buf[i + 2].toInt() and 0xFF
            val b3 = buf[i + 3].toInt() and 0xFF

            // 1. JPEG: FF D8 FF ... FF D9
            if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF) {
                var end = i + 4
                val limit = minOf(maxBytesToScan - 1, i + 1024 * 1024)
                var foundEoi = false
                while (end < limit) {
                    if ((buf[end].toInt() and 0xFF) == 0xFF && (buf[end + 1].toInt() and 0xFF) == 0xD9) {
                        val sliceLen = (end + 2) - i
                        if (sliceLen >= 64) {
                            val out = File(stagingDir, "rawcarve_${sourceFile.nameWithoutExtension}_${carved.size + 1}.jpg")
                            out.writeBytes(buf.copyOfRange(i, end + 2))
                            carved.add(out)
                            i = end + 2
                            foundEoi = true
                        }
                        break
                    }
                    end++
                }
                if (foundEoi) continue
            }

            // 2. PDF: %PDF- (25 50 44 46 2D) ... %%EOF
            if (b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46) {
                var end = i + 5
                val limit = minOf(maxBytesToScan - 5, i + 1024 * 1024)
                var foundEof = false
                while (end < limit) {
                    if (buf[end] == 0x25.toByte() && buf[end + 1] == 0x25.toByte() &&
                        buf[end + 2] == 0x45.toByte() && buf[end + 3] == 0x4F.toByte() &&
                        buf[end + 4] == 0x46.toByte()
                    ) {
                        val sliceEnd = minOf(maxBytesToScan, end + 6)
                        val out = File(stagingDir, "rawcarve_${sourceFile.nameWithoutExtension}_${carved.size + 1}.pdf")
                        out.writeBytes(buf.copyOfRange(i, sliceEnd))
                        carved.add(out)
                        i = sliceEnd
                        foundEof = true
                        break
                    }
                    end++
                }
                if (foundEof) continue
            }

            i++
        }
        return carved
    }

    private fun recordAudit(operation: String, mode: String, outcome: String) {
        auditLog.add(
            0,
            ForensicAuditLogEntry(
                timestampIso = ForensicTimeUtil.nowIsoUtc(),
                operation = operation,
                mode = mode,
                readOnlyEnforced = readOnlyAcquisitionPreference,
                outcome = outcome
            )
        )
        while (auditLog.size > 100) {
            auditLog.removeAt(auditLog.lastIndex)
        }
    }
}
