package com.clone.filesrecovery.forensics

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import androidx.core.content.ContextCompat
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Adaptive operating mode for DeepVault.
 */
enum class OperatingMode(val id: String, val displayName: String, val badgeText: String) {
    STANDARD("standard_mode", "Standard", "STANDARD MODE"),
    ROOT_ENABLED("root_enabled_mode", "Root-Enabled (Read-Only)", "ROOT-ENABLED MODE");

    companion object {
        val STANDARD_MODE: OperatingMode get() = STANDARD
        val ROOT_ENABLED_MODE: OperatingMode get() = ROOT_ENABLED
    }
}

/**
 * Dynamically assessed root & privilege state of the Android device.
 */
enum class DeviceRootState {
    /** State A: Non-rooted device (no su binary or root manager present, or standard mode forced). */
    NON_ROOTED,

    /** State B: Root indicators / su binary detected, but superuser shell access has not been verified yet. */
    ROOT_DETECTED_NOT_GRANTED,

    /** State C: Verified superuser (uid=0) shell access granted with verified read-only forensic capabilities. */
    ROOT_ENABLED,

    /** State D: Root shell responded, but SELinux enforcing, mount namespace, or FBE blocks privileged storage paths. */
    ROOT_RESTRICTED,

    /** State E: Root authorization was explicitly requested by the user, and su denied/rejected the request. */
    ROOT_ACCESS_DENIED,

    /** State F: Root/environment probe threw an unexpected error or returned inconclusive status. */
    ROOT_STATUS_UNKNOWN
}

enum class CapabilityAvailability(val label: String) {
    AVAILABLE("Available"),
    LIMITED("Limited"),
    RESTRICTED("Restricted")
}

/**
 * Describes a specific recovery or forensic inspection method and its real availability on the current device.
 */
data class RecoveryMethodCapability(
    val id: String,
    val title: String,
    val description: String,
    val requiresRoot: Boolean,
    val availability: CapabilityAvailability,
    val statusReason: String
)

/**
 * Complete, deterministic assessment of the device's root status, storage permissions,
 * encryption constraints, active operating mode, available recovery methods, and restricted capabilities.
 */
data class DeviceEnvironmentAssessment(
    val rootState: DeviceRootState = DeviceRootState.NON_ROOTED,
    val activeOperatingMode: OperatingMode = OperatingMode.STANDARD,
    val cardTitle: String = "STANDARD MODE ACTIVE",
    val cardStatusLine: String = "Root access not detected.",
    val cardDescription: String = "DeepVault is using Android-supported storage access and non-root recovery methods.",
    val deviceRootStatusLabel: String = "Not detected",
    val storageAccessStatusLabel: String = "Checking permissions…",
    val hasStorageAccess: Boolean = false,
    val recoveryModeLabel: String = "Standard",
    val suBinaryPath: String? = null,
    val rootManagerPackage: String? = null,
    val testKeysDetected: Boolean = false,
    val rootShellVerifiedUid0: Boolean = false,
    val userForcedStandardMode: Boolean = false,
    val selinuxMode: String = "Enforcing",
    val encryptionState: String = "File-Based Encryption (FBE)",
    val canReadDataMedia: Boolean = false,
    val canReadMediaStoreWal: Boolean = false,
    val rawBlockAccessStatus: String = "Restricted (Kernel & FBE Protected)",
    val availableMethods: List<RecoveryMethodCapability> = emptyList(),
    val restrictedCapabilities: List<RecoveryMethodCapability> = emptyList(),
    val forensicLimitationsNotes: List<String> = emptyList(),
    val androidRelease: String = Build.VERSION.RELEASE ?: "Android",
    val sdkInt: Int = Build.VERSION.SDK_INT,
    val deviceModel: String = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
    val assessedAtIso: String = ForensicTimeUtil.nowIsoUtc()
)

/**
 * Abstraction over low-level system/root probing so unit and Robolectric tests can deterministically
 * verify all 4 adaptive root states (NON_ROOTED, ROOT_DETECTED_NOT_GRANTED, ROOT_ENABLED, ROOT_RESTRICTED)
 * while production code probes the real Android environment safely.
 */
interface RootEnvironmentProbe {
    fun findSuBinaryPath(): String?
    fun detectRootManagerPackage(context: Context): String?
    fun hasTestKeysBuildTag(): Boolean
    fun getSelinuxStatus(): String
    fun getEncryptionStatus(): String
    fun verifyRootShellUid0(timeoutMs: Long = 2500L): Boolean
    fun canReadPathWithRoot(path: String, timeoutMs: Long = 2000L): Boolean
    fun listFilesWithRootReadOnly(directories: List<String>, maxDepth: Int = 4, timeoutMs: Long = 4000L): List<RootDiscoveredFile>
}

data class RootDiscoveredFile(
    val path: String,
    val sizeBytes: Long,
    val lastModifiedEpochSec: Long,
    val originLabel: String
)

/**
 * Production implementation of [RootEnvironmentProbe] using strictly read-only, timeout-bounded
 * inspection commands. Never modifies system partitions or user files.
 */
object SystemRootEnvironmentProbe : RootEnvironmentProbe {

    private val KNOWN_SU_PATHS = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        "/apex/com.android.runtime/bin/su",
        "/data/adb/magisk/busybox",
        "/data/adb/ksu/bin/su",
        "/data/adb/ap/bin/su"
    )

    private val KNOWN_ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk" to "Magisk",
        "io.github.vvb2060.magisk" to "Magisk Alpha",
        "me.weishu.kernelsu" to "KernelSU",
        "me.bmax.apatch" to "APatch",
        "eu.chainfire.supersu" to "SuperSU"
    )

    override fun findSuBinaryPath(): String? {
        for (p in KNOWN_SU_PATHS) {
            val f = runCatching { File(p) }.getOrNull() ?: continue
            if (runCatching { f.exists() }.getOrDefault(false)) {
                return p
            }
        }
        val pathEnv = runCatching { System.getenv("PATH") }.getOrNull() ?: return null
        for (dir in pathEnv.split(':')) {
            if (dir.isBlank()) continue
            val candidate = File(dir, "su")
            if (runCatching { candidate.exists() }.getOrDefault(false)) {
                return candidate.absolutePath
            }
        }
        return null
    }

    override fun detectRootManagerPackage(context: Context): String? {
        val pm = context.packageManager
        for ((pkg, label) in KNOWN_ROOT_PACKAGES) {
            val installed = runCatching {
                pm.getPackageInfo(pkg, 0)
                true
            }.getOrDefault(false)
            if (installed) return "$label ($pkg)"
        }
        return null
    }

    override fun hasTestKeysBuildTag(): Boolean {
        return Build.TAGS?.contains("test-keys", ignoreCase = true) == true
    }

    override fun getSelinuxStatus(): String {
        val sysFs = runCatching {
            val f = File("/sys/fs/selinux/enforce")
            if (f.exists() && f.canRead()) {
                when (f.readText().trim()) {
                    "1" -> "Enforcing"
                    "0" -> "Permissive"
                    else -> null
                }
            } else null
        }.getOrNull()
        if (sysFs != null) return sysFs

        val out = runProcessCommand(listOf("getenforce"), 1200L)?.trim()
        return when {
            out.equals("Enforcing", ignoreCase = true) -> "Enforcing"
            out.equals("Permissive", ignoreCase = true) -> "Permissive"
            out.equals("Disabled", ignoreCase = true) -> "Disabled"
            else -> "Enforcing (Android Default)"
        }
    }

    override fun getEncryptionStatus(): String {
        val cryptoType = getSystemProp("ro.crypto.type")?.lowercase(Locale.US)
        val cryptoState = getSystemProp("ro.crypto.state")?.lowercase(Locale.US)
        return when {
            cryptoType == "file" -> "File-Based Encryption (FBE)"
            cryptoType == "block" -> "Full-Disk Encryption (FDE)"
            cryptoState == "encrypted" && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                "File-Based Encryption (FBE)"
            cryptoState == "encrypted" -> "Hardware-Backed Storage Encryption"
            cryptoState == "unencrypted" -> "Unencrypted"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> "File-Based Encryption (FBE)"
            else -> "Encrypted (Standard Android)"
        }
    }

    override fun verifyRootShellUid0(timeoutMs: Long): Boolean {
        val out = runRootCommand("id", timeoutMs) ?: return false
        return out.contains("uid=0", ignoreCase = true)
    }

    override fun canReadPathWithRoot(path: String, timeoutMs: Long): Boolean {
        val escaped = path.replace("'", "'\\''")
        val out = runRootCommand("ls -d '$escaped' >/dev/null 2>&1 && echo DV_OK", timeoutMs) ?: return false
        return out.contains("DV_OK")
    }

    override fun listFilesWithRootReadOnly(
        directories: List<String>,
        maxDepth: Int,
        timeoutMs: Long
    ): List<RootDiscoveredFile> {
        val results = ArrayList<RootDiscoveredFile>()
        for (dir in directories) {
            val escaped = dir.replace("'", "'\\''")
            // Strictly read-only stat listing: path|size|mtime
            val cmd = "find '$escaped' -maxdepth $maxDepth -type f -exec stat -c '%n|%s|%Y' {} + 2>/dev/null"
            val output = runRootCommand(cmd, timeoutMs) ?: continue
            val origin = when {
                dir.contains("providers.media", ignoreCase = true) -> "Root MediaStore DB / WAL"
                dir.contains(".Trash", ignoreCase = true) || dir.contains("trash", ignoreCase = true) -> "Root Privileged Trash"
                dir.contains("cache", ignoreCase = true) -> "Root App Sandbox Cache"
                else -> "Root Read-Only VFS"
            }
            output.lineSequence().forEach { line ->
                val parts = line.trim().split('|')
                if (parts.size >= 3) {
                    val filePath = parts[0]
                    val size = parts[1].toLongOrNull() ?: 0L
                    val mtime = parts[2].toLongOrNull() ?: 0L
                    if (filePath.isNotBlank() && size > 0L) {
                        results += RootDiscoveredFile(
                            path = filePath,
                            sizeBytes = size,
                            lastModifiedEpochSec = mtime,
                            originLabel = origin
                        )
                    }
                }
            }
        }
        return results
    }

    private fun getSystemProp(key: String): String? {
        return runProcessCommand(listOf("getprop", key), 1000L)?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun runRootCommand(command: String, timeoutMs: Long): String? {
        return runProcessCommand(listOf("su", "-c", command), timeoutMs)
    }

    private fun runProcessCommand(cmd: List<String>, timeoutMs: Long): String? = runCatching {
        val process = ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start()
        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            return null
        }
        if (process.exitValue() != 0) return null
        BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
            val sb = StringBuilder()
            var line: String?
            var linesRead = 0
            while (reader.readLine().also { line = it } != null && linesRead < 2500) {
                sb.appendLine(line)
                linesRead++
            }
            sb.toString()
        }
    }.getOrNull()
}

/**
 * Deterministic Dual-Mode Environment Assessor & Privileged Read-Only Scanner.
 *
 * Evaluates whether the device is operating in:
 * - STANDARD MODE (non-rooted, or root not granted / user-forced standard mode)
 * - ROOT-ENABLED MODE (only when uid=0 shell and real capabilities are verified)
 */
object DeviceEnvironmentAssessor {

    @Volatile
    var probe: RootEnvironmentProbe = SystemRootEnvironmentProbe

    /**
     * Evaluates storage permissions using standard Android APIs.
     */
    fun evaluateStoragePermissions(context: Context): Pair<Boolean, String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val allFiles = runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)
            if (allFiles) {
                true to "All Files Access (MANAGE_EXTERNAL_STORAGE) Granted"
            } else {
                val hasMedia = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ContextCompat.checkSelfPermission(context, Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED ||
                        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_MEDIA_VIDEO) == PackageManager.PERMISSION_GRANTED
                } else {
                    ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
                }
                if (hasMedia) {
                    false to "Scoped Media Access Only (All Files Access Not Granted)"
                } else {
                    false to "Restricted (Storage Permission Not Granted)"
                }
            }
        } else {
            val readGranted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
            if (readGranted) {
                true to "Legacy External Storage Read/Write Granted"
            } else {
                false to "Restricted (READ_EXTERNAL_STORAGE Not Granted)"
            }
        }
    }

    /**
     * Performs a complete environment assessment without faking or exaggerating capabilities.
     *
     * @param context Application or Activity context
     * @param verifyRootShell If true (or if a su binary is present and not forced into standard mode),
     *                        attempts a non-blocking, timeout-bounded `su -c id` verification.
     * @param forceStandardMode If true, locks DeepVault into Standard Mode even if the device is rooted.
     */
    suspend fun assess(
        context: Context,
        verifyRootShell: Boolean = false,
        forceStandardMode: Boolean = false
    ): DeviceEnvironmentAssessment = withContext(Dispatchers.IO) {
        val (hasFullStorage, storageLabel) = evaluateStoragePermissions(context)
        val suPath = runCatching { probe.findSuBinaryPath() }.getOrNull()
        val rootManager = runCatching { probe.detectRootManagerPackage(context) }.getOrNull()
        val testKeys = runCatching { probe.hasTestKeysBuildTag() }.getOrDefault(false)
        val selinux = runCatching { probe.getSelinuxStatus() }.getOrDefault("Enforcing")
        val encryption = runCatching { probe.getEncryptionStatus() }.getOrDefault("File-Based Encryption (FBE)")
        val isFbe = encryption.contains("FBE", ignoreCase = true) || encryption.contains("File-Based", ignoreCase = true)

        val anyRootIndicator = suPath != null || rootManager != null

        var uid0Verified = false
        var canReadDataMedia = false
        var canReadMediaWal = false

        if (anyRootIndicator && !forceStandardMode && verifyRootShell) {
            uid0Verified = runCatching { probe.verifyRootShellUid0(2500L) }.getOrDefault(false)
            if (uid0Verified) {
                canReadDataMedia = runCatching { probe.canReadPathWithRoot("/data/media/0", 1800L) }.getOrDefault(false)
                canReadMediaWal = runCatching {
                    probe.canReadPathWithRoot("/data/data/com.android.providers.media.module/databases", 1800L) ||
                        probe.canReadPathWithRoot("/data/data/com.android.providers.media/databases", 1800L)
                }.getOrDefault(false)
            }
        }

        val rootState = when {
            !anyRootIndicator -> DeviceRootState.NON_ROOTED
            forceStandardMode || !uid0Verified -> DeviceRootState.ROOT_DETECTED_NOT_GRANTED
            canReadDataMedia || canReadMediaWal -> DeviceRootState.ROOT_ENABLED
            else -> DeviceRootState.ROOT_RESTRICTED
        }

        val activeMode = if (rootState == DeviceRootState.ROOT_ENABLED || rootState == DeviceRootState.ROOT_RESTRICTED) {
            OperatingMode.ROOT_ENABLED
        } else {
            OperatingMode.STANDARD
        }

        val allCapabilities = buildCapabilitiesList(
            hasFullStorage = hasFullStorage,
            uid0Verified = uid0Verified && !forceStandardMode,
            canReadDataMedia = canReadDataMedia,
            canReadMediaWal = canReadMediaWal,
            isFbe = isFbe,
            selinux = selinux
        )

        val availableMethods = allCapabilities.filter {
            it.availability == CapabilityAvailability.AVAILABLE || it.availability == CapabilityAvailability.LIMITED
        }
        val restrictedCapabilities = allCapabilities.filter {
            it.availability == CapabilityAvailability.RESTRICTED
        }

        val limitations = buildHonestForensicLimitations(
            rootState = rootState,
            hasFullStorage = hasFullStorage,
            isFbe = isFbe,
            selinux = selinux
        )

        when (rootState) {
            DeviceRootState.NON_ROOTED -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.NON_ROOTED,
                activeOperatingMode = OperatingMode.STANDARD,
                cardTitle = "STANDARD MODE ACTIVE",
                cardStatusLine = "Root access not detected.",
                cardDescription = "DeepVault is using Android-supported storage access and non-root recovery methods.",
                deviceRootStatusLabel = "Not detected",
                storageAccessStatusLabel = storageLabel,
                hasStorageAccess = hasFullStorage,
                recoveryModeLabel = "Standard",
                suBinaryPath = null,
                rootManagerPackage = null,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = false,
                userForcedStandardMode = forceStandardMode,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = false,
                canReadMediaStoreWal = false,
                rawBlockAccessStatus = "Unavailable (Requires Root + Unencrypted Block Access)",
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )

            DeviceRootState.ROOT_DETECTED_NOT_GRANTED -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.ROOT_DETECTED_NOT_GRANTED,
                activeOperatingMode = OperatingMode.STANDARD,
                cardTitle = if (forceStandardMode) "STANDARD MODE ACTIVE (USER SELECTED)" else "STANDARD MODE ACTIVE (ROOT NOT GRANTED)",
                cardStatusLine = if (forceStandardMode) {
                    "Root environment detected, but Standard Mode is manually locked."
                } else {
                    "Root environment detected, but superuser permission is not granted."
                },
                cardDescription = "DeepVault is using Android-supported storage access and non-root recovery methods. Grant or verify superuser access only if you wish to enable read-only root inspection.",
                deviceRootStatusLabel = if (forceStandardMode) {
                    "Detected (${suPath ?: rootManager ?: "su"}) — Bypassed"
                } else {
                    "Detected (${suPath ?: rootManager ?: "su"}) — Not Granted"
                },
                storageAccessStatusLabel = storageLabel,
                hasStorageAccess = hasFullStorage,
                recoveryModeLabel = "Standard",
                suBinaryPath = suPath,
                rootManagerPackage = rootManager,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = false,
                userForcedStandardMode = forceStandardMode,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = false,
                canReadMediaStoreWal = false,
                rawBlockAccessStatus = "Unavailable (Root Shell Not Authorized)",
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )

            DeviceRootState.ROOT_ENABLED -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.ROOT_ENABLED,
                activeOperatingMode = OperatingMode.ROOT_ENABLED,
                cardTitle = "ROOT-ENABLED MODE ACTIVE",
                cardStatusLine = "Verified superuser (uid=0) read-only access active.",
                cardDescription = "DeepVault is using verified read-only root capabilities alongside standard carving. Hardware File-Based Encryption (FBE) and TRIM constraints still apply.",
                deviceRootStatusLabel = "Verified (uid=0 • ${suPath ?: "su"})",
                storageAccessStatusLabel = "$storageLabel + Root VFS Read-Only",
                hasStorageAccess = true,
                recoveryModeLabel = "Root-Enabled (Read-Only)",
                suBinaryPath = suPath,
                rootManagerPackage = rootManager,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = true,
                userForcedStandardMode = false,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = canReadDataMedia,
                canReadMediaStoreWal = canReadMediaWal,
                rawBlockAccessStatus = if (isFbe) {
                    "Limited by FBE (Unallocated blocks contain per-file encrypted ciphertext)"
                } else {
                    "Read-Only Partition Inspection Available"
                },
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )

            DeviceRootState.ROOT_RESTRICTED -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.ROOT_RESTRICTED,
                activeOperatingMode = OperatingMode.ROOT_ENABLED,
                cardTitle = "ROOT-ENABLED MODE (RESTRICTED)",
                cardStatusLine = "Root shell active, but SELinux / mount namespace restricts private partitions.",
                cardDescription = "Superuser shell responded, but SELinux ($selinux) or FBE restricts direct /data sandbox reads. DeepVault is combining accessible root paths with Standard Mode recovery.",
                deviceRootStatusLabel = "Verified (uid=0) — Restricted by SELinux/FBE",
                storageAccessStatusLabel = storageLabel,
                hasStorageAccess = hasFullStorage,
                recoveryModeLabel = "Hybrid (Root-Assisted Standard)",
                suBinaryPath = suPath,
                rootManagerPackage = rootManager,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = true,
                userForcedStandardMode = false,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = false,
                canReadMediaStoreWal = false,
                rawBlockAccessStatus = "Blocked by SELinux / File-Based Encryption",
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )

            DeviceRootState.ROOT_ACCESS_DENIED -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.ROOT_ACCESS_DENIED,
                activeOperatingMode = OperatingMode.STANDARD,
                cardTitle = "ROOT ACCESS DENIED",
                cardStatusLine = "User or root manager denied the authorization request.",
                cardDescription = "DeepVault fell back safely to Standard Mode using Android-supported storage access and non-root recovery methods.",
                deviceRootStatusLabel = "Denied (${suPath ?: rootManager ?: "su"})",
                storageAccessStatusLabel = storageLabel,
                hasStorageAccess = hasFullStorage,
                recoveryModeLabel = "Standard (Fallback)",
                suBinaryPath = suPath,
                rootManagerPackage = rootManager,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = false,
                userForcedStandardMode = forceStandardMode,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = false,
                canReadMediaStoreWal = false,
                rawBlockAccessStatus = "Unavailable (Root Authorization Denied)",
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )

            DeviceRootState.ROOT_STATUS_UNKNOWN -> DeviceEnvironmentAssessment(
                rootState = DeviceRootState.ROOT_STATUS_UNKNOWN,
                activeOperatingMode = OperatingMode.STANDARD,
                cardTitle = "ROOT STATUS UNKNOWN",
                cardStatusLine = "Root or storage-access status could not be established.",
                cardDescription = "DeepVault defaulted to safe Standard Mode using verified non-root Android storage APIs.",
                deviceRootStatusLabel = "Unknown / Inconclusive",
                storageAccessStatusLabel = storageLabel,
                hasStorageAccess = hasFullStorage,
                recoveryModeLabel = "Standard (Safe Default)",
                suBinaryPath = suPath,
                rootManagerPackage = rootManager,
                testKeysDetected = testKeys,
                rootShellVerifiedUid0 = false,
                userForcedStandardMode = forceStandardMode,
                selinuxMode = selinux,
                encryptionState = encryption,
                canReadDataMedia = false,
                canReadMediaStoreWal = false,
                rawBlockAccessStatus = "Unknown (Defaulted to Standard Mode)",
                availableMethods = availableMethods,
                restrictedCapabilities = restrictedCapabilities,
                forensicLimitationsNotes = limitations
            )
        }
    }

    /**
     * Executes strictly read-only privileged discovery when [DeviceEnvironmentAssessment.activeOperatingMode]
     * is [OperatingMode.ROOT_ENABLED] and `rootShellVerifiedUid0` is true.
     * Never returns fake or simulated files.
     */
    suspend fun scanPrivilegedRootFiles(
        category: FileCategory,
        assessment: DeviceEnvironmentAssessment
    ): List<RecoverableFile> = withContext(Dispatchers.IO) {
        if (assessment.activeOperatingMode != OperatingMode.ROOT_ENABLED || !assessment.rootShellVerifiedUid0) {
            return@withContext emptyList()
        }
        val candidateDirs = buildList {
            if (assessment.canReadDataMedia) {
                add("/data/media/0/.Trash")
                add("/data/media/0/.trash")
                add("/data/media/0/DCIM/.thumbnails")
                add("/data/media/0/Pictures/.thumbnails")
                add("/data/media/0/Android/data")
            }
        }
        if (candidateDirs.isEmpty()) return@withContext emptyList()

        val discovered = runCatching {
            probe.listFilesWithRootReadOnly(candidateDirs, maxDepth = 4, timeoutMs = 4000L)
        }.getOrDefault(emptyList())

        val results = ArrayList<RecoverableFile>()
        for (item in discovered) {
            val name = item.path.substringAfterLast('/')
            val ext = name.substringAfterLast('.', "").lowercase(Locale.US)
            val matchedCat = FileCategory.fromExtension(ext)
            if (matchedCat == category && item.sizeBytes > 0L) {
                results += RecoverableFile(
                    path = item.path,
                    name = name,
                    category = category,
                    size = item.sizeBytes,
                    lastModified = item.lastModifiedEpochSec * 1000L,
                    isHiddenOrTrashed = true,
                    recoveryOrigin = item.originLabel,
                    detectedExt = ext
                )
            }
        }
        results
    }

    private fun buildCapabilitiesList(
        hasFullStorage: Boolean,
        uid0Verified: Boolean,
        canReadDataMedia: Boolean,
        canReadMediaWal: Boolean,
        isFbe: Boolean,
        selinux: String
    ): List<RecoveryMethodCapability> {
        return listOf(
            RecoveryMethodCapability(
                id = "shared_storage_walk",
                title = "Shared Storage & Directory Traversal",
                description = "Scans user-accessible shared storage (/storage/emulated/0), Downloads, DCIM, Pictures, Movies, Music, and Documents.",
                requiresRoot = false,
                availability = if (hasFullStorage) CapabilityAvailability.AVAILABLE else CapabilityAvailability.LIMITED,
                statusReason = if (hasFullStorage) {
                    "Active via All Files Access permission."
                } else {
                    "Limited to MediaStore-indexed files until All Files Access is granted."
                }
            ),
            RecoveryMethodCapability(
                id = "hidden_trash_recycle",
                title = "Hidden .Trash, .trashed-* & Recycle Bin Scan",
                description = "Locates soft-deleted files retained in hidden .Trash, .recycle, and OEM gallery trash folders prior to permanent purge.",
                requiresRoot = false,
                availability = if (hasFullStorage || canReadDataMedia) CapabilityAvailability.AVAILABLE else CapabilityAvailability.LIMITED,
                statusReason = if (hasFullStorage || canReadDataMedia) {
                    "Active across hidden dot-directories and trash staging folders."
                } else {
                    "Requires All Files Access to inspect hidden dot-folders outside MediaStore."
                }
            ),
            RecoveryMethodCapability(
                id = "thumbdata_carving",
                title = ".thumbdata Binary Stream JPEG Carving",
                description = "Carves embedded SOI (FF D8 FF) to EOI (FF D9) JPEG frames out of monolithic .thumbdata3/.thumbdata4 cache containers.",
                requiresRoot = false,
                availability = if (hasFullStorage || canReadDataMedia) CapabilityAvailability.AVAILABLE else CapabilityAvailability.LIMITED,
                statusReason = if (hasFullStorage || canReadDataMedia) {
                    "Active with bounded 2 MB sliding window memory protection."
                } else {
                    "Grant All Files Access to read DCIM/.thumbnails container files."
                }
            ),
            RecoveryMethodCapability(
                id = "mediastore_trashed_query",
                title = "MediaStore Trashed & Pending Index Query",
                description = "Queries Android 11+ MediaStore with MATCH_TRASHED and MATCH_PENDING flags for unpurged media entries.",
                requiresRoot = false,
                availability = CapabilityAvailability.AVAILABLE,
                statusReason = "Supported natively via Android ContentResolver."
            ),
            RecoveryMethodCapability(
                id = "magic_byte_validation",
                title = "Magic-Byte Signature & Structural Verification",
                description = "Detects renamed or extension-stripped files by inspecting binary headers/footers (JPEG, PNG, PDF, ZIP/OOXML, MP4, WAV, MP3).",
                requiresRoot = false,
                availability = CapabilityAvailability.AVAILABLE,
                statusReason = "Deterministic offline parser suite active."
            ),
            RecoveryMethodCapability(
                id = "root_data_media_sandbox",
                title = "Privileged /data/media & App Sandbox Cache Inspection",
                description = "Read-only inspection of Scoped-Storage-restricted /Android/data caches and /data/media/0 staging directories.",
                requiresRoot = true,
                availability = when {
                    uid0Verified && canReadDataMedia -> CapabilityAvailability.AVAILABLE
                    uid0Verified -> CapabilityAvailability.RESTRICTED
                    else -> CapabilityAvailability.RESTRICTED
                },
                statusReason = when {
                    uid0Verified && canReadDataMedia -> "Verified read-only root access to /data/media/0."
                    uid0Verified -> "Blocked by SELinux ($selinux) or mount namespace isolation."
                    else -> "Requires Root-Enabled Mode (verified uid=0 shell)."
                }
            ),
            RecoveryMethodCapability(
                id = "root_mediastore_wal",
                title = "MediaStore SQLite Database & WAL Record Inspection",
                description = "Read-only inspection of system MediaStore SQLite databases and write-ahead logs (-wal) for recently deleted path metadata.",
                requiresRoot = true,
                availability = if (uid0Verified && canReadMediaWal) {
                    CapabilityAvailability.AVAILABLE
                } else {
                    CapabilityAvailability.RESTRICTED
                },
                statusReason = if (uid0Verified && canReadMediaWal) {
                    "Read-only access to MediaProvider SQLite database directory verified."
                } else {
                    "Restricted in Standard Mode; requires verified root read access to /data/data/com.android.providers.media*."
                }
            ),
            RecoveryMethodCapability(
                id = "raw_block_unallocated_carving",
                title = "Raw Block / Unallocated Partition Sector Carving",
                description = "Low-level block carving of unallocated filesystem sectors (/dev/block/by-name/userdata).",
                requiresRoot = true,
                availability = when {
                    !uid0Verified -> CapabilityAvailability.RESTRICTED
                    isFbe -> CapabilityAvailability.LIMITED
                    else -> CapabilityAvailability.LIMITED
                },
                statusReason = when {
                    !uid0Verified -> "Restricted in Standard Mode (kernel blocks direct /dev/block access without root)."
                    isFbe -> "Severely limited by File-Based Encryption (FBE) & flash TRIM: deleted files have per-file keys evicted upon unlink, leaving unallocated blocks as non-decryptable ciphertext."
                    else -> "Limited by filesystem TRIM/discard and SELinux block device policies."
                }
            )
        )
    }

    private fun buildHonestForensicLimitations(
        rootState: DeviceRootState,
        hasFullStorage: Boolean,
        isFbe: Boolean,
        selinux: String
    ): List<String> {
        val notes = ArrayList<String>()
        if (rootState == DeviceRootState.NON_ROOTED || rootState == DeviceRootState.ROOT_DETECTED_NOT_GRANTED) {
            notes += "Standard Mode operates strictly within Android's non-root security model. Private app sandboxes (/data/data) and raw block devices (/dev/block) are inaccessible without root."
        } else {
            notes += "Root-Enabled Mode uses strictly read-only inspection commands. DeepVault never remounts system partitions read-write or alters live filesystem structures."
        }
        if (!hasFullStorage) {
            notes += "All Files Access (MANAGE_EXTERNAL_STORAGE) is not currently granted; hidden .Trash and .thumbnails directories outside MediaStore may be skipped until granted."
        }
        if (isFbe) {
            notes += "File-Based Encryption (FBE) is active on this device. When a file is permanently unlinked and its inode key is evicted by the kernel/keystore, raw unallocated disk blocks contain encrypted ciphertext that cannot be carved even with root access."
        }
        notes += "UFS/eMMC flash storage controllers execute asynchronous TRIM/DISCARD on freed blocks, which zeroes unallocated sectors shortly after permanent deletion."
        notes += "SELinux policy status: $selinux."
        return notes
    }
}
