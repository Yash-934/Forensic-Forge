package com.clone.filesrecovery.forensics

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.clone.filesrecovery.MainActivity
import com.clone.filesrecovery.data.FileCategory
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AdaptiveDualModeTest {

    @After
    fun tearDown() {
        DeviceEnvironmentAssessor.probe = SystemRootEnvironmentProbe
    }

    @Test
    fun `state A non-rooted device reports STANDARD MODE ACTIVE and never claims root capabilities`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        DeviceEnvironmentAssessor.probe = object : RootEnvironmentProbe {
            override fun findSuBinaryPath(): String? = null
            override fun detectRootManagerPackage(context: Context): String? = null
            override fun hasTestKeysBuildTag(): Boolean = false
            override fun getSelinuxStatus(): String = "Enforcing"
            override fun getEncryptionStatus(): String = "File-Based Encryption (FBE)"
            override fun verifyRootShellUid0(timeoutMs: Long): Boolean = false
            override fun canReadPathWithRoot(path: String, timeoutMs: Long): Boolean = false
            override fun listFilesWithRootReadOnly(
                directories: List<String>,
                maxDepth: Int,
                timeoutMs: Long
            ): List<RootDiscoveredFile> = emptyList()
        }

        val assessment = DeviceEnvironmentAssessor.assess(context, verifyRootShell = false, forceStandardMode = false)
        assertEquals(DeviceRootState.NON_ROOTED, assessment.rootState)
        assertEquals(OperatingMode.STANDARD, assessment.activeOperatingMode)
        assertEquals("STANDARD MODE ACTIVE", assessment.cardTitle)
        assertEquals("Root access not detected.", assessment.cardStatusLine)
        assertEquals(
            "DeepVault is using Android-supported storage access and non-root recovery methods.",
            assessment.cardDescription
        )
        assertEquals("Not detected", assessment.deviceRootStatusLabel)
        assertEquals("Standard", assessment.recoveryModeLabel)
        assertFalse(assessment.rootShellVerifiedUid0)
        assertTrue(assessment.availableMethods.isNotEmpty())
        assertTrue(assessment.restrictedCapabilities.any { it.requiresRoot })
    }

    @Test
    fun `state B root detected but not granted stays safely in STANDARD MODE`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        DeviceEnvironmentAssessor.probe = object : RootEnvironmentProbe {
            override fun findSuBinaryPath(): String? = "/system/bin/su"
            override fun detectRootManagerPackage(context: Context): String? = "Magisk (com.topjohnwu.magisk)"
            override fun hasTestKeysBuildTag(): Boolean = true
            override fun getSelinuxStatus(): String = "Enforcing"
            override fun getEncryptionStatus(): String = "File-Based Encryption (FBE)"
            override fun verifyRootShellUid0(timeoutMs: Long): Boolean = false
            override fun canReadPathWithRoot(path: String, timeoutMs: Long): Boolean = false
            override fun listFilesWithRootReadOnly(
                directories: List<String>,
                maxDepth: Int,
                timeoutMs: Long
            ): List<RootDiscoveredFile> = emptyList()
        }

        val assessment = DeviceEnvironmentAssessor.assess(context, verifyRootShell = true, forceStandardMode = false)
        assertEquals(DeviceRootState.ROOT_DETECTED_NOT_GRANTED, assessment.rootState)
        assertEquals(OperatingMode.STANDARD, assessment.activeOperatingMode)
        assertFalse(assessment.rootShellVerifiedUid0)
        assertEquals("Standard", assessment.recoveryModeLabel)
    }

    @Test
    fun `state C verified root shell enables ROOT-ENABLED MODE while disclosing FBE limits`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        DeviceEnvironmentAssessor.probe = object : RootEnvironmentProbe {
            override fun findSuBinaryPath(): String? = "/system/bin/su"
            override fun detectRootManagerPackage(context: Context): String? = "Magisk (com.topjohnwu.magisk)"
            override fun hasTestKeysBuildTag(): Boolean = false
            override fun getSelinuxStatus(): String = "Enforcing"
            override fun getEncryptionStatus(): String = "File-Based Encryption (FBE)"
            override fun verifyRootShellUid0(timeoutMs: Long): Boolean = true
            override fun canReadPathWithRoot(path: String, timeoutMs: Long): Boolean = true
            override fun listFilesWithRootReadOnly(
                directories: List<String>,
                maxDepth: Int,
                timeoutMs: Long
            ): List<RootDiscoveredFile> = listOf(
                RootDiscoveredFile(
                    path = "/data/media/0/.Trash/deleted_photo.jpg",
                    sizeBytes = 128_000L,
                    lastModifiedEpochSec = 1729400000L,
                    originLabel = "Root Privileged Trash"
                )
            )
        }

        val assessment = DeviceEnvironmentAssessor.assess(context, verifyRootShell = true, forceStandardMode = false)
        assertEquals(DeviceRootState.ROOT_ENABLED, assessment.rootState)
        assertEquals(OperatingMode.ROOT_ENABLED, assessment.activeOperatingMode)
        assertEquals("ROOT-ENABLED MODE ACTIVE", assessment.cardTitle)
        assertTrue(assessment.rootShellVerifiedUid0)
        assertTrue(assessment.canReadDataMedia)
        assertTrue(assessment.forensicLimitationsNotes.any { it.contains("File-Based Encryption", ignoreCase = true) })

        val rootFiles = DeviceEnvironmentAssessor.scanPrivilegedRootFiles(FileCategory.PHOTO, assessment)
        assertEquals(1, rootFiles.size)
        assertEquals("deleted_photo.jpg", rootFiles.first().name)

        // Verify user can lock Standard Mode even when root is available
        val forcedStandard = DeviceEnvironmentAssessor.assess(context, verifyRootShell = true, forceStandardMode = true)
        assertEquals(OperatingMode.STANDARD, forcedStandard.activeOperatingMode)
        assertFalse(forcedStandard.rootShellVerifiedUid0)
    }

    @Test
    fun `RecoveryModeController evaluates Capabilities A through J and States A B C D`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val controller = RecoveryModeController()
        val stateA = controller.evaluateEnvironment(context)
        assertEquals(10, stateA.capabilities.size)
        assertEquals(OperatingMode.STANDARD_MODE, stateA.activeOperatingMode)

        val stateD = controller.evaluateEnvironment(context, simulateInconclusive = true)
        assertEquals(DeviceAccessState.STATE_D_UNKNOWN_INCONCLUSIVE, stateD.accessState)
        assertEquals(OperatingMode.STANDARD_MODE, stateD.activeOperatingMode)
    }

    @Test
    fun `MainActivity launches in Robolectric without crashing`() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertNotNull(activity)
            }
        }
    }
}
