package com.clone.filesrecovery

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.clone.filesrecovery.data.AppStore
import com.clone.filesrecovery.data.ContactInfo
import com.clone.filesrecovery.data.ContactsHelper
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.FileScanner
import com.clone.filesrecovery.data.FolderBucket
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.RecoveredRecord
import com.clone.filesrecovery.data.SavedNotification
import com.clone.filesrecovery.data.StorageBreakdown
import com.clone.filesrecovery.forensics.ArchiveForensicReport
import com.clone.filesrecovery.forensics.CarvedStreamResult
import com.clone.filesrecovery.forensics.CaseAndCustodyManager
import com.clone.filesrecovery.forensics.CaseEvidenceItem
import com.clone.filesrecovery.forensics.ChainIntegrityVerification
import com.clone.filesrecovery.forensics.ChainOfCustodyEntry
import com.clone.filesrecovery.forensics.CustodyActionType
import com.clone.filesrecovery.forensics.DeepVaultLabsEngine
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessment
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessor
import com.clone.filesrecovery.forensics.DeviceRootState
import com.clone.filesrecovery.forensics.EvidenceComparisonResult
import com.clone.filesrecovery.forensics.ExportFormat
import com.clone.filesrecovery.forensics.ExportedReportBundle
import com.clone.filesrecovery.forensics.FileRelationshipEdge
import com.clone.filesrecovery.forensics.FileRepairReport
import com.clone.filesrecovery.forensics.FileStructureAnalysis
import com.clone.filesrecovery.forensics.ForensicAnalyzer
import com.clone.filesrecovery.forensics.ForensicCaseReport
import com.clone.filesrecovery.forensics.ForensicEvidenceRecord
import com.clone.filesrecovery.forensics.ForensicPrivacyOptions
import com.clone.filesrecovery.forensics.ForensicReportExporter
import com.clone.filesrecovery.forensics.ForensicTimeUtil
import com.clone.filesrecovery.forensics.HexSearchMatch
import com.clone.filesrecovery.forensics.HexViewerPage
import com.clone.filesrecovery.forensics.InvestigationCase
import com.clone.filesrecovery.forensics.MultiStrategyDuplicateCluster
import com.clone.filesrecovery.forensics.ReportVerificationResult
import com.clone.filesrecovery.forensics.ScanCheckpoint
import com.clone.filesrecovery.forensics.ScanHistoryEntry
import com.clone.filesrecovery.forensics.SqliteForensicReport
import com.clone.filesrecovery.forensics.StorageForensicsAnalyzer
import com.clone.filesrecovery.forensics.StorageForensicsExportResult
import com.clone.filesrecovery.forensics.StorageForensicsReport
import com.clone.filesrecovery.forensics.ThumbnailForensicItem
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.Locale
import java.util.UUID

class AppViewModel(app: Application) : AndroidViewModel(app) {

    // ---- Adaptive Dual-Mode Environment Assessment (Standard vs Root-Enabled) ----
    private val _environmentAssessment = MutableStateFlow(DeviceEnvironmentAssessment())
    val environmentAssessment: StateFlow<DeviceEnvironmentAssessment> = _environmentAssessment.asStateFlow()

    private val _isAssessingEnvironment = MutableStateFlow(false)
    val isAssessingEnvironment: StateFlow<Boolean> = _isAssessingEnvironment.asStateFlow()

    private val _forceStandardMode = MutableStateFlow(false)
    val forceStandardMode: StateFlow<Boolean> = _forceStandardMode.asStateFlow()

    private var rootVerifyRequestedByUser = false

    fun refreshEnvironmentAssessment(verifyRootShell: Boolean = rootVerifyRequestedByUser) {
        if (verifyRootShell) {
            rootVerifyRequestedByUser = true
        }
        viewModelScope.launch {
            _isAssessingEnvironment.value = true
            try {
                var assessment = DeviceEnvironmentAssessor.assess(
                    context = getApplication(),
                    verifyRootShell = verifyRootShell,
                    forceStandardMode = _forceStandardMode.value
                )
                // If user explicitly clicked Verify Root Access and root indicators existed,
                // but uid=0 was not granted, represent ROOT_ACCESS_DENIED clearly
                if (verifyRootShell && !_forceStandardMode.value &&
                    assessment.rootState == DeviceRootState.ROOT_DETECTED_NOT_GRANTED
                ) {
                    assessment = assessment.copy(
                        rootState = DeviceRootState.ROOT_ACCESS_DENIED,
                        cardTitle = "ROOT ACCESS DENIED",
                        cardStatusLine = "User or root manager denied the authorization request.",
                        cardDescription = "DeepVault fell back safely to Standard Mode using Android-supported storage access and non-root recovery methods.",
                        deviceRootStatusLabel = "Denied (${assessment.suBinaryPath ?: assessment.rootManagerPackage ?: "su"})"
                    )
                }
                _environmentAssessment.value = assessment
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Keep safe fallback assessment if probing encounters an unexpected OS error
            } finally {
                _isAssessingEnvironment.value = false
            }
        }
    }

    fun requestRootModeVerification() {
        _forceStandardMode.value = false
        rootVerifyRequestedByUser = true
        CaseAndCustodyManager.appendCustodyEvent(
            context = getApplication(),
            actionType = CustodyActionType.PERMISSION_OR_MODE_CHANGE,
            caseId = currentCaseId,
            details = "User initiated explicit read-only root privilege verification (su -c id)"
        )
        refreshCustodyLogState()
        refreshEnvironmentAssessment(verifyRootShell = true)
    }

    fun setForceStandardMode(force: Boolean) {
        _forceStandardMode.value = force
        CaseAndCustodyManager.appendCustodyEvent(
            context = getApplication(),
            actionType = CustodyActionType.PERMISSION_OR_MODE_CHANGE,
            caseId = currentCaseId,
            details = if (force) "User locked Standard Mode (non-root)" else "User unlocked adaptive mode evaluation"
        )
        refreshCustodyLogState()
        refreshEnvironmentAssessment(verifyRootShell = !force && rootVerifyRequestedByUser)
    }

    // ---- Storage Capacity Breakdown (Home Screen) ----
    private val _storageBreakdown = MutableStateFlow(StorageBreakdown())
    val storageBreakdown: StateFlow<StorageBreakdown> = _storageBreakdown.asStateFlow()

    fun refreshStorageBreakdown() {
        viewModelScope.launch {
            runCatching {
                _storageBreakdown.value = FileScanner.getStorageBreakdown(getApplication())
            }
        }
    }

    // ---- Storage Forensics Intelligence Module State ----
    private val _storageForensicsReport = MutableStateFlow<StorageForensicsReport?>(null)
    val storageForensicsReport: StateFlow<StorageForensicsReport?> = _storageForensicsReport.asStateFlow()

    private val _isScanningStorageForensics = MutableStateFlow(false)
    val isScanningStorageForensics: StateFlow<Boolean> = _isScanningStorageForensics.asStateFlow()

    private val _storageForensicsProgressText = MutableStateFlow("")
    val storageForensicsProgressText: StateFlow<String> = _storageForensicsProgressText.asStateFlow()

    private val _lastStorageForensicsExport = MutableStateFlow<StorageForensicsExportResult?>(null)
    val lastStorageForensicsExport: StateFlow<StorageForensicsExportResult?> = _lastStorageForensicsExport.asStateFlow()

    private var storageForensicsJob: Job? = null

    fun runStorageForensicsScan(explicitRoots: List<File>? = null) {
        storageForensicsJob?.cancel()
        _isScanningStorageForensics.value = true
        _storageForensicsProgressText.value = "Initializing deterministic storage forensics scan…"
        storageForensicsJob = viewModelScope.launch {
            try {
                val report = StorageForensicsAnalyzer.analyzeStorage(
                    context = getApplication(),
                    explicitRoots = explicitRoots,
                    environmentAssessment = _environmentAssessment.value
                ) { filesCount, bytesCount, currentPath ->
                    _storageForensicsProgressText.value = if (currentPath.isNotBlank()) {
                        "Scanned $filesCount files (${com.clone.filesrecovery.forensics.formatBytesHuman(bytesCount)}): $currentPath"
                    } else {
                        "Finalizing report ($filesCount files)…"
                    }
                }
                _storageForensicsReport.value = report
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.FILE_VERIFIED,
                    caseId = currentCaseId,
                    details = "Storage Forensics Intelligence scan ${report.reportId}: ${report.filesActuallyScanned} files (${report.bytesActuallyScanned} B), hidden=${report.hiddenFindings.size}, confirmedEnc=${report.totalConfirmedEncryptedFiles}, potentialEnc=${report.totalPotentialEncryptedFiles}, mismatches=${report.totalSignatureMismatches}"
                )
                refreshCustodyLogState()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isScanningStorageForensics.value = false
                _storageForensicsProgressText.value = ""
            }
        }
    }

    fun runStorageForensicsWithSafTree(treeUri: Uri) {
        storageForensicsJob?.cancel()
        _isScanningStorageForensics.value = true
        _storageForensicsProgressText.value = "Acquiring authorized SAF folder tree for inspection…"
        storageForensicsJob = viewModelScope.launch {
            try {
                val app = getApplication<Application>()
                val safStaging = StorageForensicsAnalyzer.copySafTreeForInspection(app, treeUri)
                val roots = buildList {
                    add(safStaging)
                    android.os.Environment.getExternalStorageDirectory()?.takeIf { it.exists() && it.canRead() }?.let { add(it) }
                }
                val report = StorageForensicsAnalyzer.analyzeStorage(
                    context = app,
                    explicitRoots = roots,
                    environmentAssessment = _environmentAssessment.value
                ) { filesCount, bytesCount, currentPath ->
                    _storageForensicsProgressText.value = "Scanned $filesCount files (${com.clone.filesrecovery.forensics.formatBytesHuman(bytesCount)}): $currentPath"
                }
                _storageForensicsReport.value = report
                CaseAndCustodyManager.appendCustodyEvent(
                    context = app,
                    actionType = CustodyActionType.FILE_VERIFIED,
                    caseId = currentCaseId,
                    details = "Storage Forensics Intelligence scan with SAF tree (${treeUri}): ${report.filesActuallyScanned} files inspected"
                )
                refreshCustodyLogState()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isScanningStorageForensics.value = false
                _storageForensicsProgressText.value = ""
            }
        }
    }

    fun exportStorageForensicsReport(onDone: ((StorageForensicsExportResult) -> Unit)? = null) {
        val current = _storageForensicsReport.value ?: return
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val baseDir = ForensicReportExporter.getReportsBaseDir(getApplication())
                val exported = StorageForensicsAnalyzer.exportReportFiles(current, baseDir)
                _lastStorageForensicsExport.value = exported
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.REPORT_EXPORTED,
                    caseId = currentCaseId,
                    details = "Exported Storage Forensics Intelligence report ${current.reportId} (JSON SHA-256=${exported.jsonSha256.take(16)}…)"
                )
                refreshCustodyLogState()
                withContext(Dispatchers.Main) {
                    onDone?.invoke(exported)
                }
            }
        }
    }

    // ---- Scan flow & Checkpointing (Section 9) ----
    private val _scanResults = MutableStateFlow<List<RecoverableFile>>(emptyList())
    val scanResults: StateFlow<List<RecoverableFile>> = _scanResults.asStateFlow()

    private val _folderBuckets = MutableStateFlow<List<FolderBucket>>(emptyList())
    val folderBuckets: StateFlow<List<FolderBucket>> = _folderBuckets.asStateFlow()

    private val _isPreparing = MutableStateFlow(false)
    val isPreparing: StateFlow<Boolean> = _isPreparing.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanProgressText = MutableStateFlow("")
    val scanProgressText: StateFlow<String> = _scanProgressText.asStateFlow()

    private val _scannedCount = MutableStateFlow(0)
    val scannedCount: StateFlow<Int> = _scannedCount.asStateFlow()

    private val _foundLiveCount = MutableStateFlow(0)
    val foundLiveCount: StateFlow<Int> = _foundLiveCount.asStateFlow()

    private val _lastScanCheckpoint = MutableStateFlow<ScanCheckpoint?>(null)
    val lastScanCheckpoint: StateFlow<ScanCheckpoint?> = _lastScanCheckpoint.asStateFlow()

    private val _scanHistory = MutableStateFlow<List<ScanHistoryEntry>>(emptyList())
    val scanHistory: StateFlow<List<ScanHistoryEntry>> = _scanHistory.asStateFlow()

    var currentCategory: FileCategory = FileCategory.PHOTO
    var currentBucket: FolderBucket? = null
    var currentFile: RecoverableFile? = null
    var currentScanSessionId: String = "SESSION-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}"
        private set
    var currentCaseId: String = "CASE-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}"
        private set

    private var scanJob: Job? = null
    private var forensicJob: Job? = null

    private val _selected = MutableStateFlow<Set<String>>(emptySet())
    val selected: StateFlow<Set<String>> = _selected.asStateFlow()

    private val _isRecovering = MutableStateFlow(false)
    val isRecovering: StateFlow<Boolean> = _isRecovering.asStateFlow()

    private val _lastRecoveredCount = MutableStateFlow<Int?>(null)
    val lastRecoveredCount: StateFlow<Int?> = _lastRecoveredCount.asStateFlow()

    // ---- Forensic Analysis & AI-Ready Report Engine State ----
    private val _activeForensicRecord = MutableStateFlow<ForensicEvidenceRecord?>(null)
    val activeForensicRecord: StateFlow<ForensicEvidenceRecord?> = _activeForensicRecord.asStateFlow()

    private val _isAnalyzingForensics = MutableStateFlow(false)
    val isAnalyzingForensics: StateFlow<Boolean> = _isAnalyzingForensics.asStateFlow()

    private val _forensicProgressText = MutableStateFlow("")
    val forensicProgressText: StateFlow<String> = _forensicProgressText.asStateFlow()

    private val _forensicAnalyzedCount = MutableStateFlow(0)
    val forensicAnalyzedCount: StateFlow<Int> = _forensicAnalyzedCount.asStateFlow()

    private val _forensicTotalCount = MutableStateFlow(0)
    val forensicTotalCount: StateFlow<Int> = _forensicTotalCount.asStateFlow()

    private val _caseEvidenceRecords = MutableStateFlow<List<ForensicEvidenceRecord>>(emptyList())
    val caseEvidenceRecords: StateFlow<List<ForensicEvidenceRecord>> = _caseEvidenceRecords.asStateFlow()

    private val _privacyOptions = MutableStateFlow(ForensicPrivacyOptions())
    val privacyOptions: StateFlow<ForensicPrivacyOptions> = _privacyOptions.asStateFlow()

    private val _currentCaseReports = MutableStateFlow<List<ForensicCaseReport>>(emptyList())
    val currentCaseReports: StateFlow<List<ForensicCaseReport>> = _currentCaseReports.asStateFlow()

    private val _isExportingReport = MutableStateFlow(false)
    val isExportingReport: StateFlow<Boolean> = _isExportingReport.asStateFlow()

    private val _lastExportedBundle = MutableStateFlow<ExportedReportBundle?>(null)
    val lastExportedBundle: StateFlow<ExportedReportBundle?> = _lastExportedBundle.asStateFlow()

    private val _exportHistory = MutableStateFlow<List<ExportedReportBundle>>(emptyList())
    val exportHistory: StateFlow<List<ExportedReportBundle>> = _exportHistory.asStateFlow()

    private val _lastVerificationResult = MutableStateFlow<ReportVerificationResult?>(null)
    val lastVerificationResult: StateFlow<ReportVerificationResult?> = _lastVerificationResult.asStateFlow()

    private var reportVersionCounter = 1

    // ---- Advanced Forensics Lab, File Repair Lab & Case Manager State ----
    private val _selectedLabFile = MutableStateFlow<File?>(null)
    val selectedLabFile: StateFlow<File?> = _selectedLabFile.asStateFlow()

    private val _hexViewerPage = MutableStateFlow<HexViewerPage?>(null)
    val hexViewerPage: StateFlow<HexViewerPage?> = _hexViewerPage.asStateFlow()

    private val _hexSearchMatches = MutableStateFlow<List<HexSearchMatch>>(emptyList())
    val hexSearchMatches: StateFlow<List<HexSearchMatch>> = _hexSearchMatches.asStateFlow()

    private val _activeStructureAnalysis = MutableStateFlow<FileStructureAnalysis?>(null)
    val activeStructureAnalysis: StateFlow<FileStructureAnalysis?> = _activeStructureAnalysis.asStateFlow()

    private val _activeArchiveReport = MutableStateFlow<ArchiveForensicReport?>(null)
    val activeArchiveReport: StateFlow<ArchiveForensicReport?> = _activeArchiveReport.asStateFlow()

    private val _activeSqliteReport = MutableStateFlow<SqliteForensicReport?>(null)
    val activeSqliteReport: StateFlow<SqliteForensicReport?> = _activeSqliteReport.asStateFlow()

    private val _multiStrategyDuplicates = MutableStateFlow<List<MultiStrategyDuplicateCluster>>(emptyList())
    val multiStrategyDuplicates: StateFlow<List<MultiStrategyDuplicateCluster>> = _multiStrategyDuplicates.asStateFlow()

    private val _fileRelationships = MutableStateFlow<List<FileRelationshipEdge>>(emptyList())
    val fileRelationships: StateFlow<List<FileRelationshipEdge>> = _fileRelationships.asStateFlow()

    private val _thumbnailForensicItems = MutableStateFlow<List<ThumbnailForensicItem>>(emptyList())
    val thumbnailForensicItems: StateFlow<List<ThumbnailForensicItem>> = _thumbnailForensicItems.asStateFlow()

    private val _carvedStreams = MutableStateFlow<List<CarvedStreamResult>>(emptyList())
    val carvedStreams: StateFlow<List<CarvedStreamResult>> = _carvedStreams.asStateFlow()

    private val _lastRepairReport = MutableStateFlow<FileRepairReport?>(null)
    val lastRepairReport: StateFlow<FileRepairReport?> = _lastRepairReport.asStateFlow()

    private val _repairHistory = MutableStateFlow<List<FileRepairReport>>(emptyList())
    val repairHistory: StateFlow<List<FileRepairReport>> = _repairHistory.asStateFlow()

    private val _investigationCases = MutableStateFlow<List<InvestigationCase>>(emptyList())
    val investigationCases: StateFlow<List<InvestigationCase>> = _investigationCases.asStateFlow()

    private val _activeInvestigationCase = MutableStateFlow<InvestigationCase?>(null)
    val activeInvestigationCase: StateFlow<InvestigationCase?> = _activeInvestigationCase.asStateFlow()

    private val _custodyLog = MutableStateFlow<List<ChainOfCustodyEntry>>(emptyList())
    val custodyLog: StateFlow<List<ChainOfCustodyEntry>> = _custodyLog.asStateFlow()

    private val _custodyVerification = MutableStateFlow<ChainIntegrityVerification?>(null)
    val custodyVerification: StateFlow<ChainIntegrityVerification?> = _custodyVerification.asStateFlow()

    private val _evidenceComparison = MutableStateFlow<EvidenceComparisonResult?>(null)
    val evidenceComparison: StateFlow<EvidenceComparisonResult?> = _evidenceComparison.asStateFlow()

    init {
        refreshEnvironmentAssessment(verifyRootShell = false)
        refreshStorageBreakdown()
        loadRecovered()
        initializeCasesAndCustody()
    }

    private fun initializeCasesAndCustody() {
        runCatching {
            val defaultCase = CaseAndCustodyManager.ensureDefaultCase(
                context = getApplication(),
                defaultCaseId = currentCaseId,
                operatingMode = _environmentAssessment.value.recoveryModeLabel
            )
            currentCaseId = defaultCase.caseId
            _investigationCases.value = CaseAndCustodyManager.loadCases(getApplication())
            _activeInvestigationCase.value = defaultCase
            _custodyLog.value = CaseAndCustodyManager.loadCustodyLog(getApplication())
            _custodyVerification.value = CaseAndCustodyManager.verifyCustodyChainIntegrity(getApplication())
            _lastScanCheckpoint.value = CaseAndCustodyManager.loadLastScanCheckpoint(getApplication())
            _scanHistory.value = CaseAndCustodyManager.loadScanHistory(getApplication())
        }
    }

    fun refreshCustodyLogState() {
        runCatching {
            _investigationCases.value = CaseAndCustodyManager.loadCases(getApplication())
            _activeInvestigationCase.value = _investigationCases.value.firstOrNull { it.caseId == currentCaseId }
                ?: _investigationCases.value.firstOrNull()
            _custodyLog.value = CaseAndCustodyManager.loadCustodyLog(getApplication())
            _custodyVerification.value = CaseAndCustodyManager.verifyCustodyChainIntegrity(getApplication())
        }
    }

    fun startScan(category: FileCategory) {
        scanJob?.cancel()
        currentCategory = category
        currentBucket = null
        currentScanSessionId = "SESSION-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}"
        _selected.value = emptySet()
        _scanResults.value = emptyList()
        _folderBuckets.value = emptyList()
        _isPreparing.value = true
        _isScanning.value = true
        _scannedCount.value = 0
        _foundLiveCount.value = 0
        _scanProgressText.value = ""

        val startedIso = ForensicTimeUtil.nowIsoUtc()
        val startMs = System.currentTimeMillis()
        val modeLabel = _environmentAssessment.value.recoveryModeLabel

        scanJob = viewModelScope.launch {
            var lastPath = ""
            try {
                delay(650)
                _isPreparing.value = false
                val found = FileScanner.scan(
                    context = getApplication(),
                    category = category,
                    environmentAssessment = _environmentAssessment.value
                ) { count, foundSoFar, path ->
                    _scannedCount.value = count
                    _foundLiveCount.value = foundSoFar
                    if (path.isNotBlank()) {
                        lastPath = path
                        _scanProgressText.value = path
                    }
                    if (count % 50 == 0) {
                        runCatching {
                            val cp = ScanCheckpoint(
                                checkpointId = currentScanSessionId,
                                categoryName = category.name,
                                operatingMode = modeLabel,
                                startedAtIso = startedIso,
                                updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
                                status = "IN_PROGRESS",
                                scannedDirectoriesCount = count,
                                discoveredFilesCount = foundSoFar,
                                bytesEvaluated = 0L,
                                lastProcessedPath = lastPath,
                                completedRootPaths = emptyList(),
                                DiscoveredPathsSnapshot = emptyList()
                            )
                            CaseAndCustodyManager.saveScanCheckpoint(getApplication(), cp)
                            _lastScanCheckpoint.value = cp
                        }
                    }
                }
                _scanResults.value = found
                _foundLiveCount.value = found.size
                val buckets = FileScanner.buildFolderBuckets(category, found)
                _folderBuckets.value = buckets
                currentBucket = buckets.firstOrNull { it.isAllBucket } ?: buckets.firstOrNull()

                val totalBytes = found.sumOf { it.size }
                val completedCp = ScanCheckpoint(
                    checkpointId = currentScanSessionId,
                    categoryName = category.name,
                    operatingMode = modeLabel,
                    startedAtIso = startedIso,
                    updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
                    status = "COMPLETED",
                    scannedDirectoriesCount = _scannedCount.value,
                    discoveredFilesCount = found.size,
                    bytesEvaluated = totalBytes,
                    lastProcessedPath = lastPath,
                    completedRootPaths = emptyList(),
                    DiscoveredPathsSnapshot = found.take(200).map { it.path }
                )
                CaseAndCustodyManager.saveScanCheckpoint(getApplication(), completedCp)
                _lastScanCheckpoint.value = completedCp

                CaseAndCustodyManager.appendScanHistory(
                    context = getApplication(),
                    entry = ScanHistoryEntry(
                        sessionId = currentScanSessionId,
                        categoryName = category.title,
                        operatingMode = modeLabel,
                        startedAtIso = startedIso,
                        finishedAtIso = ForensicTimeUtil.nowIsoUtc(),
                        status = "COMPLETED",
                        filesDiscovered = found.size,
                        bytesEvaluated = totalBytes,
                        durationMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1L),
                        notes = "5-stage scan completed in $modeLabel mode."
                    )
                )
                _scanHistory.value = CaseAndCustodyManager.loadScanHistory(getApplication())
            } catch (ce: CancellationException) {
                runCatching {
                    val interruptedCp = ScanCheckpoint(
                        checkpointId = currentScanSessionId,
                        categoryName = category.name,
                        operatingMode = modeLabel,
                        startedAtIso = startedIso,
                        updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
                        status = "INTERRUPTED_RESUMABLE",
                        scannedDirectoriesCount = _scannedCount.value,
                        discoveredFilesCount = _foundLiveCount.value,
                        bytesEvaluated = 0L,
                        lastProcessedPath = lastPath,
                        completedRootPaths = emptyList(),
                        DiscoveredPathsSnapshot = _scanResults.value.take(200).map { it.path }
                    )
                    CaseAndCustodyManager.saveScanCheckpoint(getApplication(), interruptedCp)
                    _lastScanCheckpoint.value = interruptedCp
                }
                throw ce
            } catch (t: Throwable) {
                runCatching {
                    val failedCp = ScanCheckpoint(
                        checkpointId = currentScanSessionId,
                        categoryName = category.name,
                        operatingMode = modeLabel,
                        startedAtIso = startedIso,
                        updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
                        status = "FAILED",
                        scannedDirectoriesCount = _scannedCount.value,
                        discoveredFilesCount = _foundLiveCount.value,
                        bytesEvaluated = 0L,
                        lastProcessedPath = lastPath,
                        completedRootPaths = emptyList(),
                        DiscoveredPathsSnapshot = emptyList(),
                        errorSummary = t.message
                    )
                    CaseAndCustodyManager.saveScanCheckpoint(getApplication(), failedCp)
                    _lastScanCheckpoint.value = failedCp
                }
            } finally {
                _isPreparing.value = false
                _isScanning.value = false
            }
        }
    }

    fun selectBucket(bucket: FolderBucket) {
        currentBucket = bucket
        _selected.value = emptySet()
    }

    fun toggleSelect(file: RecoverableFile) {
        _selected.value = if (_selected.value.contains(file.path))
            _selected.value - file.path else _selected.value + file.path
    }

    fun toggleGroupSelection(files: List<RecoverableFile>) {
        val paths = files.map { it.path }.toSet()
        val allSelected = paths.all { _selected.value.contains(it) }
        _selected.value = if (allSelected) {
            _selected.value - paths
        } else {
            _selected.value + paths
        }
    }

    fun selectAll(files: List<RecoverableFile> = currentBucket?.files ?: _scanResults.value) {
        _selected.value = files.map { it.path }.toSet()
    }

    fun clearSelection() {
        _selected.value = emptySet()
    }

    fun recoverSelected() {
        val pool = currentBucket?.files ?: _scanResults.value
        val files = pool.filter { _selected.value.contains(it.path) }
            .ifEmpty { _scanResults.value.filter { _selected.value.contains(it.path) } }
        if (files.isEmpty()) return
        _isRecovering.value = true
        viewModelScope.launch {
            try {
                val done = FileScanner.recover(getApplication(), files)
                _lastRecoveredCount.value = done.size
                _selected.value = emptySet()
                loadRecovered()
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.RECOVERY_ATTEMPT,
                    caseId = currentCaseId,
                    details = "Batch recovery completed: ${done.size} of ${files.size} selected artifacts copied to recovery vault"
                )
                refreshCustodyLogState()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                _lastRecoveredCount.value = 0
            } finally {
                _isRecovering.value = false
            }
        }
    }

    fun recoverSingle(file: RecoverableFile) {
        _isRecovering.value = true
        viewModelScope.launch {
            try {
                val done = FileScanner.recover(getApplication(), listOf(file))
                _lastRecoveredCount.value = done.size
                loadRecovered()
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.RECOVERY_ATTEMPT,
                    caseId = currentCaseId,
                    details = "Single artifact recovery (${file.name}): ${done.size} copied to recovery vault"
                )
                refreshCustodyLogState()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                _lastRecoveredCount.value = 0
            } finally {
                _isRecovering.value = false
            }
        }
    }

    fun consumeRecoveredEvent() {
        _lastRecoveredCount.value = null
    }

    // ---- Forensic Inspection & Case Report Operations ----

    fun analyzeSingleRecoverableFile(file: RecoverableFile, referenceHash: String? = null) {
        forensicJob?.cancel()
        _isAnalyzingForensics.value = true
        _forensicProgressText.value = "Inspecting binary header, hashes & metadata for ${file.name}…"
        forensicJob = viewModelScope.launch {
            try {
                val target = File(file.path)
                inspectFileInAdvancedLabsInternal(target)
                val method = mapOriginToMethod(file.recoveryOrigin)
                val status = if (file.isHiddenOrTrashed || file.recoveryOrigin.contains("Carved", true)) {
                    "carved_candidate"
                } else {
                    "accessible_active"
                }
                val record = ForensicAnalyzer.analyzeFile(
                    context = getApplication(),
                    targetFile = target,
                    originalFilename = file.name,
                    sourceLocation = target.parent,
                    recoveredOutputPath = null,
                    recoveryStatus = status,
                    recoveryMethod = method,
                    recoveryTimestampMs = null,
                    scanSessionId = currentScanSessionId,
                    referenceHash = referenceHash
                )
                _activeForensicRecord.value = ForensicAnalyzer.applyRedactionToRecord(record, _privacyOptions.value)
                val existing = _caseEvidenceRecords.value.filterNot { it.evidenceId == record.evidenceId }
                _caseEvidenceRecords.value = listOf(record) + existing
                CaseAndCustodyManager.addOrUpdateEvidenceInCase(getApplication(), currentCaseId, record)
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.HASH_CALCULATED,
                    caseId = currentCaseId,
                    evidenceId = record.evidenceId,
                    details = "Computed streaming SHA-256 (${record.sha256.take(16)}…) & metadata for '${record.currentFilename}'"
                )
                refreshCustodyLogState()
                rebuildCaseReportsFromCache()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isAnalyzingForensics.value = false
                _forensicProgressText.value = ""
            }
        }
    }

    fun analyzeRecoveredRecord(record: RecoveredRecord, referenceHash: String? = null) {
        forensicJob?.cancel()
        _isAnalyzingForensics.value = true
        _forensicProgressText.value = "Analyzing recovered evidence ${record.name}…"
        forensicJob = viewModelScope.launch {
            try {
                val recoveredFile = File(record.recoveredPath).takeIf { it.exists() } ?: File(record.originalPath)
                inspectFileInAdvancedLabsInternal(recoveredFile)
                val evRecord = ForensicAnalyzer.analyzeFile(
                    context = getApplication(),
                    targetFile = recoveredFile,
                    originalFilename = File(record.originalPath).name,
                    sourceLocation = File(record.originalPath).parent,
                    recoveredOutputPath = record.recoveredPath,
                    recoveryStatus = "recovered",
                    recoveryMethod = "deepvault_recovery_restore",
                    recoveryTimestampMs = record.recoveredAt,
                    scanSessionId = currentScanSessionId,
                    referenceHash = referenceHash
                )
                _activeForensicRecord.value = ForensicAnalyzer.applyRedactionToRecord(evRecord, _privacyOptions.value)
                val existing = _caseEvidenceRecords.value.filterNot { it.evidenceId == evRecord.evidenceId }
                _caseEvidenceRecords.value = listOf(evRecord) + existing
                CaseAndCustodyManager.addOrUpdateEvidenceInCase(getApplication(), currentCaseId, evRecord)
                refreshCustodyLogState()
                rebuildCaseReportsFromCache()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isAnalyzingForensics.value = false
                _forensicProgressText.value = ""
            }
        }
    }

    /**
     * Imports a user-selected file via Android Storage Access Framework (SAF) into a read-only
     * forensic workspace file and runs complete forensic, hex, structure, archive/SQLite analysis.
     */
    fun importSafUriForForensics(uri: Uri) {
        forensicJob?.cancel()
        _isAnalyzingForensics.value = true
        _forensicProgressText.value = "Acquiring read-only stream from Storage Access Framework URI…"
        forensicJob = viewModelScope.launch {
            try {
                val app = getApplication<Application>()
                val safFile = withContext(Dispatchers.IO) {
                    val resolver = app.contentResolver
                    var displayName = "saf_evidence_${System.currentTimeMillis()}"
                    runCatching {
                        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                            if (c.moveToFirst()) {
                                val name = c.getString(0)
                                if (!name.isNullOrBlank()) displayName = name.replace(Regex("""[^\w.\-]"""), "_")
                            }
                        }
                    }
                    val dir = File(app.cacheDir, "saf_forensic_imports").apply { mkdirs() }
                    val out = File(dir, displayName)
                    resolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(out).use { output ->
                            input.copyTo(output, 64 * 1024)
                        }
                    }
                    out
                }
                if (safFile.exists() && safFile.length() >= 0L) {
                    inspectFileInAdvancedLabsInternal(safFile)
                    val evRecord = ForensicAnalyzer.analyzeFile(
                        context = app,
                        targetFile = safFile,
                        originalFilename = safFile.name,
                        sourceLocation = uri.toString(),
                        recoveredOutputPath = null,
                        recoveryStatus = "accessible_active",
                        recoveryMethod = "saf_user_selected_document",
                        scanSessionId = currentScanSessionId
                    )
                    _activeForensicRecord.value = ForensicAnalyzer.applyRedactionToRecord(evRecord, _privacyOptions.value)
                    val existing = _caseEvidenceRecords.value.filterNot { it.evidenceId == evRecord.evidenceId }
                    _caseEvidenceRecords.value = listOf(evRecord) + existing
                    CaseAndCustodyManager.addOrUpdateEvidenceInCase(app, currentCaseId, evRecord)
                    refreshCustodyLogState()
                    rebuildCaseReportsFromCache()
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isAnalyzingForensics.value = false
                _forensicProgressText.value = ""
            }
        }
    }

    /**
     * Selects a specific file for the Advanced Forensics Lab (Hex Viewer, Structure Analyzer,
     * Archive Forensics, SQLite Forensics, Signature Carving, and File Repair Lab).
     */
    fun selectFileForAdvancedLab(file: File) {
        viewModelScope.launch {
            inspectFileInAdvancedLabsInternal(file)
        }
    }

    private suspend fun inspectFileInAdvancedLabsInternal(file: File) = withContext(Dispatchers.IO) {
        if (!file.exists() || !file.isFile) return@withContext
        _selectedLabFile.value = file
        _hexViewerPage.value = DeepVaultLabsEngine.readHexPage(file, pageOffset = 0L)
        _hexSearchMatches.value = emptyList()
        val struct = DeepVaultLabsEngine.analyzeFileStructure(file)
        _activeStructureAnalysis.value = struct

        val ext = file.extension.lowercase(Locale.US)
        if (struct.detectedFormat.contains("ZIP") || ext in setOf("zip", "apk", "jar", "docx", "xlsx", "pptx", "epub")) {
            _activeArchiveReport.value = DeepVaultLabsEngine.inspectArchiveForensics(file)
        } else {
            _activeArchiveReport.value = null
        }

        if (struct.detectedFormat.contains("SQLITE") || ext in setOf("db", "sqlite", "sqlite3")) {
            _activeSqliteReport.value = DeepVaultLabsEngine.inspectSqliteDatabase(file)
        } else {
            _activeSqliteReport.value = null
        }
    }

    fun loadHexViewerPage(offset: Long) {
        val f = _selectedLabFile.value ?: _activeForensicRecord.value?.sourceLocation?.let { parent ->
            File(parent, _activeForensicRecord.value!!.currentFilename)
        } ?: return
        viewModelScope.launch(Dispatchers.IO) {
            _hexViewerPage.value = DeepVaultLabsEngine.readHexPage(f, pageOffset = offset)
        }
    }

    fun searchInHexViewer(query: String, isHex: Boolean) {
        val f = _selectedLabFile.value ?: return
        viewModelScope.launch {
            _hexSearchMatches.value = DeepVaultLabsEngine.searchBytePatternStreaming(f, query, isHex)
        }
    }

    fun runSignatureStreamCarvingOnSelectedFile() {
        val f = _selectedLabFile.value ?: return
        viewModelScope.launch {
            val outDir = File(getApplication<Application>().filesDir, "carved_streams_${System.currentTimeMillis()}").apply { mkdirs() }
            val results = DeepVaultLabsEngine.carveStreamsFromAccessibleSource(f, outDir)
            _carvedStreams.value = results
            CaseAndCustodyManager.appendCustodyEvent(
                context = getApplication(),
                actionType = CustodyActionType.RECOVERY_ATTEMPT,
                caseId = currentCaseId,
                details = "Executed signature-based stream carving on '${f.name}': ${results.size} embedded stream(s) extracted"
            )
            refreshCustodyLogState()
        }
    }

    fun runNonDestructiveFileRepair(targetFile: File? = _selectedLabFile.value) {
        val f = targetFile ?: return
        viewModelScope.launch {
            val repairDir = File(ForensicReportExporter.getReportsBaseDir(getApplication()), "Repaired_Artifacts").apply { mkdirs() }
            val report = DeepVaultLabsEngine.repairFileNonDestructive(f, repairDir)
            _lastRepairReport.value = report
            _repairHistory.value = listOf(report) + _repairHistory.value.filterNot { it.originalPath == report.originalPath }
            CaseAndCustodyManager.appendCustodyEvent(
                context = getApplication(),
                actionType = CustodyActionType.FILE_REPAIR_ATTEMPT,
                caseId = currentCaseId,
                details = "File Repair Lab on '${f.name}': method=${report.repairMethodApplied}, outcome=${report.repairOutcome.name}, origSHA=${report.originalSha256.take(12)}…, repairedSHA=${report.repairedSha256?.take(12) ?: "n/a"}"
            )
            refreshCustodyLogState()
        }
    }

    /**
     * Creates a synthetic demo SQLite database or truncated JPEG in the app's local forensic sandbox
     * ONLY when the user explicitly clicks "Load Diagnostic Test Fixture" in the SQLite or Repair Lab
     * to test unallocated record inspection or container repair on a clean emulator.
     */
    fun loadSqliteLabSelfTestFixture() {
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            val dbFile = File(app.cacheDir, "forensic_evidence_sample.sqlite")
            if (dbFile.exists()) dbFile.delete()
            val db = android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(dbFile, null)
            db.use { sqlite ->
                sqlite.execSQL("PRAGMA auto_vacuum = NONE;")
                sqlite.execSQL("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body TEXT, timestamp_utc TEXT);")
                sqlite.execSQL("CREATE INDEX idx_messages_sender ON messages(sender);")
                sqlite.execSQL("INSERT INTO messages VALUES (1, 'vault_admin', 'Initial forensic integrity checkpoint verified', '2026-10-20T09:00:00Z');")
                sqlite.execSQL("INSERT INTO messages VALUES (2, 'field_unit_04', 'DELETED_ARTIFACT_EVIDENCE_PAYLOAD_7749', '2026-10-20T09:15:00Z');")
                sqlite.execSQL("INSERT INTO messages VALUES (3, 'audit_logger', 'SHA256 manifest signed offline', '2026-10-20T09:30:00Z');")
                sqlite.execSQL("DELETE FROM messages WHERE id = 2;")
            }
            inspectFileInAdvancedLabsInternal(dbFile)
        }
    }

    // ---- Investigation Case Management & Evidence Annotations (Section 7 & 8) ----

    fun createNewInvestigationCase(title: String, investigator: String, description: String) {
        val newCaseId = "CASE-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}"
        val created = CaseAndCustodyManager.createCase(
            context = getApplication(),
            caseId = newCaseId,
            title = title,
            investigatorName = investigator,
            description = description,
            operatingMode = _environmentAssessment.value.recoveryModeLabel
        )
        currentCaseId = created.caseId
        _activeInvestigationCase.value = created
        refreshCustodyLogState()
    }

    fun switchActiveCase(caseId: String) {
        val found = _investigationCases.value.firstOrNull { it.caseId == caseId } ?: return
        currentCaseId = found.caseId
        _activeInvestigationCase.value = found
        refreshCustodyLogState()
    }

    fun toggleBookmarkEvidence(evidenceId: String) {
        val active = _activeInvestigationCase.value ?: return
        val item = active.evidenceItems.firstOrNull { it.evidenceId == evidenceId } ?: return
        CaseAndCustodyManager.updateEvidenceAnnotation(
            context = getApplication(),
            caseId = active.caseId,
            evidenceId = evidenceId,
            bookmarked = !item.bookmarked
        )
        refreshCustodyLogState()
    }

    fun saveEvidenceNotesAndTags(evidenceId: String, notes: String, commaSeparatedTags: String) {
        val active = _activeInvestigationCase.value ?: return
        val tags = commaSeparatedTags.split(',').map { it.trim() }.filter { it.isNotBlank() }.distinct()
        CaseAndCustodyManager.updateEvidenceAnnotation(
            context = getApplication(),
            caseId = active.caseId,
            evidenceId = evidenceId,
            tags = tags,
            analystNotes = notes.trim()
        )
        refreshCustodyLogState()
    }

    fun removeEvidenceFromActiveCase(evidenceId: String) {
        val active = _activeInvestigationCase.value ?: return
        CaseAndCustodyManager.removeEvidenceFromCase(getApplication(), active.caseId, evidenceId)
        refreshCustodyLogState()
    }

    fun compareTwoCaseEvidenceItems(leftId: String, rightId: String) {
        val active = _activeInvestigationCase.value ?: return
        val left = active.evidenceItems.firstOrNull { it.evidenceId == leftId } ?: return
        val right = active.evidenceItems.firstOrNull { it.evidenceId == rightId } ?: return
        _evidenceComparison.value = CaseAndCustodyManager.compareEvidenceItems(left, right)
    }

    fun verifyChainOfCustodyNow() {
        _custodyVerification.value = CaseAndCustodyManager.verifyCustodyChainIntegrity(getApplication())
    }

    fun exportCaseBackupArchive(onDone: (File) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val dir = ForensicReportExporter.getReportsBaseDir(getApplication())
            val f = CaseAndCustodyManager.exportCasesBackupFile(getApplication(), dir)
            withContext(Dispatchers.Main) {
                onDone(f)
            }
        }
    }

    /**
     * Runs deterministic forensic analysis across a batch of files (selected scan items,
     * recovered vault records, or current scan results) to build a Combined Case Report.
     */
    fun runCaseForensicAnalysis(explicitFiles: List<RecoverableFile>? = null) {
        forensicJob?.cancel()
        _isAnalyzingForensics.value = true
        _lastVerificationResult.value = null

        forensicJob = viewModelScope.launch {
            try {
                val targetRecoverables: List<RecoverableFile> = when {
                    !explicitFiles.isNullOrEmpty() -> explicitFiles
                    _selected.value.isNotEmpty() -> {
                        val pool = currentBucket?.files ?: _scanResults.value
                        pool.filter { _selected.value.contains(it.path) }
                    }
                    _scanResults.value.isNotEmpty() -> _scanResults.value.take(40)
                    else -> emptyList()
                }

                val recoveredRecords = _recovered.value
                val totalToAnalyze = if (targetRecoverables.isNotEmpty()) {
                    targetRecoverables.size
                } else {
                    recoveredRecords.size
                }

                _forensicTotalCount.value = totalToAnalyze
                _forensicAnalyzedCount.value = 0
                val analyzedList = ArrayList<ForensicEvidenceRecord>()
                val candidateFilesForDup = ArrayList<File>()

                if (targetRecoverables.isNotEmpty()) {
                    for ((idx, item) in targetRecoverables.withIndex()) {
                        ensureActive()
                        _forensicAnalyzedCount.value = idx + 1
                        _forensicProgressText.value = "Analyzing (${idx + 1}/${targetRecoverables.size}): ${item.name}"
                        val f = File(item.path)
                        if (f.exists()) candidateFilesForDup.add(f)
                        val method = mapOriginToMethod(item.recoveryOrigin)
                        val status = if (item.isHiddenOrTrashed || item.recoveryOrigin.contains("Carved", true)) {
                            "carved_candidate"
                        } else {
                            "accessible_active"
                        }
                        val rec = ForensicAnalyzer.analyzeFile(
                            context = getApplication(),
                            targetFile = f,
                            originalFilename = item.name,
                            sourceLocation = f.parent,
                            recoveredOutputPath = null,
                            recoveryStatus = status,
                            recoveryMethod = method,
                            recoveryTimestampMs = null,
                            scanSessionId = currentScanSessionId
                        )
                        analyzedList.add(rec)
                        CaseAndCustodyManager.addOrUpdateEvidenceInCase(getApplication(), currentCaseId, rec)
                    }
                } else if (recoveredRecords.isNotEmpty()) {
                    for ((idx, recItem) in recoveredRecords.withIndex()) {
                        ensureActive()
                        _forensicAnalyzedCount.value = idx + 1
                        _forensicProgressText.value = "Analyzing recovered (${idx + 1}/${recoveredRecords.size}): ${recItem.name}"
                        val targetFile = File(recItem.recoveredPath).takeIf { it.exists() } ?: File(recItem.originalPath)
                        if (targetFile.exists()) candidateFilesForDup.add(targetFile)
                        val rec = ForensicAnalyzer.analyzeFile(
                            context = getApplication(),
                            targetFile = targetFile,
                            originalFilename = File(recItem.originalPath).name,
                            sourceLocation = File(recItem.originalPath).parent,
                            recoveredOutputPath = recItem.recoveredPath,
                            recoveryStatus = "recovered",
                            recoveryMethod = "deepvault_recovery_restore",
                            recoveryTimestampMs = recItem.recoveredAt,
                            scanSessionId = currentScanSessionId
                        )
                        analyzedList.add(rec)
                        CaseAndCustodyManager.addOrUpdateEvidenceInCase(getApplication(), currentCaseId, rec)
                    }
                } else {
                    _forensicProgressText.value = "Scanning accessible storage for forensic evidence sample…"
                    val photos = FileScanner.scan(
                        getApplication(),
                        FileCategory.PHOTO,
                        _environmentAssessment.value
                    ) { _, _, _ -> }.take(10)
                    val docs = FileScanner.scan(
                        getApplication(),
                        FileCategory.DOCUMENT,
                        _environmentAssessment.value
                    ) { _, _, _ -> }.take(10)
                    val combined = (photos + docs).distinctBy { it.path }.take(15)
                    _forensicTotalCount.value = combined.size
                    for ((idx, item) in combined.withIndex()) {
                        ensureActive()
                        _forensicAnalyzedCount.value = idx + 1
                        _forensicProgressText.value = "Analyzing (${idx + 1}/${combined.size}): ${item.name}"
                        val f = File(item.path)
                        if (f.exists()) candidateFilesForDup.add(f)
                        val rec = ForensicAnalyzer.analyzeFile(
                            context = getApplication(),
                            targetFile = f,
                            originalFilename = item.name,
                            sourceLocation = f.parent,
                            recoveredOutputPath = null,
                            recoveryStatus = if (item.isHiddenOrTrashed) "carved_candidate" else "accessible_active",
                            recoveryMethod = mapOriginToMethod(item.recoveryOrigin),
                            scanSessionId = currentScanSessionId
                        )
                        analyzedList.add(rec)
                        CaseAndCustodyManager.addOrUpdateEvidenceInCase(getApplication(), currentCaseId, rec)
                    }
                }

                _caseEvidenceRecords.value = analyzedList
                if (analyzedList.isNotEmpty()) {
                    val first = analyzedList.first()
                    if (_activeForensicRecord.value == null) {
                        _activeForensicRecord.value = ForensicAnalyzer.applyRedactionToRecord(first, _privacyOptions.value)
                    }
                    first.sourceLocation?.let { parent ->
                        val f = File(parent, first.currentFilename)
                        if (f.exists()) inspectFileInAdvancedLabsInternal(f)
                    }
                }

                // Populate Multi-Strategy Duplicates, Relationships, and Thumbnail Explorer
                _multiStrategyDuplicates.value = DeepVaultLabsEngine.analyzeMultiStrategyDuplicates(candidateFilesForDup)
                _fileRelationships.value = DeepVaultLabsEngine.discoverFileRelationships(analyzedList)
                val allDiscoverable = if (_scanResults.value.isNotEmpty()) _scanResults.value else targetRecoverables
                _thumbnailForensicItems.value = DeepVaultLabsEngine.inspectAccessibleThumbnails(allDiscoverable)

                refreshCustodyLogState()
                rebuildCaseReportsFromCache()
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isAnalyzingForensics.value = false
                _forensicProgressText.value = ""
            }
        }
    }

    fun cancelForensicAnalysis() {
        forensicJob?.cancel()
        _isAnalyzingForensics.value = false
        _forensicProgressText.value = "Analysis cancelled by user."
    }

    fun updatePrivacyOptions(transform: (ForensicPrivacyOptions) -> ForensicPrivacyOptions) {
        val updated = transform(_privacyOptions.value)
        _privacyOptions.value = updated
        reportVersionCounter++
        val currentActiveId = _activeForensicRecord.value?.evidenceId
        if (currentActiveId != null) {
            val raw = _caseEvidenceRecords.value.firstOrNull { it.evidenceId == currentActiveId }
            if (raw != null) {
                _activeForensicRecord.value = ForensicAnalyzer.applyRedactionToRecord(raw, updated)
            }
        }
        rebuildCaseReportsFromCache()
    }

    private fun rebuildCaseReportsFromCache() {
        val raw = _caseEvidenceRecords.value
        val reports = ForensicAnalyzer.buildCaseReport(
            evidenceRecords = raw,
            reportType = if (raw.size == 1) "individual_file" else "combined_case",
            caseId = currentCaseId,
            scanSessionId = currentScanSessionId,
            privacyOptions = _privacyOptions.value,
            reportVersion = reportVersionCounter
        )
        _currentCaseReports.value = reports
    }

    fun exportForensicReport(
        formats: Set<ExportFormat>,
        singleRecordOnly: Boolean = false,
        onComplete: ((ExportedReportBundle) -> Unit)? = null
    ) {
        if (_isExportingReport.value) return
        _isExportingReport.value = true
        viewModelScope.launch {
            try {
                val rawRecords = if (singleRecordOnly && _activeForensicRecord.value != null) {
                    val activeId = _activeForensicRecord.value!!.evidenceId
                    val unredacted = _caseEvidenceRecords.value.firstOrNull { it.evidenceId == activeId }
                        ?: _activeForensicRecord.value!!
                    listOf(unredacted)
                } else {
                    _caseEvidenceRecords.value
                }

                val reportParts = ForensicAnalyzer.buildCaseReport(
                    evidenceRecords = rawRecords,
                    reportType = if (singleRecordOnly || rawRecords.size == 1) "individual_file" else "combined_case",
                    caseId = currentCaseId,
                    scanSessionId = currentScanSessionId,
                    privacyOptions = _privacyOptions.value,
                    reportVersion = reportVersionCounter
                )
                _currentCaseReports.value = reportParts

                val baseDir = ForensicReportExporter.getReportsBaseDir(getApplication())
                val bundle = ForensicReportExporter.exportReports(
                    reportParts = reportParts,
                    formats = formats,
                    outputRootDir = baseDir
                )
                _lastExportedBundle.value = bundle
                _exportHistory.value = listOf(bundle) + _exportHistory.value.filterNot { it.reportId == bundle.reportId && it.reportVersion == bundle.reportVersion }
                _lastVerificationResult.value = ForensicReportExporter.verifyExportedBundle(bundle)

                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.REPORT_EXPORTED,
                    caseId = currentCaseId,
                    details = "Exported forensic report bundle ${bundle.reportId} v${bundle.reportVersion} (sanitized=${bundle.isSanitized}, files=${bundle.files.size})"
                )
                refreshCustodyLogState()
                onComplete?.invoke(bundle)
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Safe guard
            } finally {
                _isExportingReport.value = false
            }
        }
    }

    fun verifyExportedBundleIntegrity(bundle: ExportedReportBundle? = _lastExportedBundle.value) {
        val target = bundle ?: return
        viewModelScope.launch {
            runCatching {
                val res = ForensicReportExporter.verifyExportedBundle(target)
                _lastVerificationResult.value = res
                CaseAndCustodyManager.appendCustodyEvent(
                    context = getApplication(),
                    actionType = CustodyActionType.FILE_VERIFIED,
                    caseId = currentCaseId,
                    details = "Verified exported bundle ${target.reportId}: allPassed=${res.allPassed} (${res.fileResults.count { it.passed }}/${res.fileResults.size} files matched SHA-256)"
                )
                refreshCustodyLogState()
            }
        }
    }

    private fun mapOriginToMethod(origin: String): String = when {
        origin.contains("Root", ignoreCase = true) -> "root_readonly_vfs_inspection"
        origin.contains("Carved", ignoreCase = true) -> "thumbdata_jpeg_stream_carve"
        origin.contains("Header Signature", ignoreCase = true) -> "magic_byte_carving"
        origin.contains("MediaStore", ignoreCase = true) || origin.contains("Trash", ignoreCase = true) -> "mediastore_trashed_query"
        else -> "filesystem_traversal"
    }

    // ---- Recovered history ----
    private val _recovered = MutableStateFlow<List<RecoveredRecord>>(emptyList())
    val recovered: StateFlow<List<RecoveredRecord>> = _recovered.asStateFlow()

    fun loadRecovered() {
        runCatching {
            _recovered.value = AppStore.loadRecovered(getApplication())
        }
    }

    // ---- Notifications ----
    private val _notifications = MutableStateFlow<List<SavedNotification>>(emptyList())
    val notifications: StateFlow<List<SavedNotification>> = _notifications.asStateFlow()

    fun loadNotifications() {
        runCatching {
            _notifications.value = AppStore.loadNotifications(getApplication())
        }
    }

    fun clearNotifications() {
        runCatching {
            AppStore.clearNotifications(getApplication())
            _notifications.value = emptyList()
        }
    }

    // ---- Contacts ----
    private val _contacts = MutableStateFlow<List<ContactInfo>>(emptyList())
    val contacts: StateFlow<List<ContactInfo>> = _contacts.asStateFlow()

    fun loadContacts() {
        viewModelScope.launch {
            runCatching {
                _contacts.value = ContactsHelper.loadContacts(getApplication())
            }
        }
    }
}
