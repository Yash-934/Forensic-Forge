package com.clone.filesrecovery.ui

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.FindInPage
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.IosShare
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.data.formatSize
import com.clone.filesrecovery.forensics.ExportFormat
import com.clone.filesrecovery.forensics.ExportedReportBundle
import com.clone.filesrecovery.forensics.ForensicCaseReport
import com.clone.filesrecovery.forensics.ForensicEvidenceRecord
import com.clone.filesrecovery.forensics.ForensicPrivacyOptions
import com.clone.filesrecovery.forensics.ForensicReportExporter
import com.clone.filesrecovery.forensics.ReportVerificationResult
import java.util.Locale

@Composable
fun ForensicLabScreen(
    nav: NavController,
    vm: AppViewModel,
    initialTab: Int = 0
) {
    val context = LocalContext.current
    val isAnalyzing by vm.isAnalyzingForensics.collectAsState()
    val progressText by vm.forensicProgressText.collectAsState()
    val analyzedCount by vm.forensicAnalyzedCount.collectAsState()
    val totalCount by vm.forensicTotalCount.collectAsState()
    val evidenceRecords by vm.caseEvidenceRecords.collectAsState()
    val caseReports by vm.currentCaseReports.collectAsState()
    val privacyOptions by vm.privacyOptions.collectAsState()
    val isExporting by vm.isExportingReport.collectAsState()
    val lastBundle by vm.lastExportedBundle.collectAsState()
    val verificationResult by vm.lastVerificationResult.collectAsState()

    var selectedTab by remember { mutableIntStateOf(initialTab) }

    // Automatically trigger initial forensic case analysis if no evidence records are loaded yet
    LaunchedEffect(Unit) {
        if (evidenceRecords.isEmpty() && !isAnalyzing) {
            vm.runCaseForensicAnalysis()
        }
    }

    val primaryReport = caseReports.firstOrNull()

    SimpleScaffold(
        title = "DeepVault Forensic Lab",
        onBack = { nav.popBackStack() },
        actions = {
            IconButton(
                onClick = { vm.runCaseForensicAnalysis() },
                enabled = !isAnalyzing,
                modifier = Modifier.testTag("forensic_run_analysis_btn")
            ) {
                Icon(
                    imageVector = Icons.Outlined.Refresh,
                    contentDescription = "Re-run Forensic Analysis",
                    tint = PrimaryGreen
                )
            }
        }
    ) { mod ->
        Column(
            modifier = mod
                .fillMaxSize()
                .background(SurfaceGray)
        ) {
            // Top Case Telemetry Header Card
            ForensicCaseHeaderBanner(
                caseId = vm.currentCaseId,
                report = primaryReport,
                isAnalyzing = isAnalyzing,
                progressText = progressText,
                analyzedCount = analyzedCount,
                totalCount = totalCount,
                onCancel = { vm.cancelForensicAnalysis() },
                onQuickExportBundle = {
                    vm.exportForensicReport(
                        formats = setOf(
                            ExportFormat.JSON,
                            ExportFormat.MARKDOWN,
                            ExportFormat.PDF,
                            ExportFormat.CSV,
                            ExportFormat.EXTERNAL_AI_BUNDLE
                        )
                    ) { bundle ->
                        Toast.makeText(
                            context,
                            "Exported AI Bundle (${bundle.files.size} files) & verified SHA-256 manifest",
                            Toast.LENGTH_SHORT
                        ).show()
                        selectedTab = 3
                    }
                }
            )

            // Quick-Launch Strip to Advanced Forensics Lab, File Repair Lab & Case Manager
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { nav.navigate("advanced_forensics_lab") },
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.testTag("open_advanced_forensics_lab_btn")
                ) {
                    Icon(Icons.Outlined.Science, contentDescription = null, modifier = Modifier.size(15.dp), tint = PrimaryGreen)
                    Spacer(Modifier.width(4.dp))
                    Text("Hex / SQLite / Archive Lab", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = PrimaryGreen)
                }
                OutlinedButton(
                    onClick = { nav.navigate("file_repair_lab") },
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.testTag("open_file_repair_lab_btn")
                ) {
                    Text("File Repair Lab", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = SelectionOrange)
                }
                OutlinedButton(
                    onClick = { nav.navigate("case_manager") },
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.testTag("open_case_manager_btn")
                ) {
                    Text("Cases & Chain of Custody", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = AccentEmerald)
                }
            }

            // 5-Tab Navigation Bar
            val tabs = listOf(
                Triple(0, "Evidence (${evidenceRecords.size})", "forensic_tab_evidence"),
                Triple(1, "Timeline & Findings", "forensic_tab_timeline"),
                Triple(2, "Privacy & Redact", "forensic_tab_privacy"),
                Triple(3, "Export & AI Brief", "forensic_tab_export"),
                Triple(4, "SHA-256 Verify", "forensic_tab_verify")
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                tabs.forEach { (idx, label, tag) ->
                    val active = selectedTab == idx
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(12.dp))
                            .background(
                                if (active) PrimaryGreen else Color.White
                            )
                            .border(
                                width = 1.dp,
                                color = if (active) PrimaryGreen else Color(0xFFE2E8F0),
                                shape = RoundedCornerShape(12.dp)
                            )
                            .clickable { selectedTab = idx }
                            .padding(horizontal = 14.dp, vertical = 9.dp)
                            .testTag(tag)
                    ) {
                        Text(
                            text = label,
                            color = if (active) Color.White else TextPrimary,
                            fontSize = 13.sp,
                            fontWeight = if (active) FontWeight.Bold else FontWeight.Medium
                        )
                    }
                }
            }

            // Tab Content
            Box(modifier = Modifier.fillMaxSize()) {
                when (selectedTab) {
                    0 -> EvidenceListTab(
                        report = primaryReport,
                        vm = vm,
                        onExportSingle = {
                            vm.exportForensicReport(
                                formats = setOf(ExportFormat.JSON, ExportFormat.MARKDOWN, ExportFormat.PDF, ExportFormat.CSV),
                                singleRecordOnly = true
                            ) {
                                Toast.makeText(context, "Single-file forensic report exported!", Toast.LENGTH_SHORT).show()
                                selectedTab = 3
                            }
                        }
                    )
                    1 -> TimelineAndFindingsTab(report = primaryReport)
                    2 -> PrivacyAndRedactionTab(
                        privacyOptions = privacyOptions,
                        allRawRecords = evidenceRecords,
                        onUpdatePrivacy = { vm.updatePrivacyOptions(it) }
                    )
                    3 -> ExportAndExternalAiTab(
                        report = primaryReport,
                        isExporting = isExporting,
                        lastBundle = lastBundle,
                        onExportFormats = { formats ->
                            vm.exportForensicReport(formats = formats) { bundle ->
                                Toast.makeText(
                                    context,
                                    "Generated ${bundle.files.size} report files in ${bundle.manifestFile.parentFile?.name}",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    )
                    4 -> IntegrityVerificationTab(
                        lastBundle = lastBundle,
                        verificationResult = verificationResult,
                        onVerifyNow = { vm.verifyExportedBundleIntegrity() },
                        onGenerateBundleFirst = {
                            vm.exportForensicReport(
                                formats = setOf(
                                    ExportFormat.JSON,
                                    ExportFormat.MARKDOWN,
                                    ExportFormat.PDF,
                                    ExportFormat.CSV,
                                    ExportFormat.EXTERNAL_AI_BUNDLE
                                )
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun ForensicCaseHeaderBanner(
    caseId: String,
    report: ForensicCaseReport?,
    isAnalyzing: Boolean,
    progressText: String,
    analyzedCount: Int,
    totalCount: Int,
    onCancel: () -> Unit,
    onQuickExportBundle: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 8.dp),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = DarkCardBg)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.linearGradient(
                        listOf(Color(0xFF0F172A), Color(0xFF1E1B4B))
                    )
                )
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(RoundedCornerShape(11.dp))
                            .background(PrimaryGreen.copy(alpha = 0.25f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Science,
                            contentDescription = "Forensic Engine",
                            tint = AccentCyan,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = caseId,
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                            Spacer(Modifier.width(8.dp))
                            val sanitized = report?.isSanitized == true
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(
                                        if (sanitized) SelectionOrange.copy(alpha = 0.22f)
                                        else AccentEmerald.copy(alpha = 0.22f)
                                    )
                                    .padding(horizontal = 7.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = if (sanitized) "SANITIZED v${report?.reportVersion ?: 1}" else "SCHEMA v1.0",
                                    color = if (sanitized) SelectionOrange else AccentEmerald,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                        Text(
                            text = "Deterministic Offline Analysis • Zero External AI Calls",
                            color = Color(0xFF94A3B8),
                            fontSize = 11.sp
                        )
                    }
                }

                if (!isAnalyzing) {
                    Button(
                        onClick = onQuickExportBundle,
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.testTag("header_quick_export_btn")
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.IosShare,
                            contentDescription = "Export Bundle",
                            modifier = Modifier.size(15.dp)
                        )
                        Spacer(Modifier.width(5.dp))
                        Text("AI Bundle", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            if (isAnalyzing) {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = progressText.ifBlank { "Running binary signature & hash analysis…" },
                        color = Color(0xFFE2E8F0),
                        fontSize = 12.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Cancel",
                        color = CoralRed,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier
                            .clickable { onCancel() }
                            .padding(4.dp)
                            .testTag("forensic_cancel_btn")
                    )
                }
                Spacer(Modifier.height(6.dp))
                val progress = if (totalCount > 0) analyzedCount.toFloat() / totalCount.toFloat() else 0.3f
                LinearProgressIndicator(
                    progress = { progress.coerceIn(0.05f, 1f) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(CircleShape),
                    color = AccentCyan,
                    trackColor = Color(0xFF334155)
                )
            } else if (report != null) {
                Spacer(Modifier.height(12.dp))
                val st = report.recoveryStats
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatMiniPill("Evaluated", "${st.totalFilesEvaluated}", AccentCyan)
                    StatMiniPill("Verified", "${st.recoveredCompleteCount}", AccentEmerald)
                    StatMiniPill("Partial/Carved", "${st.partialOrCarvedCount}", SelectionOrange)
                    StatMiniPill("Warnings", "${st.corruptedOrWarningCount + st.extensionMismatchCount}", CoralRed)
                    StatMiniPill("Duplicates", "${st.duplicateGroupCount}", Color(0xFFA855F7))
                }
            }
        }
    }
}

@Composable
private fun StatMiniPill(label: String, value: String, accent: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            color = accent,
            fontWeight = FontWeight.ExtraBold,
            fontSize = 15.sp
        )
        Text(
            text = label,
            color = Color(0xFF94A3B8),
            fontSize = 10.sp
        )
    }
}

// ==================== TAB 0: EVIDENCE & METADATA ====================

@Composable
private fun EvidenceListTab(
    report: ForensicCaseReport?,
    vm: AppViewModel,
    onExportSingle: () -> Unit
) {
    val context = LocalContext.current
    val items = report?.evidenceItems ?: emptyList()

    if (items.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = Icons.Outlined.FindInPage,
                    contentDescription = "No Evidence Loaded",
                    tint = TextSecondary,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "No Evidence Items in Current Case",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    color = TextPrimary
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Tap Refresh above or run a Photo, Video, Audio, or Document scan first to populate deterministic forensic evidence records.",
                    fontSize = 13.sp,
                    color = TextSecondary
                )
            }
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        items(items, key = { it.evidenceId }) { record ->
            EvidenceRecordCard(
                record = record,
                onCopyHash = { sha ->
                    ForensicReportExporter.copyTextToClipboard(context, "SHA-256 (${record.evidenceId})", sha)
                    Toast.makeText(context, "Copied SHA-256 for ${record.evidenceId}", Toast.LENGTH_SHORT).show()
                },
                onExportSingle = onExportSingle
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvidenceRecordCard(
    record: ForensicEvidenceRecord,
    onCopyHash: (String) -> Unit,
    onExportSingle: () -> Unit
) {
    var expanded by remember { mutableStateOf(true) }
    var refHashInput by remember { mutableStateOf(record.referenceHash ?: "") }

    val structColor = when (record.structureCheck) {
        "passed" -> AccentEmerald
        "warning" -> SelectionOrange
        "corrupted" -> CoralRed
        else -> TextSecondary
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("evidence_card_${record.evidenceId}"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(PrimaryGreen.copy(alpha = 0.12f))
                        .padding(horizontal = 8.dp, vertical = 5.dp)
                ) {
                    Text(
                        text = record.evidenceId,
                        color = PrimaryGreen,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = record.currentFilename,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${record.detectedFormat} (${record.detectedMimeType}) • ${formatSize(record.sizeBytes)}",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                }
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(structColor.copy(alpha = 0.14f))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = record.structureCheck.uppercase(Locale.US),
                        color = structColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 10.sp
                    )
                }
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                        contentDescription = "Toggle Evidence Details"
                    )
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 10.dp)) {
                    HorizontalDivider(color = DividerLight)
                    Spacer(Modifier.height(10.dp))

                    // Binary Magic & Structure Summary
                    ForensicKeyValueRow("Magic Bytes (Hex)", record.signatureHex.ifBlank { "empty" }, mono = true)
                    ForensicKeyValueRow("Signature Detail", record.magicDescription)
                    ForensicKeyValueRow("Structure Check", "${record.structureCheck.uppercase(Locale.US)} — ${record.structureDetail}")
                    ForensicKeyValueRow("Recovery Status", "${record.recoveryStatus} via ${record.recoveryMethod} (Completeness: ${record.completenessStatus})")
                    if (record.extensionMismatch) {
                        ForensicKeyValueRow(
                            label = "Extension Mismatch",
                            value = record.extensionMismatchDetail ?: "Extension does not match binary header",
                            highlightColor = CoralRed
                        )
                    }
                    if (record.sourceLocation != null) {
                        ForensicKeyValueRow("Source Location", record.sourceLocation, mono = true)
                    }
                    if (record.recoveredOutputPath != null) {
                        ForensicKeyValueRow("Recovered Output", record.recoveredOutputPath, mono = true)
                    }

                    Spacer(Modifier.height(8.dp))
                    // Cryptographic Hash Block
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background( Color(0xFFF8FAFC))
                            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                            .padding(10.dp)
                    ) {
                        Column {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "CRYPTOGRAPHIC HASHES (${record.hashTarget.uppercase(Locale.US)})",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = PrimaryGreen
                                )
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .clickable { onCopyHash(record.sha256) }
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                        .testTag("copy_sha256_${record.evidenceId}")
                                ) {
                                    Icon(
                                        imageVector = Icons.Outlined.ContentCopy,
                                        contentDescription = "Copy SHA-256",
                                        tint = PrimaryGreen,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(Modifier.width(4.dp))
                                    Text("Copy SHA-256", fontSize = 11.sp, color = PrimaryGreen, fontWeight = FontWeight.SemiBold)
                                }
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = "SHA-256: ${record.sha256}",
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TextPrimary
                            )
                            if (record.md5 != null) {
                                Text(
                                    text = "MD5:     ${record.md5}",
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary
                                )
                            }
                            if (record.sha1 != null) {
                                Text(
                                    text = "SHA-1:   ${record.sha1}",
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary
                                )
                            }

                            // Interactive Reference Hash Comparison
                            Spacer(Modifier.height(6.dp))
                            OutlinedTextField(
                                value = refHashInput,
                                onValueChange = { refHashInput = it.trim() },
                                label = { Text("Compare Reference Hash (SHA-256 / MD5 / SHA-1)", fontSize = 11.sp) },
                                singleLine = true,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("ref_hash_input_${record.evidenceId}")
                            )
                            if (refHashInput.isNotBlank()) {
                                val matched = refHashInput.equals(record.sha256, ignoreCase = true) ||
                                    refHashInput.equals(record.md5, ignoreCase = true) ||
                                    refHashInput.equals(record.sha1, ignoreCase = true)
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = if (matched) "✓ Reference Hash MATCHED" else "✗ Reference Hash MISMATCH",
                                    color = if (matched) AccentEmerald else CoralRed,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp
                                )
                            }
                        }
                    }

                    // Extracted Metadata Fields with Provenance
                    if (record.extractedFields.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = "Deterministic Extracted Metadata (${record.extractedFields.size} fields)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(4.dp))
                        record.extractedFields.forEach { mf ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = mf.key,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary,
                                    modifier = Modifier.weight(0.42f)
                                )
                                Text(
                                    text = "${mf.value} [${mf.valueCategory}]",
                                    fontSize = 11.sp,
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Medium,
                                    modifier = Modifier.weight(0.58f)
                                )
                            }
                        }
                    }

                    // Unavailable fields (explicitly distinguished from tampering)
                    if (record.unavailableFields.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Unavailable / Absent Fields (Not Assumed Tampered): ${record.unavailableFields.joinToString(", ")}",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }

                    // Corruption indicators or inconsistencies
                    if (record.corruptionIndicators.isNotEmpty() || record.metadataInconsistencies.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        (record.corruptionIndicators + record.metadataInconsistencies).forEach { warn ->
                            Text(
                                text = "⚠ $warn",
                                fontSize = 11.sp,
                                color = CoralRed,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        OutlinedButton(
                            onClick = onExportSingle,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("forensic_export_single_btn")
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Description,
                                contentDescription = "Export Single Report",
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("Export Single-File Report", fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ForensicKeyValueRow(
    label: String,
    value: String,
    mono: Boolean = false,
    highlightColor: Color? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
    ) {
        Text(
            text = "$label:",
            fontSize = 12.sp,
            color = TextSecondary,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.width(132.dp)
        )
        Text(
            text = value,
            fontSize = 12.sp,
            color = highlightColor ?: TextPrimary,
            fontWeight = if (highlightColor != null) FontWeight.Bold else FontWeight.Normal,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
            modifier = Modifier.weight(1f)
        )
    }
}

// ==================== TAB 1: TIMELINE & FINDINGS ====================

@Composable
private fun TimelineAndFindingsTab(report: ForensicCaseReport?) {
    if (report == null) return
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.WarningAmber,
                            contentDescription = "Rule-Based Findings",
                            tint = SelectionOrange
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Rule-Based Forensic Findings (${report.findings.size})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = TextPrimary
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    if (report.findings.isEmpty()) {
                        Text(
                            text = "No structural anomalies or rule-based warnings triggered across evaluated items.",
                            fontSize = 13.sp,
                            color = TextSecondary
                        )
                    } else {
                        report.findings.forEach { f ->
                            val sevColor = when (f.severity) {
                                "high" -> CoralRed
                                "warning" -> SelectionOrange
                                "notice" -> AccentCyan
                                else -> AccentEmerald
                            }
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(sevColor.copy(alpha = 0.08f))
                                    .padding(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "[${f.severity.uppercase(Locale.US)}] ${f.title}",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp,
                                        color = sevColor
                                    )
                                    Text(
                                        text = "${f.evidenceId} • ${f.observationBasis}",
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = TextSecondary
                                    )
                                }
                                Spacer(Modifier.height(3.dp))
                                Text(
                                    text = f.description,
                                    fontSize = 12.sp,
                                    color = TextPrimary
                                )
                            }
                        }
                    }
                }
            }
        }

        // Duplicate Clusters
        if (report.duplicateGroups.isNotEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Exact SHA-256 Duplicate Clusters (${report.duplicateGroups.size})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(8.dp))
                        report.duplicateGroups.forEach { dg ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFFF8FAFC))
                                    .padding(10.dp)
                            ) {
                                Text(
                                    text = "${dg.groupId} • ${dg.evidenceIds.joinToString(", ")}",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = PrimaryGreen
                                )
                                Text(
                                    text = "SHA-256: ${dg.hashValue}",
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary
                                )
                                Text(
                                    text = "Files: ${dg.filenames.joinToString(", ")}",
                                    fontSize = 12.sp,
                                    color = TextPrimary
                                )
                            }
                        }
                    }
                }
            }
        }

        // Chronological Timeline
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.History,
                            contentDescription = "Chronological Timeline",
                            tint = PrimaryGreen
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Forensic Event Timeline (${report.timeline.size} events)",
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = TextPrimary
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Timestamps preserve explicit timezone provenance (UTC vs offset vs local_unverified).",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(8.dp))
                    report.timeline.forEach { ev ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 5.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(PrimaryGreen.copy(alpha = 0.1f))
                                    .padding(horizontal = 6.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = ev.evidenceId,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = PrimaryGreen,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Spacer(Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${ev.timestampIso ?: ev.timestampRaw}  [${ev.timezoneStatus}]",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "${ev.eventType} • Source: ${ev.source}",
                                    fontSize = 11.sp,
                                    color = TextSecondary
                                )
                            }
                        }
                        HorizontalDivider(color = DividerLight)
                    }
                }
            }
        }
    }
}

// ==================== TAB 2: PRIVACY & REDACTION ====================

@Composable
private fun PrivacyAndRedactionTab(
    privacyOptions: ForensicPrivacyOptions,
    allRawRecords: List<ForensicEvidenceRecord>,
    onUpdatePrivacy: ((ForensicPrivacyOptions) -> ForensicPrivacyOptions) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.PrivacyTip,
                            contentDescription = "Privacy Controls",
                            tint = PrimaryGreen
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Non-Destructive Report Sanitization",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            color = TextPrimary
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "Redaction modifies only the generated forensic reports and External AI Bundles. Underlying evidence files on disk are never altered.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(12.dp))

                    // Toggle 1: Include GPS Coordinates
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Include EXIF GPS Coordinates", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text("Turn off to strip latitude, longitude & altitude from reports", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = privacyOptions.includeGps,
                            onCheckedChange = { checked ->
                                onUpdatePrivacy { it.copy(includeGps = checked) }
                            },
                            modifier = Modifier.testTag("privacy_toggle_gps")
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = DividerLight)

                    // Toggle 2: Redact Sensitive Filesystem Paths
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Redact Sensitive Directory Paths", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text("Replaces parent path segments with [REDACTED_PATH]", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = privacyOptions.redactSensitivePaths,
                            onCheckedChange = { checked ->
                                onUpdatePrivacy { it.copy(redactSensitivePaths = checked) }
                            },
                            modifier = Modifier.testTag("privacy_toggle_paths")
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = DividerLight)

                    // Toggle 3: Exclude Personal Filenames
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Exclude Personal Filenames", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text("Replaces filenames with [REDACTED_FILENAME_DV-XXXXXX] while keeping SHA-256", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = privacyOptions.excludePersonalFilenames,
                            onCheckedChange = { checked ->
                                onUpdatePrivacy { it.copy(excludePersonalFilenames = checked) }
                            },
                            modifier = Modifier.testTag("privacy_toggle_filenames")
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = DividerLight)

                    // Toggle 4: Exclude Personal Metadata (Author/Camera/Owner)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Exclude Personal & Device Metadata", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text("Strips document author/creator, camera make/model/serial & artist tags", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = privacyOptions.excludePersonalMetadata,
                            onCheckedChange = { checked ->
                                onUpdatePrivacy { it.copy(excludePersonalMetadata = checked) }
                            },
                            modifier = Modifier.testTag("privacy_toggle_personal_meta")
                        )
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = DividerLight)

                    // Toggle 5: Exclude Analyst Notes
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Exclude Analyst Case Notes", fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                            Text("Omits internal analyst observations & notes from exported reports", fontSize = 12.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = privacyOptions.excludeNotes,
                            onCheckedChange = { checked ->
                                onUpdatePrivacy { it.copy(excludeNotes = checked) }
                            },
                            modifier = Modifier.testTag("privacy_toggle_notes")
                        )
                    }

                    Spacer(Modifier.height(12.dp))
                    val summary = privacyOptions.buildRedactionSummary()
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(
                                if (privacyOptions.isSanitized) SelectionOrange.copy(alpha = 0.12f)
                                else AccentEmerald.copy(alpha = 0.12f)
                            )
                            .padding(12.dp)
                    ) {
                        Text(
                            text = if (privacyOptions.isSanitized) {
                                "Report Status: SANITIZED — Active rules: ${summary.joinToString(", ")}"
                            } else {
                                "Report Status: UNREDACTED — Full forensic metadata included"
                            },
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (privacyOptions.isSanitized) SelectionOrange else AccentEmerald
                        )
                    }
                }
            }
        }

        // Evidence Selection / Exclusion List
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Evidence Scope Selection (${allRawRecords.size - privacyOptions.excludedEvidenceIds.size} of ${allRawRecords.size} included)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(8.dp))
                    allRawRecords.forEach { rec ->
                        val included = !privacyOptions.excludedEvidenceIds.contains(rec.evidenceId)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onUpdatePrivacy { old ->
                                        val nextExcl = if (included) old.excludedEvidenceIds + rec.evidenceId
                                        else old.excludedEvidenceIds - rec.evidenceId
                                        old.copy(excludedEvidenceIds = nextExcl)
                                    }
                                }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RoundCheckButton(
                                checked = included,
                                onToggle = {
                                    onUpdatePrivacy { old ->
                                        val nextExcl = if (included) old.excludedEvidenceIds + rec.evidenceId
                                        else old.excludedEvidenceIds - rec.evidenceId
                                        old.copy(excludedEvidenceIds = nextExcl)
                                    }
                                }
                            )
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${rec.evidenceId} — ${rec.currentFilename}",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (included) TextPrimary else TextSecondary
                                )
                                Text(
                                    text = "${rec.detectedFormat} • ${formatSize(rec.sizeBytes)}",
                                    fontSize = 11.sp,
                                    color = TextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==================== TAB 3: EXPORT & EXTERNAL AI HANDOFF ====================

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ExportAndExternalAiTab(
    report: ForensicCaseReport?,
    isExporting: Boolean,
    lastBundle: ExportedReportBundle?,
    onExportFormats: (Set<ExportFormat>) -> Unit
) {
    val context = LocalContext.current
    var selectedPromptTemplate by remember {
        mutableStateOf(ForensicReportExporter.PromptTemplateType.ANOMALY_REVIEW)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Multi-Format Export Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Generate & Export Forensic Reports",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Exports deterministic reports with Schema v1.0 metadata and a verifiable SHA-256 manifest.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(8.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(SelectionOrange.copy(alpha = 0.12f))
                            .padding(10.dp)
                    ) {
                        Text(
                            text = "Privacy Notice: DeepVault never automatically uploads reports. If you manually upload an exported report to an external AI provider, that provider may process uploaded information according to its own data policies. Use the Privacy & Redact tab to sanitize GPS, paths, and filenames before export.",
                            fontSize = 11.sp,
                            color = SelectionOrange,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Spacer(Modifier.height(12.dp))

                    Button(
                        onClick = {
                            onExportFormats(
                                setOf(
                                    ExportFormat.JSON,
                                    ExportFormat.MARKDOWN,
                                    ExportFormat.PDF,
                                    ExportFormat.CSV,
                                    ExportFormat.EXTERNAL_AI_BUNDLE
                                )
                            )
                        },
                        enabled = !isExporting && report != null,
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("export_bundle_btn")
                    ) {
                        if (isExporting) {
                            CircularProgressIndicator(
                                color = Color.White,
                                strokeWidth = 2.dp,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("Generating Reports & SHA-256 Manifest…")
                        } else {
                            Icon(imageVector = Icons.Outlined.IosShare, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Export Complete External AI Bundle (All Formats)", fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { onExportFormats(setOf(ExportFormat.JSON)) },
                            enabled = !isExporting && report != null,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("export_json_btn")
                        ) {
                            Text("JSON (v1.0)", fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = { onExportFormats(setOf(ExportFormat.MARKDOWN)) },
                            enabled = !isExporting && report != null,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("export_md_btn")
                        ) {
                            Text("Markdown (.md)", fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = { onExportFormats(setOf(ExportFormat.PDF)) },
                            enabled = !isExporting && report != null,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("export_pdf_btn")
                        ) {
                            Text("Printable PDF", fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = { onExportFormats(setOf(ExportFormat.CSV)) },
                            enabled = !isExporting && report != null,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("export_csv_btn")
                        ) {
                            Text("CSV Tables (3x)", fontSize = 12.sp)
                        }
                    }

                    if (lastBundle != null) {
                        Spacer(Modifier.height(12.dp))
                        HorizontalDivider(color = DividerLight)
                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = "Latest Exported Bundle: ${lastBundle.caseId} / ${lastBundle.reportId} (v${lastBundle.reportVersion})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = AccentEmerald
                        )
                        Text(
                            text = "Saved to: ${lastBundle.manifestFile.parentFile?.absolutePath}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = TextSecondary
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { ForensicReportExporter.shareExportedBundle(context, lastBundle) },
                                colors = ButtonDefaults.buttonColors(containerColor = AccentCyan),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.testTag("share_bundle_btn")
                            ) {
                                Icon(imageVector = Icons.Outlined.IosShare, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Share Bundle to External App", fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }

        // User-Initiated External AI Handoff Prompts Card
        if (report != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "User-Initiated External AI Handoff Prompts",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "DeepVault contains no internal AI SDK. Copy a deterministic prompt below and upload your exported report to any external AI tool of your choice.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                        Spacer(Modifier.height(10.dp))

                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            ForensicReportExporter.PromptTemplateType.entries.forEach { tmpl ->
                                FilterChip(
                                    selected = selectedPromptTemplate == tmpl,
                                    onClick = { selectedPromptTemplate = tmpl },
                                    label = { Text(tmpl.title, fontSize = 12.sp) }
                                )
                            }
                        }

                        Spacer(Modifier.height(8.dp))
                        val promptText = remember(selectedPromptTemplate, report) {
                            ForensicReportExporter.buildPromptText(selectedPromptTemplate, report, includeExcerpt = true)
                        }
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color(0xFF0F172A))
                                .padding(12.dp)
                        ) {
                            Text(
                                text = promptText,
                                color = Color(0xFFE2E8F0),
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        Spacer(Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    ForensicReportExporter.copyTextToClipboard(
                                        context,
                                        "DeepVault AI Prompt (${selectedPromptTemplate.title})",
                                        promptText
                                    )
                                    Toast.makeText(context, "Copied AI Prompt & Case Excerpt to clipboard!", Toast.LENGTH_SHORT).show()
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("copy_ai_prompt_btn")
                            ) {
                                Icon(imageVector = Icons.Outlined.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Copy Prompt", fontSize = 12.sp)
                            }

                            OutlinedButton(
                                onClick = {
                                    val md = ForensicReportExporter.toMarkdownString(report)
                                    ForensicReportExporter.copyTextToClipboard(
                                        context,
                                        "DeepVault Markdown Report (${report.reportId})",
                                        md
                                    )
                                    Toast.makeText(context, "Copied Full Markdown Report to clipboard!", Toast.LENGTH_SHORT).show()
                                },
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("copy_markdown_report_btn")
                            ) {
                                Icon(imageVector = Icons.Outlined.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Copy Full .MD", fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==================== TAB 4: SHA-256 MANIFEST INTEGRITY VERIFIER ====================

@Composable
private fun IntegrityVerificationTab(
    lastBundle: ExportedReportBundle?,
    verificationResult: ReportVerificationResult?,
    onVerifyNow: () -> Unit,
    onGenerateBundleFirst: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.VerifiedUser,
                            contentDescription = "SHA-256 Verifier",
                            tint = PrimaryGreen
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Cryptographic Report & Manifest Verification",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            color = TextPrimary
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(12.dp))

                    if (lastBundle == null) {
                        Text(
                            text = "No report bundle has been exported in this session yet.",
                            fontSize = 13.sp,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(10.dp))
                        Button(
                            onClick = onGenerateBundleFirst,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("verify_generate_bundle_btn")
                        ) {
                            Text("Generate & Verify Bundle Now")
                        }
                    } else {
                        Button(
                            onClick = onVerifyNow,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("verify_manifest_btn")
                        ) {
                            Icon(imageVector = Icons.Outlined.Security, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Re-Verify Exported Files Against sha256_manifest.txt")
                        }

                        if (verificationResult != null) {
                            Spacer(Modifier.height(12.dp))
                            val ok = verificationResult.allPassed
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(
                                        if (ok) AccentEmerald.copy(alpha = 0.14f)
                                        else CoralRed.copy(alpha = 0.14f)
                                    )
                                    .padding(12.dp)
                                    .testTag("verification_status_banner")
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = if (ok) Icons.Outlined.GppGood else Icons.Outlined.ErrorOutline,
                                        contentDescription = null,
                                        tint = if (ok) AccentEmerald else CoralRed
                                    )
                                    Spacer(Modifier.width(10.dp))
                                    Column {
                                        Text(
                                            text = verificationResult.summaryMessage,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 13.sp,
                                            color = if (ok) AccentEmerald else CoralRed
                                        )
                                        Text(
                                            text = "Verified At (UTC): ${verificationResult.verifiedAtIso}",
                                            fontSize = 11.sp,
                                            color = TextSecondary
                                        )
                                    }
                                }
                            }

                            Spacer(Modifier.height(10.dp))
                            verificationResult.fileResults.forEach { fr ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (fr.passed) Icons.Outlined.CheckCircle else Icons.Outlined.ErrorOutline,
                                        contentDescription = null,
                                        tint = if (fr.passed) AccentEmerald else CoralRed,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "${fr.filename} (${fr.role})",
                                            fontWeight = FontWeight.SemiBold,
                                            fontSize = 13.sp,
                                            color = TextPrimary
                                        )
                                        Text(
                                            text = "Expected: ${fr.expectedSha256}",
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = TextSecondary
                                        )
                                        Text(
                                            text = "Actual:   ${fr.actualSha256 ?: "MISSING_FILE"}",
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = if (fr.passed) AccentEmerald else CoralRed
                                        )
                                    }
                                }
                                HorizontalDivider(color = DividerLight)
                            }
                        }
                    }
                }
            }
        }
    }
}
