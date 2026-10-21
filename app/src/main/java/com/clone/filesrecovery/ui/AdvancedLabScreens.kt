package com.clone.filesrecovery.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.Archive
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.CompareArrows
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material.icons.outlined.FileOpen
import androidx.compose.material.icons.outlined.FolderSpecial
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.ImageSearch
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.RuleFolder
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import com.clone.filesrecovery.forensics.ArchiveForensicReport
import com.clone.filesrecovery.forensics.CarvedStreamResult
import com.clone.filesrecovery.forensics.CaseEvidenceItem
import com.clone.filesrecovery.forensics.ChainIntegrityVerification
import com.clone.filesrecovery.forensics.ChainOfCustodyEntry
import com.clone.filesrecovery.forensics.DuplicateMatchStrategy
import com.clone.filesrecovery.forensics.EvidenceComparisonResult
import com.clone.filesrecovery.forensics.FileRelationshipEdge
import com.clone.filesrecovery.forensics.FileRepairOutcome
import com.clone.filesrecovery.forensics.FileRepairReport
import com.clone.filesrecovery.forensics.FileStructureAnalysis
import com.clone.filesrecovery.forensics.ForensicReportExporter
import com.clone.filesrecovery.forensics.HexSearchMatch
import com.clone.filesrecovery.forensics.HexViewerPage
import com.clone.filesrecovery.forensics.MultiStrategyDuplicateCluster
import com.clone.filesrecovery.forensics.RecoveryClassification
import com.clone.filesrecovery.forensics.SqliteForensicReport
import com.clone.filesrecovery.forensics.ThumbnailForensicItem
import java.io.File
import java.util.Locale

// ============================================================================
// SCREEN 1: ADVANCED FORENSICS LAB (Section 5: Hex, Structure, SQLite, Archive,
//           Duplicates, Relationships, Thumbnails & SAF File Acquisition)
// ============================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdvancedForensicsLabScreen(nav: NavController, vm: AppViewModel) {
    BackHandler { nav.popBackStack() }
    val context = LocalContext.current

    val selectedFile by vm.selectedLabFile.collectAsState()
    val evidenceRecords by vm.caseEvidenceRecords.collectAsState()
    val hexPage by vm.hexViewerPage.collectAsState()
    val hexMatches by vm.hexSearchMatches.collectAsState()
    val structAnalysis by vm.activeStructureAnalysis.collectAsState()
    val archiveReport by vm.activeArchiveReport.collectAsState()
    val sqliteReport by vm.activeSqliteReport.collectAsState()
    val duplicateClusters by vm.multiStrategyDuplicates.collectAsState()
    val relationships by vm.fileRelationships.collectAsState()
    val thumbnails by vm.thumbnailForensicItems.collectAsState()
    val carvedStreams by vm.carvedStreams.collectAsState()

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(
        "Hex Viewer",
        "Structure & Carving",
        "SQLite Forensics",
        "Archive Forensics",
        "Duplicates & Links",
        "Thumbnails"
    )

    val safDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            vm.importSafUriForForensics(uri)
            Toast.makeText(context, "Acquired read-only file stream via SAF", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        if (evidenceRecords.isEmpty()) {
            vm.runCaseForensicAnalysis()
        } else if (selectedFile == null) {
            val first = evidenceRecords.firstOrNull()
            val loc = first?.sourceLocation
            if (loc != null) {
                val f = File(loc, first.currentFilename)
                if (f.exists()) vm.selectFileForAdvancedLab(f)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "Advanced Forensics Lab",
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = "Hex • Structure • SQLite • Archive • Relationships",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                },
                navigationIcon = {
                    IconButton(
                        onClick = { nav.popBackStack() },
                        modifier = Modifier.testTag("adv_lab_back_btn")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = TextPrimary
                        )
                    }
                },
                actions = {
                    OutlinedButton(
                        onClick = { safDocumentLauncher.launch(arrayOf("*/*")) },
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                        modifier = Modifier
                            .padding(end = 8.dp)
                            .testTag("adv_lab_saf_open_btn")
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.FileOpen,
                            contentDescription = "Open File via SAF",
                            modifier = Modifier.size(16.dp),
                            tint = PrimaryGreen
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("Open File (SAF)", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = PrimaryGreen)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        containerColor = SoftSurfaceBg
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            // Active File Selector Strip
            LabTargetFileSelectorBar(
                selectedFile = selectedFile,
                evidenceRecords = evidenceRecords.mapNotNull { rec ->
                    val p = rec.sourceLocation ?: return@mapNotNull null
                    File(p, rec.currentFilename).takeIf { it.exists() }
                },
                onSelectFile = { vm.selectFileForAdvancedLab(it) },
                onOpenRepairLab = { nav.navigate("file_repair_lab") }
            )

            ScrollableTabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color.White,
                contentColor = PrimaryGreen,
                edgePadding = 12.dp
            ) {
                tabs.forEachIndexed { idx, title ->
                    Tab(
                        selected = selectedTab == idx,
                        onClick = { selectedTab = idx },
                        modifier = Modifier.testTag("adv_lab_tab_$idx"),
                        text = {
                            Text(
                                text = title,
                                fontWeight = if (selectedTab == idx) FontWeight.Bold else FontWeight.Medium,
                                fontSize = 13.sp
                            )
                        }
                    )
                }
            }

            when (selectedTab) {
                0 -> HexViewerTab(
                    page = hexPage,
                    matches = hexMatches,
                    onLoadPage = { offset -> vm.loadHexViewerPage(offset) },
                    onSearch = { q, isHex -> vm.searchInHexViewer(q, isHex) }
                )
                1 -> StructureAndCarvingTab(
                    analysis = structAnalysis,
                    carvedStreams = carvedStreams,
                    onRunCarver = { vm.runSignatureStreamCarvingOnSelectedFile() },
                    onOpenRepairLab = { nav.navigate("file_repair_lab") }
                )
                2 -> SqliteForensicsTab(
                    report = sqliteReport,
                    onOpenSafDb = { safDocumentLauncher.launch(arrayOf("*/*")) },
                    onLoadDiagnosticFixture = { vm.loadSqliteLabSelfTestFixture() }
                )
                3 -> ArchiveForensicsTab(
                    report = archiveReport,
                    onOpenSafArchive = { safDocumentLauncher.launch(arrayOf("application/zip", "*/*")) }
                )
                4 -> DuplicatesAndRelationshipsTab(
                    clusters = duplicateClusters,
                    relationships = relationships,
                    onRefresh = { vm.runCaseForensicAnalysis() }
                )
                5 -> ThumbnailExplorerTab(
                    items = thumbnails,
                    onInspectFile = { path ->
                        val f = File(path)
                        if (f.exists()) {
                            vm.selectFileForAdvancedLab(f)
                            selectedTab = 1
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun LabTargetFileSelectorBar(
    selectedFile: File?,
    evidenceRecords: List<File>,
    onSelectFile: (File) -> Unit,
    onOpenRepairLab: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = DarkCardBg)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "ACTIVE TARGET ARTIFACT (READ-ONLY)",
                        color = AccentCyan,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        text = selectedFile?.let { "${it.name} (${formatSize(it.length())})" }
                            ?: "Select an evidence artifact below or via SAF Open File",
                        color = Color.White,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = onOpenRepairLab,
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("goto_repair_lab_btn")
                ) {
                    Icon(Icons.Outlined.Build, contentDescription = "Repair Lab", modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Repair Lab", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                }
            }
            if (evidenceRecords.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(evidenceRecords.take(20), key = { it.absolutePath }) { f ->
                        val isSelected = selectedFile?.absolutePath == f.absolutePath
                        FilterChip(
                            selected = isSelected,
                            onClick = { onSelectFile(f) },
                            label = {
                                Text(
                                    text = f.name,
                                    fontSize = 11.sp,
                                    maxLines = 1
                                )
                            }
                        )
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 0: READ-ONLY STREAMING HEX VIEWER (Section 5.C)
// ============================================================================

@Composable
private fun HexViewerTab(
    page: HexViewerPage?,
    matches: List<HexSearchMatch>,
    onLoadPage: (Long) -> Unit,
    onSearch: (String, Boolean) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var isHexSearch by remember { mutableStateOf(true) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Streaming Hex & ASCII Inspector",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(Modifier.width(8.dp))
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(PrimaryGreen.copy(alpha = 0.12f))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = "512 B Window",
                                fontSize = 10.sp,
                                color = PrimaryGreen,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                softWrap = false
                            )
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Reads fixed 512-byte slices via RandomAccessFile without loading large files into RAM. Original evidence is strictly read-only.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )

                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            label = {
                                Text(
                                    if (isHexSearch) "Search Hex Bytes (e.g. FF D8 FF or 50 4B)" else "Search ASCII Text",
                                    fontSize = 11.sp
                                )
                            },
                            singleLine = true,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("hex_search_input")
                        )
                        Spacer(Modifier.width(8.dp))
                        Button(
                            onClick = { onSearch(searchQuery, isHexSearch) },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("hex_search_btn")
                        ) {
                            Icon(Icons.Outlined.Search, contentDescription = "Search", modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Find", fontSize = 12.sp)
                        }
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(top = 4.dp)
                    ) {
                        FilterChip(
                            selected = isHexSearch,
                            onClick = { isHexSearch = true },
                            label = { Text("Hex Pattern", fontSize = 11.sp) }
                        )
                        Spacer(Modifier.width(8.dp))
                        FilterChip(
                            selected = !isHexSearch,
                            onClick = { isHexSearch = false },
                            label = { Text("ASCII String", fontSize = 11.sp) }
                        )
                    }

                    if (matches.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Pattern Matches (${matches.size}) — Tap to Jump Offset:",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            color = PrimaryGreen
                        )
                        Spacer(Modifier.height(4.dp))
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(matches, key = { it.offset }) { m ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(PrimaryGreen.copy(alpha = 0.12f))
                                        .clickable { onLoadPage((m.offset / 16L) * 16L) }
                                        .padding(horizontal = 8.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        text = "${m.offsetHex} (${m.contextAscii.take(10)})",
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = PrimaryGreen,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        if (page != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        // Signature Highlight Banner
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "FILE SIGNATURE",
                                    color = AccentEmerald,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "Offset 0x${page.pageOffset.toString(16).uppercase(Locale.US)} / ${formatSize(page.totalFileSize)}",
                                    color = Color(0xFF94A3B8),
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                            Text(
                                text = page.signatureDescription,
                                color = Color.White,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        Spacer(Modifier.height(8.dp))
                        // Page Navigation Controls
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            OutlinedButton(
                                onClick = { onLoadPage(0L) },
                                enabled = page.pageOffset > 0L,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("Start (0x0)", fontSize = 11.sp, color = Color.White)
                            }
                            OutlinedButton(
                                onClick = { onLoadPage((page.pageOffset - 512L).coerceAtLeast(0L)) },
                                enabled = page.pageOffset > 0L,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("◀ -512 B", fontSize = 11.sp, color = Color.White)
                            }
                            OutlinedButton(
                                onClick = { onLoadPage(page.pageOffset + 512L) },
                                enabled = page.pageOffset + 512L < page.totalFileSize,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("+512 B ▶", fontSize = 11.sp, color = Color.White)
                            }
                            OutlinedButton(
                                onClick = { onLoadPage((page.totalFileSize - 512L).coerceAtLeast(0L)) },
                                enabled = page.totalFileSize > 512L,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text("EOF (Tail)", fontSize = 11.sp, color = Color.White)
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        HorizontalDivider(color = Color(0xFF334155))
                        Spacer(Modifier.height(6.dp))

                        val hScroll = rememberScrollState()
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(hScroll)
                        ) {
                            Text(
                                text = "OFFSET    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII",
                                color = AccentCyan,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.height(4.dp))
                            page.rows.forEach { row ->
                                val hexFormatted = row.hexBytes.joinToString(" ").padEnd(47, ' ')
                                val hasSigHighlight = row.highlightedByteIndices.isNotEmpty()
                                Text(
                                    text = "${row.offsetHex}  $hexFormatted  |${row.asciiText.padEnd(16, ' ')}|",
                                    color = if (hasSigHighlight) AccentEmerald else Color(0xFFE2E8F0),
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = if (hasSigHighlight) FontWeight.Bold else FontWeight.Normal
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 1: FILE STRUCTURE ANALYZER & SIGNATURE STREAM CARVING (Section 4 & 5.D)
// ============================================================================

@Composable
private fun StructureAndCarvingTab(
    analysis: FileStructureAnalysis?,
    carvedStreams: List<CarvedStreamResult>,
    onRunCarver: () -> Unit,
    onOpenRepairLab: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (analysis != null) {
            item {
                val badgeColor = when (analysis.recoveryClassification) {
                    RecoveryClassification.RECOVERED -> AccentEmerald
                    RecoveryClassification.PARTIALLY_RECOVERED -> SelectionOrange
                    RecoveryClassification.CORRUPTED, RecoveryClassification.FAILED -> CoralRed
                    else -> AccentCyan
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = analysis.detectedFormat,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 16.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "${analysis.fileName} • ${formatSize(analysis.fileSize)}",
                                    fontSize = 12.sp,
                                    color = TextSecondary
                                )
                            }
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(badgeColor.copy(alpha = 0.14f))
                                    .padding(horizontal = 10.dp, vertical = 5.dp)
                            ) {
                                Text(
                                    text = analysis.recoveryClassification.code,
                                    color = badgeColor,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp
                                )
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        HorizontalDivider(color = DividerLight)
                        Spacer(Modifier.height(8.dp))

                        LabKvRow("Magic Bytes", analysis.recognizedSignatureHex, mono = true)
                        LabKvRow("Expected Spec", analysis.expectedStructureSummary)
                        LabKvRow("Header Validation", "${if (analysis.headerValid) "PASSED" else "FAILED"} — ${analysis.headerDetail}")
                        LabKvRow(
                            "Footer Validation",
                            when (analysis.footerValid) {
                                true -> "PASSED — ${analysis.footerDetail}"
                                false -> "MISSING/FAILED — ${analysis.footerDetail}"
                                null -> "N/A — ${analysis.footerDetail}"
                            }
                        )
                        LabKvRow("Truncated?", if (analysis.isTruncated) "YES (${analysis.truncationIndicators.joinToString()})" else "No")
                        LabKvRow(
                            "Trailing Data",
                            if (analysis.unexpectedTrailingBytes > 0) {
                                "${analysis.unexpectedTrailingBytes} bytes (${analysis.trailingDataNote})"
                            } else {
                                "0 bytes beyond container end"
                            }
                        )
                        LabKvRow("Fragmentation", "${analysis.fragmentationAssessment.statusLabel} — ${analysis.fragmentationAssessment.notes}")

                        if (analysis.chunksOrBoxesSummary.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text("Observed Container Chunks / Markers / Boxes:", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            analysis.chunksOrBoxesSummary.forEach { c ->
                                Text("• $c", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
                            }
                        }

                        if (analysis.structuralErrors.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text("Detected Structural Errors:", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = CoralRed)
                            analysis.structuralErrors.forEach { err ->
                                Text("⚠ $err", fontSize = 12.sp, color = CoralRed)
                            }
                            Spacer(Modifier.height(8.dp))
                            Button(
                                onClick = onOpenRepairLab,
                                colors = ButtonDefaults.buttonColors(containerColor = SelectionOrange),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Icon(Icons.Outlined.Build, contentDescription = "Repair", modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Send to File Repair Lab", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }

                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = analysis.neutralAdvisory,
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                }
            }
        }

        // Signature-Based Stream Carving Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Signature-Based Byte Stream Carver",
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = "Scans accessible container/blob/disk-image streams for embedded JPEG, PNG, and PDF headers & trailers.",
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        }
                        Button(
                            onClick = onRunCarver,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("run_stream_carver_btn")
                        ) {
                            Text("Carve Stream", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (carvedStreams.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = "Carved Embedded Streams (${carvedStreams.size}):",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = PrimaryGreen
                        )
                        Spacer(Modifier.height(6.dp))
                        carvedStreams.forEach { cs ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFFF8FAFC))
                                    .padding(10.dp)
                            ) {
                                Text(
                                    text = "#${cs.index} • ${cs.format} (${formatSize(cs.lengthBytes)}) • [${cs.classification.code}]",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Offsets: 0x${cs.startOffset.toString(16)} .. 0x${cs.endOffsetExclusive.toString(16)} | Validation: ${cs.validationSummary}",
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary
                                )
                                if (cs.sha256 != null) {
                                    Text(
                                        text = "SHA-256: ${cs.sha256}",
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = PrimaryGreen
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 2: SQLITE FORENSICS LAB (Section 5.H)
// ============================================================================

@Composable
private fun SqliteForensicsTab(
    report: SqliteForensicReport?,
    onOpenSafDb: () -> Unit,
    onLoadDiagnosticFixture: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "SQLite Database & Unallocated Page Inspector",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Inspects 100-byte SQLite 3 headers, PRAGMA integrity_check, sqlite_master schemas, WAL/journal presence, and B-tree leaf page unallocated/freeblock deleted record remnants.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = onOpenSafDb,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(Icons.Outlined.Storage, contentDescription = "Select SQLite DB", modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Select .db / .sqlite (SAF)", fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = onLoadDiagnosticFixture,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("load_sqlite_fixture_btn")
                        ) {
                            Text("Load Test DB with Deleted Row", fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        if (report != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Database Header & Integrity: ${report.dbName}",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = PrimaryGreen
                        )
                        Spacer(Modifier.height(6.dp))
                        LabKvRow("Valid SQLite 3", if (report.isValidSqliteHeader) "YES (${report.sqliteVersionString})" else "NO")
                        LabKvRow("SHA-256", report.sha256, mono = true)
                        LabKvRow("Page Size & Count", "${report.pageSizeBytes} bytes × ${report.totalPagesInHeader} pages (${formatSize(report.fileSize)})")
                        LabKvRow("Text Encoding", report.textEncoding)
                        LabKvRow("Freelist Pages", "${report.freelistPageCount} (Trunk page: ${report.freelistTrunkPage})")
                        LabKvRow("Change Counter", "${report.fileChangeCounter}")
                        LabKvRow("Integrity Check", report.integrityCheckResult)
                        LabKvRow(
                            "WAL / Journal",
                            "WAL: ${if (report.walFilePresent) "Present (${formatSize(report.walFileSizeBytes)})" else "Absent"} | Journal: ${if (report.journalFilePresent) "Present" else "Absent"}"
                        )

                        if (report.tables.isNotEmpty()) {
                            Spacer(Modifier.height(10.dp))
                            Text("Tables & Live Records (${report.tables.size}):", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            report.tables.forEach { tbl ->
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp)
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(Color(0xFFF8FAFC))
                                        .padding(10.dp)
                                ) {
                                    Text(
                                        text = "${tbl.name} (${tbl.liveRowCount} live rows)",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp,
                                        color = TextPrimary
                                    )
                                    if (tbl.sql.isNotBlank()) {
                                        Text(
                                            text = tbl.sql,
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = TextSecondary
                                        )
                                    }
                                    tbl.sampleRows.forEachIndexed { idx, row ->
                                        Text(
                                            text = "Row #${idx + 1}: ${row.entries.joinToString(", ") { "${it.key}=${it.value}" }}",
                                            fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = PrimaryGreen
                                        )
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        Text(
                            text = "Unallocated B-Tree Page & Freeblock Remnants (${report.unallocatedRemnants.size}):",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = SelectionOrange
                        )
                        if (report.unallocatedRemnants.isEmpty()) {
                            Text(
                                text = "No unallocated deleted-record ASCII strings detected in inspected B-tree leaf pages.",
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        } else {
                            report.unallocatedRemnants.forEach { rem ->
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp)
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(SelectionOrange.copy(alpha = 0.08f))
                                        .padding(10.dp)
                                ) {
                                    Text(
                                        text = "Page #${rem.pageNumber} @ 0x${rem.byteOffset.toString(16)} (${rem.sourceRegion})",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp,
                                        color = SelectionOrange
                                    )
                                    Text(
                                        text = "Extracted Remnants: ${rem.extractedAsciiStrings.joinToString(" | ")}",
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = TextPrimary
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 3: ARCHIVE FORENSICS LAB (Section 5.G)
// ============================================================================

@Composable
private fun ArchiveForensicsTab(
    report: ArchiveForensicReport?,
    onOpenSafArchive: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Archive & Container Forensics (ZIP / APK / OOXML)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = "Lists entries, calculates per-entry SHA-256 & CRC32 in memory, checks EOCD, and flags path traversal ('../') without executing or extracting files.",
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Button(
                            onClick = onOpenSafArchive,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Select Archive", fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        if (report != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "${report.archiveName} (${formatSize(report.fileSize)})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = PrimaryGreen
                        )
                        LabKvRow("Archive SHA-256", report.sha256, mono = true)
                        LabKvRow("EOCD Present", if (report.hasEndOfCentralDirectory) "Yes (Valid Central Directory)" else "No (Truncated)")
                        LabKvRow("Total Entries", "${report.totalEntries}")

                        if (report.structuralAnomalies.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            Text("Structural Anomalies:", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = CoralRed)
                            report.structuralAnomalies.forEach { a ->
                                Text("⚠ $a", fontSize = 11.sp, color = CoralRed)
                            }
                        }

                        Spacer(Modifier.height(8.dp))
                        Text("Inspected Entries (${report.entries.size}):", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        report.entries.take(50).forEach { e ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 3.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(Color(0xFFF8FAFC))
                                    .padding(8.dp)
                            ) {
                                Text(
                                    text = "#${e.index} ${e.entryName} (${e.compressionMethod})",
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (e.hasPathTraversalAnomaly) CoralRed else TextPrimary
                                )
                                Text(
                                    text = "Size: ${formatSize(e.compressedSize)} -> ${formatSize(e.uncompressedSize)} | CRC32: ${e.crc32Hex}",
                                    fontSize = 10.sp,
                                    color = TextSecondary
                                )
                                if (e.sha256 != null) {
                                    Text(
                                        text = "Entry SHA-256: ${e.sha256}",
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = PrimaryGreen
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(report.safetyNote, fontSize = 11.sp, color = TextSecondary)
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 4: MULTI-STRATEGY DUPLICATE DETECTION & FILE RELATIONSHIPS (Section 5.E & 5.F)
// ============================================================================

@Composable
private fun DuplicatesAndRelationshipsTab(
    clusters: List<MultiStrategyDuplicateCluster>,
    relationships: List<FileRelationshipEdge>,
    onRefresh: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Multi-Strategy Duplicate Detection (${clusters.size} clusters)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = "Distinguishes Exact SHA-256 Byte Duplicates, Visually Similar Images (64-bit dHash), and Same-Sized Unproven Files. Never auto-deletes files.",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                        OutlinedButton(onClick = onRefresh, shape = RoundedCornerShape(10.dp)) {
                            Text("Re-Scan", fontSize = 11.sp)
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                    if (clusters.isEmpty()) {
                        Text(
                            text = "No duplicate or same-sized clusters detected in the current evidence set.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    } else {
                        clusters.forEach { c ->
                            val accent = when (c.strategy) {
                                DuplicateMatchStrategy.EXACT_SHA256 -> AccentEmerald
                                DuplicateMatchStrategy.PERCEPTUAL_SIMILAR_IMAGE -> AccentCyan
                                DuplicateMatchStrategy.SAME_SIZE_UNPROVEN -> SelectionOrange
                            }
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(accent.copy(alpha = 0.08f))
                                    .padding(10.dp)
                            ) {
                                Text(
                                    text = "${c.clusterId} • ${c.strategy.label}",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp,
                                    color = accent
                                )
                                Text(
                                    text = c.signatureOrSizeKey,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Files: ${c.files.joinToString(", ") { "${it.name} (${formatSize(it.sizeBytes)})" }}",
                                    fontSize = 11.sp,
                                    color = TextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "File Relationship Explorer (${relationships.size} links)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Text(
                        text = "Every relationship shows its explicit evidentiary basis and distinguishes proven facts from correlated attributes.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(8.dp))
                    if (relationships.isEmpty()) {
                        Text("No cross-file relationships identified yet.", fontSize = 12.sp, color = TextSecondary)
                    } else {
                        relationships.take(40).forEach { rel ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFFF8FAFC))
                                    .padding(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "${rel.sourceFileName} ↔ ${rel.targetFileName}",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp,
                                        color = PrimaryGreen
                                    )
                                    Text(
                                        text = if (rel.relationshipType.isProvenFact) "PROVEN FACT" else "CORRELATED",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (rel.relationshipType.isProvenFact) AccentEmerald else SelectionOrange
                                    )
                                }
                                Text(
                                    text = "${rel.relationshipType.label}: ${rel.evidenceBasis}",
                                    fontSize = 11.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Note: ${rel.confidenceNote}",
                                    fontSize = 10.sp,
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

// ============================================================================
// TAB 5: MEDIA THUMBNAIL EXPLORER (Section 5.I)
// ============================================================================

@Composable
private fun ThumbnailExplorerTab(
    items: List<ThumbnailForensicItem>,
    onInspectFile: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Accessible Media Thumbnail & Cache Explorer (${items.size})",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Text(
                        text = "Displays thumbnails from accessible .thumbnails directories and carved .thumbdata streams, with SHA-256 digests, dimensions, and parent-media matching.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                }
            }
        }

        items(items, key = { it.thumbnailPath }) { item ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onInspectFile(item.thumbnailPath) },
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = item.thumbnailName,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = item.recoveryClassification.code,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            color = AccentEmerald
                        )
                    }
                    LabKvRow("Dimensions & Size", "${item.width} × ${item.height} px • ${formatSize(item.sizeBytes)}")
                    LabKvRow("Source Origin", item.sourceOrigin)
                    LabKvRow("SHA-256", item.sha256, mono = true)
                    LabKvRow("Parent Media Match", item.relationshipBasis)
                    Text(
                        text = item.limitationsNote,
                        fontSize = 10.sp,
                        color = TextSecondary
                    )
                }
            }
        }
    }
}

// ============================================================================
// SCREEN 2: NON-DESTRUCTIVE FILE REPAIR LAB (Section 6)
// ============================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileRepairLabScreen(nav: NavController, vm: AppViewModel) {
    BackHandler { nav.popBackStack() }
    val context = LocalContext.current

    val selectedFile by vm.selectedLabFile.collectAsState()
    val structBefore by vm.activeStructureAnalysis.collectAsState()
    val lastRepair by vm.lastRepairReport.collectAsState()
    val repairHistory by vm.repairHistory.collectAsState()

    val safLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            vm.importSafUriForForensics(uri)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("File Repair Lab", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = TextPrimary)
                        Text("Non-Destructive Header & Container Reconstruction", fontSize = 11.sp, color = TextSecondary)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { nav.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                actions = {
                    OutlinedButton(
                        onClick = { safLauncher.launch(arrayOf("*/*")) },
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text("Pick File (SAF)", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = PrimaryGreen)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        containerColor = SoftSurfaceBg
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .windowInsetsPadding(WindowInsets.navigationBars),
            contentPadding = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = DarkCardBg)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "STRICT NON-DESTRUCTIVE REPAIR RULES",
                            color = AccentCyan,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 11.sp
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "1. Original evidence is never overwritten.\n2. Repaired output is saved as a separate file with before & after SHA-256 hashes.\n3. Missing payload bytes are never fabricated.",
                            color = Color(0xFFE2E8F0),
                            fontSize = 12.sp
                        )
                    }
                }
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Selected Artifact Diagnosis",
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(6.dp))
                        if (selectedFile == null || structBefore == null) {
                            Text(
                                text = "Select a file using 'Pick File (SAF)' above or from the Forensics Lab.",
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        } else {
                            LabKvRow("Target File", "${selectedFile!!.name} (${formatSize(selectedFile!!.length())})")
                            LabKvRow("Detected Format", structBefore!!.detectedFormat)
                            LabKvRow("Header Status", structBefore!!.headerDetail)
                            LabKvRow("Footer Status", structBefore!!.footerDetail)
                            LabKvRow("Classification", structBefore!!.recoveryClassification.code)

                            Spacer(Modifier.height(10.dp))
                            Button(
                                onClick = {
                                    vm.runNonDestructiveFileRepair(selectedFile)
                                    Toast.makeText(context, "Executed non-destructive repair analysis", Toast.LENGTH_SHORT).show()
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("execute_file_repair_btn")
                            ) {
                                Icon(Icons.Outlined.Build, contentDescription = "Repair", modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Run Non-Destructive Repair to New Copy", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            if (lastRepair != null) {
                val rep = lastRepair!!
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text(
                                text = "Before & After Repair Report: ${rep.repairOutcome.label}",
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = PrimaryGreen
                            )
                            Spacer(Modifier.height(6.dp))
                            LabKvRow("Repair Method", rep.repairMethodApplied, mono = true)
                            LabKvRow("Original SHA-256", rep.originalSha256, mono = true)
                            LabKvRow("Original Size", formatSize(rep.originalSize))
                            if (rep.repairedOutputFile != null) {
                                LabKvRow("Repaired Copy Path", rep.repairedOutputFile.absolutePath, mono = true)
                                LabKvRow("Repaired SHA-256", rep.repairedSha256 ?: "n/a", mono = true)
                                LabKvRow("Repaired Size", formatSize(rep.repairedSize ?: 0L))
                                LabKvRow(
                                    "After Validation",
                                    "${rep.validationAfter?.recoveryClassification?.code ?: "N/A"} — ${rep.validationAfter?.footerDetail ?: ""}"
                                )
                            }
                            if (rep.warnings.isNotEmpty()) {
                                Spacer(Modifier.height(6.dp))
                                rep.warnings.forEach { w ->
                                    Text("• $w", fontSize = 11.sp, color = SelectionOrange)
                                }
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(rep.honestDisclosure, fontSize = 11.sp, color = TextSecondary)
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// SCREEN 3: INVESTIGATION CASE MANAGER & CHAIN OF CUSTODY (Section 7, 8 & 12)
// ============================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CaseManagerScreen(nav: NavController, vm: AppViewModel) {
    BackHandler { nav.popBackStack() }
    val context = LocalContext.current

    val cases by vm.investigationCases.collectAsState()
    val activeCase by vm.activeInvestigationCase.collectAsState()
    val custodyLog by vm.custodyLog.collectAsState()
    val custodyVerif by vm.custodyVerification.collectAsState()
    val comparison by vm.evidenceComparison.collectAsState()
    val scanCheckpoint by vm.lastScanCheckpoint.collectAsState()
    val scanHistory by vm.scanHistory.collectAsState()

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Cases & Evidence", "Evidence Comparison", "Chain of Custody Log", "Scan Checkpoints")

    var newCaseTitle by remember { mutableStateOf("") }
    var newCaseInvestigator by remember { mutableStateOf("") }
    var newCaseDesc by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Investigation Case Manager", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = TextPrimary)
                        Text(
                            text = "Active: ${activeCase?.caseId ?: "None"} (${activeCase?.evidenceItems?.size ?: 0} evidence items)",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { nav.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                actions = {
                    OutlinedButton(
                        onClick = {
                            vm.exportCaseBackupArchive { file ->
                                Toast.makeText(context, "Case backup saved: ${file.name}", Toast.LENGTH_SHORT).show()
                                ForensicReportExporter.shareReportFile(context, file, "application/json")
                            }
                        },
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text("Backup Cases", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = PrimaryGreen)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        containerColor = SoftSurfaceBg
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            ScrollableTabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color.White,
                contentColor = PrimaryGreen,
                edgePadding = 12.dp
            ) {
                tabs.forEachIndexed { idx, title ->
                    Tab(
                        selected = selectedTab == idx,
                        onClick = { selectedTab = idx },
                        modifier = Modifier.testTag("case_mgr_tab_$idx"),
                        text = {
                            Text(
                                text = title,
                                fontWeight = if (selectedTab == idx) FontWeight.Bold else FontWeight.Medium,
                                fontSize = 13.sp
                            )
                        }
                    )
                }
            }

            when (selectedTab) {
                0 -> LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // Create / Switch Case Card
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White)
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Text("Create or Switch Investigation Case", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                                Spacer(Modifier.height(6.dp))
                                if (cases.size > 1) {
                                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        items(cases, key = { it.caseId }) { c ->
                                            FilterChip(
                                                selected = c.caseId == activeCase?.caseId,
                                                onClick = { vm.switchActiveCase(c.caseId) },
                                                label = { Text("${c.caseId}: ${c.title}", fontSize = 11.sp) }
                                            )
                                        }
                                    }
                                    Spacer(Modifier.height(8.dp))
                                }
                                OutlinedTextField(
                                    value = newCaseTitle,
                                    onValueChange = { newCaseTitle = it },
                                    label = { Text("New Case Title", fontSize = 11.sp) },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth().testTag("new_case_title_input")
                                )
                                Spacer(Modifier.height(6.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedTextField(
                                        value = newCaseInvestigator,
                                        onValueChange = { newCaseInvestigator = it },
                                        label = { Text("Analyst / Investigator", fontSize = 11.sp) },
                                        singleLine = true,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Button(
                                        onClick = {
                                            if (newCaseTitle.isNotBlank()) {
                                                vm.createNewInvestigationCase(newCaseTitle, newCaseInvestigator, newCaseDesc)
                                                newCaseTitle = ""
                                                Toast.makeText(context, "Created new investigation case", Toast.LENGTH_SHORT).show()
                                            }
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                                        shape = RoundedCornerShape(10.dp),
                                        modifier = Modifier.align(Alignment.CenterVertically).testTag("create_case_btn")
                                    ) {
                                        Text("Create Case", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }

                    // Active Case Evidence List with Distinct Timestamps & Annotations
                    val items = activeCase?.evidenceItems ?: emptyList()
                    items(items, key = { it.evidenceId }) { ev ->
                        CaseEvidenceCard(
                            item = ev,
                            onToggleBookmark = { vm.toggleBookmarkEvidence(ev.evidenceId) },
                            onSaveAnnotation = { notes, tags ->
                                vm.saveEvidenceNotesAndTags(ev.evidenceId, notes, tags)
                                Toast.makeText(context, "Saved analyst notes & tags to Chain of Custody", Toast.LENGTH_SHORT).show()
                            },
                            onRemove = { vm.removeEvidenceFromActiveCase(ev.evidenceId) }
                        )
                    }
                }

                1 -> EvidenceComparisonTab(
                    evidenceItems = activeCase?.evidenceItems ?: emptyList(),
                    comparison = comparison,
                    onCompare = { leftId, rightId -> vm.compareTwoCaseEvidenceItems(leftId, rightId) }
                )

                2 -> ChainOfCustodyTab(
                    entries = custodyLog,
                    verification = custodyVerif,
                    onVerifyNow = { vm.verifyChainOfCustodyNow() }
                )

                3 -> ScanCheckpointsAndHistoryTab(
                    checkpoint = scanCheckpoint,
                    history = scanHistory
                )
            }
        }
    }
}

@Composable
private fun CaseEvidenceCard(
    item: CaseEvidenceItem,
    onToggleBookmark: () -> Unit,
    onSaveAnnotation: (String, String) -> Unit,
    onRemove: () -> Unit
) {
    var notesText by remember(item.evidenceId, item.analystNotes) { mutableStateOf(item.analystNotes) }
    var tagsText by remember(item.evidenceId, item.tags) { mutableStateOf(item.tags.joinToString(", ")) }
    var showAnnotate by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    IconButton(onClick = onToggleBookmark) {
                        Icon(
                            imageVector = if (item.bookmarked) Icons.Outlined.Bookmark else Icons.Outlined.BookmarkBorder,
                            contentDescription = "Bookmark Evidence",
                            tint = if (item.bookmarked) SelectionOrange else TextSecondary
                        )
                    }
                    Column {
                        Text(
                            text = "${item.evidenceId} • ${item.currentFileName}",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = "${item.detectedFormat} • ${formatSize(item.fileSize)} • [${item.recoveryClassification.code}]",
                            fontSize = 11.sp,
                            color = PrimaryGreen,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
                OutlinedButton(
                    onClick = { showAnnotate = !showAnnotate },
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(if (showAnnotate) "Close" else "Annotate", fontSize = 11.sp)
                }
            }

            LabKvRow("SHA-256", item.sha256, mono = true)
            LabKvRow("Source Status", "${item.sourceAccessibilityStatus} (${item.recoveryMethod})")
            // 5 Explicitly Distinguished Timestamps (Section 7)
            LabKvRow("1. Filesystem Time", item.originalFileTimestampIso ?: "unavailable (not invented)")
            LabKvRow("2. Metadata Time", item.metadataTimestampIso ?: "unavailable (not present in header)")
            LabKvRow("3. Scan Time", item.scanTimestampIso ?: "n/a")
            LabKvRow("4. Recovery Time", item.recoveryTimestampIso ?: "n/a (not a restored copy)")
            LabKvRow("5. Case Added Time", item.appAddedTimestampIso)

            if (item.tags.isNotEmpty()) {
                LabKvRow("Analyst Tags", item.tags.joinToString(", "))
            }
            if (item.analystNotes.isNotBlank()) {
                LabKvRow("Analyst Notes", item.analystNotes)
            }

            AnimatedVisibility(visible = showAnnotate) {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    OutlinedTextField(
                        value = tagsText,
                        onValueChange = { tagsText = it },
                        label = { Text("Comma-Separated Tags (e.g. key-evidence, financial, verified)", fontSize = 11.sp) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = notesText,
                        onValueChange = { notesText = it },
                        label = { Text("Analyst Observations & Case Notes", fontSize = 11.sp) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        OutlinedButton(onClick = onRemove) {
                            Text("Remove from Case", fontSize = 11.sp, color = CoralRed)
                        }
                        Button(
                            onClick = {
                                onSaveAnnotation(notesText, tagsText)
                                showAnnotate = false
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen)
                        ) {
                            Text("Save Annotation", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EvidenceComparisonTab(
    evidenceItems: List<CaseEvidenceItem>,
    comparison: EvidenceComparisonResult?,
    onCompare: (String, String) -> Unit
) {
    var leftId by remember(evidenceItems) { mutableStateOf(evidenceItems.firstOrNull()?.evidenceId ?: "") }
    var rightId by remember(evidenceItems) { mutableStateOf(evidenceItems.getOrNull(1)?.evidenceId ?: evidenceItems.firstOrNull()?.evidenceId ?: "") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Side-by-Side Evidence & Metadata Comparator", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(Modifier.height(6.dp))
                    Text("Select Left Artifact:", fontSize = 11.sp, color = TextSecondary)
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(evidenceItems, key = { "L_${it.evidenceId}" }) { ev ->
                            FilterChip(
                                selected = leftId == ev.evidenceId,
                                onClick = { leftId = ev.evidenceId },
                                label = { Text("${ev.evidenceId} (${ev.currentFileName})", fontSize = 11.sp) }
                            )
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    Text("Select Right Artifact:", fontSize = 11.sp, color = TextSecondary)
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(evidenceItems, key = { "R_${it.evidenceId}" }) { ev ->
                            FilterChip(
                                selected = rightId == ev.evidenceId,
                                onClick = { rightId = ev.evidenceId },
                                label = { Text("${ev.evidenceId} (${ev.currentFileName})", fontSize = 11.sp) }
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = { onCompare(leftId, rightId) },
                        enabled = leftId.isNotBlank() && rightId.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Outlined.CompareArrows, contentDescription = "Compare", modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Compare Selected Evidence", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        if (comparison != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "${comparison.leftEvidence.evidenceId} vs ${comparison.rightEvidence.evidenceId}",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = PrimaryGreen
                        )
                        LabKvRow("SHA-256 Match", if (comparison.exactByteMatch) "IDENTICAL BYTES (Exact Match)" else "DIFFERENT CONTENT")
                        LabKvRow("Size Difference", "${comparison.sizeDifferenceBytes} bytes")
                        LabKvRow("Recovery Methods", comparison.recoveryMethodComparison)
                        LabKvRow("Classifications", comparison.classificationComparison)

                        if (comparison.timestampDifferences.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            Text("Timestamp Comparison:", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            comparison.timestampDifferences.forEach { t ->
                                Text("• $t", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                        if (comparison.differingMetadataEntries.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            Text("Differing Metadata Fields:", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            comparison.differingMetadataEntries.forEach { (k, lv, rv) ->
                                Text("• $k: Left='$lv' | Right='$rv'", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChainOfCustodyTab(
    entries: List<ChainOfCustodyEntry>,
    verification: ChainIntegrityVerification?,
    onVerifyNow: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "SHA-256 Hash-Linked Chain of Custody",
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = verification?.summaryMessage ?: "Click Verify Chain to validate all hash links.",
                                fontSize = 12.sp,
                                color = if (verification?.isChainIntact == false) CoralRed else AccentEmerald,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        Button(
                            onClick = onVerifyNow,
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.testTag("verify_custody_chain_btn")
                        ) {
                            Text("Verify Chain", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = verification?.transparencyNotice
                            ?: "Transparency note: A local hash-linked log detects accidental or post-hoc file edits, but is not tamper-proof if an attacker controls the device/application.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                }
            }
        }

        items(entries.reversed(), key = { it.sequenceNumber }) { entry ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "#${entry.sequenceNumber} • ${entry.actionType.label}",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            color = PrimaryGreen
                        )
                        Text(
                            text = entry.timestampUtc,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = TextSecondary
                        )
                    }
                    Text(
                        text = entry.details,
                        fontSize = 12.sp,
                        color = TextPrimary,
                        modifier = Modifier.padding(vertical = 3.dp)
                    )
                    Text(
                        text = "Prev: ${entry.previousEntryHash.take(16)}… → Entry SHA-256: ${entry.entrySha256.take(16)}…",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextSecondary
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanCheckpointsAndHistoryTab(
    checkpoint: com.clone.filesrecovery.forensics.ScanCheckpoint?,
    history: List<com.clone.filesrecovery.forensics.ScanHistoryEntry>
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Latest Scan Checkpoint", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(Modifier.height(6.dp))
                    if (checkpoint == null) {
                        Text("No scan checkpoint recorded yet.", fontSize = 12.sp, color = TextSecondary)
                    } else {
                        LabKvRow("Session ID", checkpoint.checkpointId, mono = true)
                        LabKvRow("Category & Mode", "${checkpoint.categoryName} (${checkpoint.operatingMode})")
                        LabKvRow("Status", checkpoint.status)
                        LabKvRow("Progress", "${checkpoint.discoveredFilesCount} files discovered across ${checkpoint.scannedDirectoriesCount} paths")
                        LabKvRow("Last Path", checkpoint.lastProcessedPath.ifBlank { "n/a" }, mono = true)
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Scan Execution History (${history.size})", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(Modifier.height(6.dp))
                    if (history.isEmpty()) {
                        Text("No completed scan sessions recorded yet.", fontSize = 12.sp, color = TextSecondary)
                    } else {
                        history.forEach { h ->
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(Color(0xFFF8FAFC))
                                    .padding(10.dp)
                            ) {
                                Text(
                                    text = "${h.sessionId} • ${h.categoryName} [${h.status}]",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp,
                                    color = PrimaryGreen
                                )
                                Text(
                                    text = "Found ${h.filesDiscovered} files (${formatSize(h.bytesEvaluated)}) in ${h.durationMs} ms • Mode: ${h.operatingMode}",
                                    fontSize = 11.sp,
                                    color = TextPrimary
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LabKvRow(label: String, value: String, mono: Boolean = false) {
    if (value.length > 28) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 3.dp)
        ) {
            Text(
                text = "$label:",
                fontSize = 11.sp,
                color = TextSecondary,
                fontWeight = FontWeight.Medium
            )
            Spacer(Modifier.height(2.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(6.dp))
                    .background(Color(0xFFF1F5F9))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = value,
                    fontSize = 10.sp,
                    color = TextPrimary,
                    fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
                    lineHeight = 14.sp
                )
            }
        }
    } else {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "$label:",
                fontSize = 11.sp,
                color = TextSecondary,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.width(130.dp)
            )
            Text(
                text = value,
                fontSize = 11.sp,
                color = TextPrimary,
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
                modifier = Modifier.weight(1f)
            )
        }
    }
}
