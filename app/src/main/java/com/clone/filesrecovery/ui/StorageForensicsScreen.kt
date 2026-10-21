package com.clone.filesrecovery.ui

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.forensics.EncryptionFinding
import com.clone.filesrecovery.forensics.ForensicReportExporter
import com.clone.filesrecovery.forensics.HiddenArtifactCategory
import com.clone.filesrecovery.forensics.HiddenArtifactFinding
import com.clone.filesrecovery.forensics.InaccessibleStorageArea
import com.clone.filesrecovery.forensics.RecognizedCategoryStat
import com.clone.filesrecovery.forensics.SignatureMismatchFinding
import com.clone.filesrecovery.forensics.StorageForensicsReport
import com.clone.filesrecovery.forensics.UnclassifiedFileFinding
import com.clone.filesrecovery.forensics.formatBytesHuman
import java.io.File
import java.util.Locale

@Composable
fun StorageForensicsScreen(nav: NavController, vm: AppViewModel) {
    BackHandler { nav.popBackStack() }
    val context = LocalContext.current
    val report by vm.storageForensicsReport.collectAsState()
    val isScanning by vm.isScanningStorageForensics.collectAsState()
    val progressText by vm.storageForensicsProgressText.collectAsState()
    val lastExport by vm.lastStorageForensicsExport.collectAsState()

    var selectedTab by remember { mutableIntStateOf(0) }
    var hiddenFilter by remember { mutableStateOf<HiddenArtifactCategory?>(null) }

    val safTreeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            vm.runStorageForensicsWithSafTree(uri)
        }
    }

    LaunchedEffect(Unit) {
        if (report == null && !isScanning) {
            vm.runStorageForensicsScan()
        }
    }

    SimpleScaffold(
        title = "Storage Forensics Intelligence",
        onBack = { nav.popBackStack() },
        actions = {
            Button(
                onClick = { vm.runStorageForensicsScan() },
                enabled = !isScanning,
                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                modifier = Modifier
                    .padding(end = 8.dp)
                    .testTag("btn_run_storage_intelligence")
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = "Rescan", modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(if (isScanning) "Scanning…" else "Rescan", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
    ) { mod ->
        Column(modifier = mod.fillMaxSize()) {
            // Top Action & Progress Strip
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "DETERMINISTIC ON-DEVICE STORAGE INTELLIGENCE",
                                color = AccentCyan,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = report?.let {
                                    "Scanned ${it.filesActuallyScanned} files (${formatBytesHuman(it.bytesActuallyScanned)}) • Mode: ${it.operatingMode}"
                                } ?: "Inspecting accessible storage scope, hidden markers & encryption headers…",
                                color = Color.White,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    if (isScanning) {
                        Spacer(Modifier.height(10.dp))
                        LinearProgressIndicator(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(6.dp)
                                .clip(RoundedCornerShape(50)),
                            color = AccentCyan,
                            trackColor = Color(0xFF1E293B)
                        )
                        if (progressText.isNotBlank()) {
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = progressText,
                                color = Color(0xFF94A3B8),
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                maxLines = 1
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { safTreeLauncher.launch(null) },
                            enabled = !isScanning,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_saf_tree_inspect")
                        ) {
                            Icon(Icons.Filled.FolderOpen, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Authorize Folder (SAF)", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                        }

                        Button(
                            onClick = {
                                vm.exportStorageForensicsReport { exported ->
                                    Toast.makeText(
                                        context,
                                        "Exported JSON & MD (${exported.jsonFile.name})",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            },
                            enabled = report != null && !isScanning,
                            colors = ButtonDefaults.buttonColors(containerColor = AccentEmerald),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_export_storage_intelligence")
                        ) {
                            Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Export JSON/MD", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (lastExport != null) {
                        Spacer(Modifier.height(8.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color(0xFF1E293B))
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Exported: ${lastExport!!.jsonFile.name}",
                                    color = AccentEmerald,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "SHA-256: ${lastExport!!.jsonSha256.take(24)}…",
                                    color = Color(0xFFCBD5E1),
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                            Text(
                                text = "SHARE",
                                color = AccentCyan,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.ExtraBold,
                                modifier = Modifier
                                    .clickable {
                                        ForensicReportExporter.shareReportFile(
                                            context,
                                            lastExport!!.markdownFile,
                                            "text/markdown"
                                        )
                                    }
                                    .padding(6.dp)
                            )
                        }
                    }
                }
            }

            val tabs = listOf(
                "Overview & Coverage",
                "Categories & Unknown (${report?.totalUnclassifiedFiles ?: 0})",
                "Hidden & .nomedia (${report?.hiddenFindings?.size ?: 0})",
                "Encryption & Mismatches (${(report?.totalConfirmedEncryptedFiles ?: 0) + (report?.totalPotentialEncryptedFiles ?: 0) + (report?.totalSignatureMismatches ?: 0)})",
                "Inaccessible Scope (${report?.inaccessibleAreas?.size ?: 0})"
            )

            ScrollableTabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color.White,
                edgePadding = 12.dp
            ) {
                tabs.forEachIndexed { idx, title ->
                    Tab(
                        selected = selectedTab == idx,
                        onClick = { selectedTab = idx },
                        text = {
                            Text(
                                text = title,
                                fontSize = 12.sp,
                                fontWeight = if (selectedTab == idx) FontWeight.ExtraBold else FontWeight.Medium
                            )
                        },
                        modifier = Modifier.testTag("storage_forensics_tab_$idx")
                    )
                }
            }

            val currentReport = report
            if (currentReport == null) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (isScanning) "Running deterministic storage forensics scan…" else "Tap Rescan to inspect device storage.",
                        color = TextSecondary,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            } else {
                when (selectedTab) {
                    0 -> OverviewAndCoverageTab(
                        report = currentReport,
                        onNavigateTab = { selectedTab = it },
                        onOpenAppsStorage = { nav.navigate("storage") }
                    )
                    1 -> CategoriesAndUnknownTab(
                        report = currentReport,
                        onInspectInHexLab = { path ->
                            val f = File(path)
                            if (f.exists()) {
                                vm.selectFileForAdvancedLab(f)
                                nav.navigate("advanced_forensics_lab")
                            }
                        }
                    )
                    2 -> HiddenArtifactsTab(
                        report = currentReport,
                        selectedFilter = hiddenFilter,
                        onSelectFilter = { hiddenFilter = it },
                        onInspectInHexLab = { path ->
                            val f = File(path)
                            if (f.exists() && f.isFile) {
                                vm.selectFileForAdvancedLab(f)
                                nav.navigate("advanced_forensics_lab")
                            }
                        }
                    )
                    3 -> EncryptionAndMismatchesTab(
                        report = currentReport,
                        onInspectInHexLab = { path ->
                            val f = File(path)
                            if (f.exists()) {
                                vm.selectFileForAdvancedLab(f)
                                nav.navigate("advanced_forensics_lab")
                            }
                        }
                    )
                    4 -> InaccessibleScopeTab(report = currentReport)
                }
            }
        }
    }
}

@Composable
private fun OverviewAndCoverageTab(
    report: StorageForensicsReport,
    onNavigateTab: (Int) -> Unit,
    onOpenAppsStorage: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 1. Whole-Device vs Accessible Scope Comparison Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                        .padding(16.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Storage, contentDescription = null, tint = PrimaryGreen)
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "Whole-Device vs. Accessible Scope",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 16.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = "Distinguishes kernel StatFs partition totals from DeepVault's authorized inspection scope",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(Modifier.height(14.dp))

                    // Whole-device section
                    Text(
                        text = "WHOLE-DEVICE STORAGE (StatFs Partition)",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = PrimaryGreen
                    )
                    Spacer(Modifier.height(6.dp))
                    MetricRow("Total Device Capacity", formatBytesHuman(report.totalDeviceBytes), "${report.totalDeviceBytes} B")
                    MetricRow("Used Device Storage", formatBytesHuman(report.usedDeviceBytes), "Includes OS, system & private app sandboxes")
                    MetricRow("Available Free Storage", formatBytesHuman(report.availableDeviceBytes), "Unallocated / free blocks")

                    Spacer(Modifier.height(12.dp))

                    // Accessible & Scanned section
                    Text(
                        text = "DEEPVAULT ACCESSIBLE & SCANNED SCOPE",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = AccentEmerald
                    )
                    Spacer(Modifier.height(6.dp))
                    MetricRow("Storage Accessible to DeepVault", formatBytesHuman(report.accessibleStorageBytes), report.storagePermissionStatus)
                    MetricRow("Bytes Actually Scanned", formatBytesHuman(report.bytesActuallyScanned), "Verified readable files")
                    MetricRow("Files & Folders Scanned", "${report.filesActuallyScanned} files", "${report.directoriesTraversed} directories traversed")
                    MetricRow(
                        label = "Uninspected OS / Sandboxed Storage",
                        value = formatBytesHuman(report.uninspectedSystemAndSandboxedBytes),
                        sub = "Outside user-space scope (NOT assumed encrypted)"
                    )
                }
            }
        }

        // 2. Scan Coverage & Calculation Method Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                        .padding(16.dp)
                ) {
                    Text(
                        text = "Scan Coverage & Calculation Method",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CoveragePill(
                            modifier = Modifier.weight(1f),
                            title = "Accessible Scope Coverage",
                            percent = report.accessibleCoveragePercent,
                            subtitle = "Scanned / Accessible Bytes",
                            color = AccentEmerald
                        )
                        CoveragePill(
                            modifier = Modifier.weight(1f),
                            title = "Whole-Device Share",
                            percent = report.wholeDeviceInspectedPercent,
                            subtitle = "Scanned / Total Capacity",
                            color = PrimaryGreen
                        )
                    }

                    Spacer(Modifier.height(12.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(SoftSurfaceBg)
                            .padding(12.dp)
                    ) {
                        Column {
                            Text(
                                text = "Calculation Formula:",
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = report.coverageCalculationMethod,
                                fontSize = 11.sp,
                                color = TextSecondary,
                                fontFamily = FontFamily.Monospace
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = report.scopeDistinctionExplanation,
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                    }
                }
            }
        }

        // 3. Forensic Intelligence Summary Grid (Interactive cards jumping to each tab)
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SummaryStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Hidden & .nomedia",
                    primaryValue = "${report.hiddenFindings.size} found",
                    secondaryValue = "${report.nomediaFilesCount} .nomedia • ${report.dotDirectoriesCount} dot-dirs",
                    accentColor = SelectionOrange,
                    onClick = { onNavigateTab(2) }
                )
                SummaryStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Confirmed Encrypted",
                    primaryValue = "${report.totalConfirmedEncryptedFiles} files",
                    secondaryValue = "${formatBytesHuman(report.totalConfirmedEncryptedBytes)} header-verified",
                    accentColor = CoralRed,
                    onClick = { onNavigateTab(3) }
                )
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SummaryStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Potential High-Entropy",
                    primaryValue = "${report.totalPotentialEncryptedFiles} blobs",
                    secondaryValue = "${report.compressedMediaHighEntropyCount} media excluded",
                    accentColor = Color(0xFF7C3AED),
                    onClick = { onNavigateTab(3) }
                )
                SummaryStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Signature Mismatches",
                    primaryValue = "${report.totalSignatureMismatches} files",
                    secondaryValue = "${report.totalUnclassifiedFiles} unclassified files",
                    accentColor = PrimaryGreen,
                    onClick = { onNavigateTab(1) }
                )
            }
        }

        // 4. Scanned Root Paths & Installed Apps Link
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                        .padding(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Inspected Storage Roots (${report.scannedRootPaths.size})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = TextPrimary
                        )
                        OutlinedButton(
                            onClick = onOpenAppsStorage,
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Text("Installed Apps", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    report.scannedRootPaths.forEach { path ->
                        Text(
                            text = "• $path",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = TextSecondary
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CategoriesAndUnknownTab(
    report: StorageForensicsReport,
    onInspectInHexLab: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(
                text = "Recognized File Categories (${report.totalRecognizedFiles} files • ${formatBytesHuman(report.totalRecognizedBytes)})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
        }

        items(report.recognizedCategories, key = { it.categoryId }) { cat ->
            CategoryBreakdownRowCard(cat)
        }

        item {
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Unknown or Unclassified Accessible Files (${report.totalUnclassifiedFiles} files • ${formatBytesHuman(report.totalUnclassifiedBytes)})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
            Text(
                text = "Files whose extension and binary magic header do not match standard media, document, database, or package signatures.",
                fontSize = 11.sp,
                color = TextSecondary
            )
        }

        if (report.unclassifiedFindings.isEmpty()) {
            item {
                EmptyFindingCard("All scanned files matched recognized format signatures or text structures.")
            }
        } else {
            items(report.unclassifiedFindings, key = { it.path }) { item ->
                UnclassifiedFileCard(item = item, onInspectHex = { onInspectInHexLab(item.path) })
            }
        }
    }
}

@Composable
private fun HiddenArtifactsTab(
    report: StorageForensicsReport,
    selectedFilter: HiddenArtifactCategory?,
    onSelectFilter: (HiddenArtifactCategory?) -> Unit,
    onInspectInHexLab: (String) -> Unit
) {
    val filtered = remember(report.hiddenFindings, selectedFilter) {
        if (selectedFilter == null) report.hiddenFindings
        else report.hiddenFindings.filter { it.category == selectedFilter }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                        .padding(14.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.VisibilityOff, contentDescription = null, tint = SelectionOrange)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Hidden File & .nomedia Analysis",
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 15.sp,
                            color = TextPrimary
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "Identifies .nomedia markers, dot-prefixed files/folders, recycle bins, and unusual compound extensions without assuming every hidden artifact is malicious.",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        MiniBadgePill(".nomedia: ${report.nomediaFilesCount}")
                        MiniBadgePill("Dot Files: ${report.dotFilesCount}")
                        MiniBadgePill("Dot Dirs: ${report.dotDirectoriesCount}")
                        MiniBadgePill("Unusual: ${report.unusualNamingOrStructureCount}")
                    }
                }
            }
        }

        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = selectedFilter == null,
                    onClick = { onSelectFilter(null) },
                    label = { Text("All (${report.hiddenFindings.size})", fontSize = 11.sp) }
                )
                HiddenArtifactCategory.entries.forEach { cat ->
                    val count = report.hiddenFindings.count { it.category == cat }
                    FilterChip(
                        selected = selectedFilter == cat,
                        onClick = { onSelectFilter(if (selectedFilter == cat) null else cat) },
                        label = { Text("${cat.label} ($count)", fontSize = 11.sp) }
                    )
                }
            }
        }

        if (filtered.isEmpty()) {
            item {
                EmptyFindingCard("No hidden files or .nomedia markers found for this filter.")
            }
        } else {
            items(filtered, key = { it.path }) { finding ->
                HiddenFindingCard(
                    finding = finding,
                    onInspectHex = { onInspectInHexLab(finding.path) }
                )
            }
        }
    }
}

@Composable
private fun EncryptionAndMismatchesTab(
    report: StorageForensicsReport,
    onInspectInHexLab: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Methodology & Anti-Fabrication Guarantee Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Lock, contentDescription = null, tint = AccentCyan)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Deterministic Encryption & Entropy Methodology",
                            color = Color.White,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 14.sp
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = report.encryptionMethodologyNote,
                        color = Color(0xFFCBD5E1),
                        fontSize = 11.sp
                    )
                }
            }
        }

        // 1. Confirmed Encryption Findings
        item {
            Text(
                text = "Confirmed Encryption Findings (${report.totalConfirmedEncryptedFiles} files • ${formatBytesHuman(report.totalConfirmedEncryptedBytes)})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
            Text(
                text = "Technically verified via cryptographic container headers (ZIP GP Bit 0 / AES-256, PDF /Encrypt, OpenSSL Salted__, LUKS, PGP, Office EncryptedPackage).",
                fontSize = 11.sp,
                color = TextSecondary
            )
        }

        if (report.confirmedEncryptionFindings.isEmpty()) {
            item {
                EmptyFindingCard("No files with confirmed format-level encryption headers were detected in accessible storage.")
            }
        } else {
            items(report.confirmedEncryptionFindings, key = { "conf_${it.path}" }) { item ->
                EncryptionFindingCard(
                    finding = item,
                    isConfirmed = true,
                    onInspectHex = { onInspectInHexLab(item.path) }
                )
            }
        }

        // 2. Potential Encryption / High-Entropy Indicators
        item {
            Spacer(Modifier.height(6.dp))
            Text(
                text = "Potential Encryption / High-Entropy Indicators (${report.totalPotentialEncryptedFiles} files • ${formatBytesHuman(report.totalPotentialEncryptedBytes)})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
            Text(
                text = "Unidentified binary files with high Shannon entropy (>= 7.80 bits/byte) or encrypted extensions. (${report.compressedMediaHighEntropyCount} standard compressed media files were automatically excluded.)",
                fontSize = 11.sp,
                color = TextSecondary
            )
        }

        if (report.potentialEncryptionFindings.isEmpty()) {
            item {
                EmptyFindingCard("No unidentified high-entropy binary streams detected.")
            }
        } else {
            items(report.potentialEncryptionFindings, key = { "pot_${it.path}" }) { item ->
                EncryptionFindingCard(
                    finding = item,
                    isConfirmed = false,
                    onInspectHex = { onInspectInHexLab(item.path) }
                )
            }
        }

        // 3. File-Extension / Signature Mismatches
        item {
            Spacer(Modifier.height(6.dp))
            Text(
                text = "File-Extension / Binary Signature Mismatches (${report.totalSignatureMismatches})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
            Text(
                text = "Files whose declared filename extension contradicts their verified binary magic header.",
                fontSize = 11.sp,
                color = TextSecondary
            )
        }

        if (report.signatureMismatches.isEmpty()) {
            item {
                EmptyFindingCard("No extension/signature mismatches found in scanned files.")
            }
        } else {
            items(report.signatureMismatches, key = { "mis_${it.path}" }) { mismatch ->
                SignatureMismatchCard(
                    mismatch = mismatch,
                    onInspectHex = { onInspectInHexLab(mismatch.path) }
                )
            }
        }
    }
}

@Composable
private fun InaccessibleScopeTab(report: StorageForensicsReport) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(
                text = "Unsupported or Inaccessible Storage Areas (${report.inaccessibleAreas.size})",
                fontWeight = FontWeight.ExtraBold,
                fontSize = 15.sp,
                color = TextPrimary
            )
            Text(
                text = "DeepVault respects Android Scoped Storage, Linux UID sandboxing, SELinux, and File-Based Encryption. Never claims that inaccessible directories contain specific hidden or encrypted user files.",
                fontSize = 11.sp,
                color = TextSecondary
            )
        }

        items(report.inaccessibleAreas, key = { it.path }) { area ->
            InaccessibleAreaCard(area)
        }

        item {
            Spacer(Modifier.height(6.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                        .padding(14.dp)
                ) {
                    Text(
                        text = "Forensic Scope & Methodology Notes",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 14.sp,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(8.dp))
                    report.forensicLimitations.forEach { lim ->
                        Text(
                            text = "• $lim",
                            fontSize = 11.sp,
                            color = TextSecondary,
                            modifier = Modifier.padding(vertical = 3.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricRow(label: String, value: String, sub: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = TextPrimary)
            Text(sub, fontSize = 10.sp, color = TextSecondary)
        }
        Text(value, fontWeight = FontWeight.ExtraBold, fontSize = 13.sp, color = TextPrimary)
    }
}

@Composable
private fun CoveragePill(
    modifier: Modifier = Modifier,
    title: String,
    percent: Double,
    subtitle: String,
    color: Color
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(color.copy(alpha = 0.08f))
            .border(1.dp, color.copy(alpha = 0.25f), RoundedCornerShape(14.dp))
            .padding(12.dp)
    ) {
        Text(title, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = color)
        Spacer(Modifier.height(4.dp))
        Text(
            text = "${String.format(Locale.US, "%.2f", percent)}%",
            fontSize = 20.sp,
            fontWeight = FontWeight.ExtraBold,
            color = TextPrimary
        )
        Text(subtitle, fontSize = 10.sp, color = TextSecondary)
    }
}

@Composable
private fun SummaryStatCard(
    modifier: Modifier = Modifier,
    title: String,
    primaryValue: String,
    secondaryValue: String,
    accentColor: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(16.dp))
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(13.dp)
        ) {
            Text(title, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = accentColor)
            Spacer(Modifier.height(4.dp))
            Text(primaryValue, fontSize = 17.sp, fontWeight = FontWeight.ExtraBold, color = TextPrimary)
            Spacer(Modifier.height(2.dp))
            Text(secondaryValue, fontSize = 10.sp, color = TextSecondary, maxLines = 1)
        }
    }
}

@Composable
private fun CategoryBreakdownRowCard(cat: RecognizedCategoryStat) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(cat.title, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = TextPrimary)
                    Text(
                        text = "${cat.fileCount} files • Extensions: ${cat.sampleExtensions.joinToString(", ").ifBlank { "none" }}",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(formatBytesHuman(cat.totalBytes), fontWeight = FontWeight.ExtraBold, fontSize = 13.sp, color = PrimaryGreen)
                    Text("${String.format(Locale.US, "%.1f", cat.shareOfScannedBytesPercent)}%", fontSize = 11.sp, color = TextSecondary)
                }
            }
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { (cat.shareOfScannedBytesPercent.toFloat() / 100f).coerceIn(0f, 1f) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(50)),
                color = PrimaryGreen,
                trackColor = SoftSurfaceBg
            )
        }
    }
}

@Composable
private fun UnclassifiedFileCard(
    item: UnclassifiedFileFinding,
    onInspectHex: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(item.name, fontWeight = FontWeight.ExtraBold, fontSize = 14.sp, color = TextPrimary, modifier = Modifier.weight(1f))
                Text(formatBytesHuman(item.sizeBytes), fontWeight = FontWeight.Bold, fontSize = 12.sp, color = PrimaryGreen)
            }
            Text(item.path, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            Text(
                text = "Magic Hex: ${item.magicHeaderHex}",
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = TextPrimary
            )
            Text(
                text = "Entropy: ${String.format(Locale.US, "%.2f", item.shannonEntropyBitsPerByte)} bits/B • Printable ASCII: ${String.format(Locale.US, "%.1f", item.printableAsciiRatio * 100)}%",
                fontSize = 11.sp,
                color = TextSecondary
            )
            Spacer(Modifier.height(4.dp))
            Text(item.classificationReason, fontSize = 11.sp, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onInspectHex,
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
            ) {
                Text("Inspect in Hex Lab", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun HiddenFindingCard(
    finding: HiddenArtifactFinding,
    onInspectHex: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(
                            if (finding.isNoMediaMarker) CoralRed.copy(alpha = 0.12f)
                            else SelectionOrange.copy(alpha = 0.12f)
                        )
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = finding.category.label,
                        color = if (finding.isNoMediaMarker) CoralRed else SelectionOrange,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(
                    text = if (finding.isDirectory) "Directory" else formatBytesHuman(finding.sizeBytes),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(finding.name, fontWeight = FontWeight.ExtraBold, fontSize = 14.sp, color = TextPrimary)
            Text(finding.path, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextSecondary)
            if (finding.lastModifiedIso != null) {
                Text("Modified (UTC): ${finding.lastModifiedIso}", fontSize = 10.sp, color = TextSecondary)
            }
            if (finding.mediaIndexingEffect != null) {
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Media Indexing Impact: ${finding.mediaIndexingEffect}",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(finding.forensicNote, fontSize = 11.sp, color = TextSecondary)
            if (!finding.isDirectory && finding.sizeBytes > 0L) {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onInspectHex,
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Text("Inspect Binary Header", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
private fun EncryptionFindingCard(
    finding: EncryptionFinding,
    isConfirmed: Boolean,
    onInspectHex: () -> Unit
) {
    val badgeColor = if (isConfirmed) CoralRed else Color(0xFF7C3AED)
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, badgeColor.copy(alpha = 0.35f), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(badgeColor.copy(alpha = 0.12f))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = finding.verificationStatus.label,
                        color = badgeColor,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
                Text(formatBytesHuman(finding.sizeBytes), fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
            }
            Spacer(Modifier.height(6.dp))
            Text(finding.name, fontWeight = FontWeight.ExtraBold, fontSize = 14.sp, color = TextPrimary)
            Text(finding.path, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            Text("Mechanism: ${finding.detectedMechanism}", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = badgeColor)
            Text("Evidence: ${finding.technicalEvidence}", fontSize = 11.sp, color = TextPrimary)
            Text(
                text = "Magic Hex: ${finding.magicHeaderHex} • Entropy: ${String.format(Locale.US, "%.2f", finding.shannonEntropyBitsPerByte)} bits/B",
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = TextSecondary
            )
            Spacer(Modifier.height(4.dp))
            Text("Caveat: ${finding.limitationOrCaveat}", fontSize = 11.sp, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onInspectHex,
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
            ) {
                Text("Inspect in Hex Lab", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SignatureMismatchCard(
    mismatch: SignatureMismatchFinding,
    onInspectHex: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, SelectionOrange.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "DECLARED .${mismatch.declaredExtension.uppercase(Locale.US)} ≠ ACTUAL ${mismatch.detectedFormat}",
                    color = CoralRed,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 11.sp
                )
                Text(formatBytesHuman(mismatch.sizeBytes), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
            }
            Spacer(Modifier.height(4.dp))
            Text(mismatch.name, fontWeight = FontWeight.ExtraBold, fontSize = 14.sp, color = TextPrimary)
            Text(mismatch.path, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            Text("Magic Bytes: ${mismatch.magicHeaderHex} (${mismatch.detectedMimeType})", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
            Text(mismatch.explanation, fontSize = 11.sp, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onInspectHex,
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
            ) {
                Text("Inspect in Hex Lab", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun InaccessibleAreaCard(area: InaccessibleStorageArea) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(area.areaType, fontWeight = FontWeight.ExtraBold, fontSize = 12.sp, color = PrimaryGreen)
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(SoftSurfaceBg)
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(area.securityMechanism, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(area.path, fontSize = 12.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = TextPrimary)
            Spacer(Modifier.height(4.dp))
            Text("Reason: ${area.restrictionReason}", fontSize = 11.sp, color = TextPrimary)
            Text("Forensic Impact: ${area.forensicImpact}", fontSize = 11.sp, color = TextSecondary)
        }
    }
}

@Composable
private fun MiniBadgePill(text: String) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(SoftSurfaceBg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Text(text, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
    }
}

@Composable
private fun EmptyFindingCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = AccentEmerald)
            Spacer(Modifier.width(10.dp))
            Text(message, fontSize = 12.sp, color = TextSecondary)
        }
    }
}
