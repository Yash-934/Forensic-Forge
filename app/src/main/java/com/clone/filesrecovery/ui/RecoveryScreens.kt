package com.clone.filesrecovery.ui

import android.media.MediaPlayer
import android.widget.MediaController
import android.widget.VideoView
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.FolderBucket
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.formatDate
import com.clone.filesrecovery.data.formatSize
import com.clone.filesrecovery.data.middleEllipsize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

// ---------------- Scanning & Scan Completed Screen (Screenshots 5, 6, 8, 9, 10) ----------------

@Composable
fun ScanScreen(nav: NavController, vm: AppViewModel, category: FileCategory) {
    val isPreparing by vm.isPreparing.collectAsState()
    val isScanning by vm.isScanning.collectAsState()
    val results by vm.scanResults.collectAsState()
    val progressText by vm.scanProgressText.collectAsState()
    val foundLive by vm.foundLiveCount.collectAsState()
    var started by remember { mutableStateOf(false) }

    LaunchedEffect(category) {
        if (!started) {
            started = true
            vm.startScan(category)
        }
    }

    SimpleScaffold(
        title = category.recoveryTitle,
        onBack = { nav.popBackStack() },
        warmBackground = true
    ) { mod ->
        if (isScanning) {
            // Active "Preparing" or "Scanning" view with Phone Laser Animation (Screenshots 5, 8, 9)
            PhoneLaserScannerView(
                category = category,
                isPreparing = isPreparing,
                foundCount = foundLive,
                scanningPath = progressText,
                modifier = mod.fillMaxSize()
            )
        } else {
            // Scan Completed view (Screenshots 6 & 10)
            ScanCompletedView(
                category = category,
                foundCount = results.size,
                onViewClick = {
                    nav.navigate("folders") {
                        popUpTo("home") { inclusive = false }
                    }
                },
                modifier = mod.fillMaxSize()
            )
        }
    }
}

@Composable
private fun PhoneLaserScannerView(
    category: FileCategory,
    isPreparing: Boolean,
    foundCount: Int,
    scanningPath: String,
    modifier: Modifier = Modifier
) {
    val transition = rememberInfiniteTransition(label = "sonar_scan")
    val radarAngle by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "radar_angle"
    )
    val pulseRadius by transition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.98f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_radius"
    )

    Column(
        modifier = modifier.padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(22.dp))

        // 360° Cyber Sonar Radar Dial
        Box(
            modifier = Modifier
                .size(260.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        listOf(Color(0xFF1E1B4B), Color(0xFF0F172A))
                    )
                )
                .border(3.dp, PrimaryGreen.copy(alpha = 0.35f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val center = Offset(size.width / 2f, size.height / 2f)
                val maxR = size.minDimension / 2f

                // Concentric sonar grid rings
                listOf(0.32f, 0.58f, 0.82f).forEach { frac ->
                    drawCircle(
                        color = AccentCyan.copy(alpha = 0.20f),
                        radius = maxR * frac,
                        center = center,
                        style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1.5.dp.toPx())
                    )
                }

                // Expanding pulse wave
                drawCircle(
                    color = AccentCyan.copy(alpha = (1f - pulseRadius) * 0.55f),
                    radius = maxR * pulseRadius,
                    center = center,
                    style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.5.dp.toPx())
                )

                // Crosshairs
                drawLine(
                    color = AccentCyan.copy(alpha = 0.16f),
                    start = Offset(0f, center.y),
                    end = Offset(size.width, center.y),
                    strokeWidth = 1.dp.toPx()
                )
                drawLine(
                    color = AccentCyan.copy(alpha = 0.16f),
                    start = Offset(center.x, 0f),
                    end = Offset(center.x, size.height),
                    strokeWidth = 1.dp.toPx()
                )

                // Rotating radar sweep sector
                drawArc(
                    brush = Brush.sweepGradient(
                        0.0f to Color.Transparent,
                        0.75f to PrimaryGreen.copy(alpha = 0.10f),
                        1.0f to AccentCyan.copy(alpha = 0.55f),
                        center = center
                    ),
                    startAngle = radarAngle - 90f,
                    sweepAngle = 90f,
                    useCenter = true
                )
            }

            // Center Category Emblem + Live Counter
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                when (category) {
                    FileCategory.PHOTO -> CuteCameraIllustration(Modifier.size(64.dp))
                    FileCategory.VIDEO -> CuteVideoProjectorIllustration(Modifier.size(64.dp))
                    FileCategory.AUDIO -> CuteMusicNoteIllustration(Modifier.size(64.dp))
                    FileCategory.DOCUMENT -> CuteFolderIllustration(Modifier.size(64.dp))
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    text = if (isPreparing) "INIT" else "$foundCount",
                    color = Color.White,
                    fontSize = 26.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    text = if (isPreparing) "MOUNTING SECTORS" else "${category.title.uppercase()} FOUND",
                    color = AccentCyan,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold
                )
            }
        }

        Spacer(Modifier.height(22.dp))

        // 4-Stage Forensic Pipeline Status Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(20.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = if (isPreparing) "Preparing Deep Carve Engine…" else "Active Deep Recovery Pipeline",
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 15.sp,
                    color = TextPrimary
                )

                PipelineStageRow("Stage 1 • Multi-Root & Hidden Trash Walk", active = true)
                PipelineStageRow("Stage 2 • Magic-Byte Binary Signature Carve", active = !isPreparing)
                PipelineStageRow("Stage 3 • MediaStore Trashed & Pending Query", active = !isPreparing && foundCount > 0)
                PipelineStageRow("Stage 4 • .thumbdata Embedded JPEG Carve", active = !isPreparing && category == FileCategory.PHOTO)

                val displayPath = if (scanningPath.isNotBlank()) {
                    middleEllipsize(scanningPath, 42)
                } else {
                    "/storage/emulated/0/…"
                }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFFF1F5F9))
                        .padding(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = "Sector: $displayPath",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
private fun PipelineStageRow(label: String, active: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(18.dp)
                .clip(CircleShape)
                .background(if (active) AccentEmerald else Color(0xFFE2E8F0)),
            contentAlignment = Alignment.Center
        ) {
            if (active) {
                Icon(
                    imageVector = Icons.Filled.Check,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(12.dp)
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        Text(
            text = label,
            fontSize = 12.sp,
            fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
            color = if (active) TextPrimary else TextSecondary
        )
    }
}

@Composable
private fun ScanCompletedView(
    category: FileCategory,
    foundCount: Int,
    onViewClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(26.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(26.dp))
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .size(88.dp)
                        .clip(RoundedCornerShape(26.dp))
                        .background(Brush.linearGradient(listOf(AccentEmerald, AccentCyan))),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.Check,
                        contentDescription = "Scan Completed",
                        tint = Color.White,
                        modifier = Modifier.size(46.dp)
                    )
                }

                Spacer(Modifier.height(18.dp))

                Text(
                    text = "Deep Analysis Complete",
                    fontSize = 23.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = TextPrimary
                )

                Spacer(Modifier.height(8.dp))

                Text(
                    text = buildAnnotatedString {
                        withStyle(SpanStyle(color = TextSecondary, fontSize = 15.sp, fontWeight = FontWeight.Medium)) {
                            append("Carved & indexed ")
                        }
                        withStyle(SpanStyle(color = PrimaryGreen, fontSize = 25.sp, fontWeight = FontWeight.ExtraBold)) {
                            append("$foundCount")
                        }
                        withStyle(SpanStyle(color = TextSecondary, fontSize = 15.sp, fontWeight = FontWeight.Medium)) {
                            append(" recoverable ${category.countableLabel}")
                        }
                    }
                )

                Spacer(Modifier.height(24.dp))

                Button(
                    onClick = onViewClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp)
                        .testTag("scan_completed_view_button"),
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Text(
                        text = "Inspect & Recover Files",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
            }
        }
    }
}

// ---------------- Folder Breakdown Screen (Screenshots 7 & 11) ----------------

@Composable
fun FolderBreakdownScreen(nav: NavController, vm: AppViewModel) {
    val buckets by vm.folderBuckets.collectAsState()
    val results by vm.scanResults.collectAsState()
    val category = vm.currentCategory
    val distinctFoldersCount = remember(results) {
        results.map { it.folderName }.distinct().size
    }

    SimpleScaffold(
        title = category.recoveryTitle,
        onBack = { nav.popBackStack() }
    ) { mod ->
        LazyColumn(
            modifier = mod
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(top = 8.dp, bottom = 24.dp)
        ) {
            // Top "Finish" Summary Card (Screenshots 7 & 11)
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F6F8)),
                    shape = RoundedCornerShape(20.dp),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 18.dp, vertical = 18.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(24.dp)
                                    .clip(CircleShape)
                                    .background(PrimaryGreen),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Check,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = "Finish",
                                fontSize = 19.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF222222)
                            )
                        }

                        // Right side mini icons + file & folder counts
                        Column(horizontalAlignment = Alignment.End) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                when (category) {
                                    FileCategory.AUDIO -> CuteMusicNoteIllustration(Modifier.size(22.dp))
                                    FileCategory.DOCUMENT -> CuteDocSheetStackIllustration(Modifier.size(22.dp))
                                    FileCategory.PHOTO -> CuteCameraIllustration(Modifier.size(22.dp))
                                    FileCategory.VIDEO -> CuteVideoProjectorIllustration(Modifier.size(22.dp))
                                }
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = "${results.size}",
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color(0xFF222222)
                                )
                            }
                            Spacer(Modifier.height(4.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CuteFolderIllustration(Modifier.size(22.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = "$distinctFoldersCount",
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color(0xFF222222)
                                )
                            }
                        }
                    }
                }
            }

            if (buckets.isEmpty()) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 64.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            Icons.Filled.FolderOpen,
                            contentDescription = null,
                            tint = Color(0xFF9EA3AE),
                            modifier = Modifier.size(64.dp)
                        )
                        Spacer(Modifier.height(12.dp))
                        Text("No recoverable ${category.countableLabel} found", fontWeight = FontWeight.Bold)
                    }
                }
            } else {
                items(buckets, key = { it.id }) { bucket ->
                    FolderBucketCard(
                        bucket = bucket,
                        category = category,
                        onClick = {
                            vm.selectBucket(bucket)
                            nav.navigate("results")
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun FolderBucketCard(
    bucket: FolderBucket,
    category: FileCategory,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .testTag("folder_bucket_${bucket.title}"),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF7F8FA)),
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Left icon matching Screenshot 7 (MP3 badge for Audio) and Screenshot 11 (Yellow Folder for Document)
            when (category) {
                FileCategory.AUDIO -> {
                    FileTypeBadgeIcon(extension = "mp3", category = FileCategory.AUDIO)
                }
                FileCategory.DOCUMENT -> {
                    YellowFolderIcon()
                }
                FileCategory.PHOTO, FileCategory.VIDEO -> {
                    val sample = bucket.files.firstOrNull()
                    if (sample != null) {
                        FileThumb(
                            file = sample,
                            modifier = Modifier
                                .size(52.dp)
                                .clip(RoundedCornerShape(10.dp))
                        )
                    } else {
                        YellowFolderIcon()
                    }
                }
            }

            Spacer(Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = bucket.title,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFF1A1A1A),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "${bucket.files.size}",
                    fontSize = 14.sp,
                    color = Color(0xFF8C919A)
                )
            }

            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = Color(0xFF222222),
                modifier = Modifier.size(24.dp)
            )
        }
    }
}

// ---------------- Date-Grouped Folder Files Screen (Screenshots 12, 13, 14) ----------------

private enum class SizeFilter(val label: String, val minBytes: Long) {
    ALL("All Sizes", 0L),
    OVER_100KB("> 100 KB", 100L * 1024L),
    OVER_1MB("> 1 MB", 1024L * 1024L),
    OVER_10MB("> 10 MB", 10L * 1024L * 1024L)
}

@Composable
fun ResultScreen(nav: NavController, vm: AppViewModel) {
    val allResults by vm.scanResults.collectAsState()
    val bucket = vm.currentBucket
    val rawFiles = bucket?.files ?: allResults
    val screenTitle = bucket?.title ?: "All"

    val selected by vm.selected.collectAsState()
    val isRecovering by vm.isRecovering.collectAsState()
    val lastRecovered by vm.lastRecoveredCount.collectAsState()
    val category = vm.currentCategory

    var sizeFilter by remember { mutableStateOf(SizeFilter.ALL) }
    var showFilterMenu by remember { mutableStateOf(false) }

    val files = remember(rawFiles, sizeFilter) {
        if (sizeFilter == SizeFilter.ALL) rawFiles
        else rawFiles.filter { it.size >= sizeFilter.minBytes }
    }

    val groupedByDate = remember(files) {
        files.groupBy { it.dateGroupKey }
    }

    val collapsedGroups = remember { mutableStateMapOf<String, Boolean>() }

    if (lastRecovered != null) {
        AlertDialog(
            onDismissRequest = { vm.consumeRecoveredEvent() },
            icon = {
                Icon(
                    Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = PrimaryGreen,
                    modifier = Modifier.size(44.dp)
                )
            },
            title = { Text("Recovery Completed", fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "$lastRecovered file(s) recovered to FilesRecovery/${category.title}. " +
                        "You can view them anytime in Recovered Files."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        vm.consumeRecoveredEvent()
                        nav.navigate("recovered")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen)
                ) {
                    Text("View Recovered")
                }
            },
            dismissButton = {
                TextButton(onClick = { vm.consumeRecoveredEvent() }) {
                    Text("Close", color = Color(0xFF666B75))
                }
            }
        )
    }

    val allSelected = files.isNotEmpty() && files.all { selected.contains(it.path) }

    SimpleScaffold(
        title = screenTitle,
        onBack = { nav.popBackStack() },
        bottomBar = {
            if (selected.isNotEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White)
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Button(
                        onClick = { vm.recoverSelected() },
                        enabled = !isRecovering,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp)
                            .testTag("recover_selected_button"),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            text = if (isRecovering) "Recovering…" else "Recover (${selected.size})",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
            }
        }
    ) { mod ->
        Column(modifier = mod.fillMaxSize()) {
            // Sub-header: Circular checkbox + "Select all" on left, Filter funnel on right (Screenshots 12, 13, 14)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable {
                        if (allSelected) vm.clearSelection() else vm.selectAll(files)
                    }
                ) {
                    RoundCheckButton(
                        checked = allSelected,
                        onToggle = {
                            if (allSelected) vm.clearSelection() else vm.selectAll(files)
                        }
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = "Select all",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF111111)
                    )
                }

                Box {
                    IconButton(onClick = { showFilterMenu = true }) {
                        Icon(
                            imageVector = Icons.Filled.FilterAlt,
                            contentDescription = "Filter",
                            tint = Color(0xFF222222)
                        )
                    }
                    DropdownMenu(
                        expanded = showFilterMenu,
                        onDismissRequest = { showFilterMenu = false }
                    ) {
                        SizeFilter.entries.forEach { f ->
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = f.label,
                                        fontWeight = if (sizeFilter == f) FontWeight.Bold else FontWeight.Normal,
                                        color = if (sizeFilter == f) PrimaryGreen else Color(0xFF222222)
                                    )
                                },
                                onClick = {
                                    sizeFilter = f
                                    showFilterMenu = false
                                }
                            )
                        }
                    }
                }
            }

            if (files.isEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        Icons.Filled.FolderOpen,
                        contentDescription = null,
                        tint = Color(0xFF9EA3AE),
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(Modifier.height(12.dp))
                    Text("No files match this filter", fontWeight = FontWeight.Bold)
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 14.dp),
                    contentPadding = PaddingValues(bottom = 24.dp)
                ) {
                    groupedByDate.forEach { (dateLabel, groupFiles) ->
                        val isCollapsed = collapsedGroups[dateLabel] == true
                        val groupSelected = groupFiles.all { selected.contains(it.path) }

                        // Date Group Header Bar (Screenshots 12, 13, 14: "October 20.2026 v" ... "Select O")
                        item(key = "header_$dateLabel") {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(Color(0xFFFAFAFC))
                                    .clickable {
                                        collapsedGroups[dateLabel] = !isCollapsed
                                    }
                                    .padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = dateLabel,
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF222222)
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Icon(
                                        imageVector = if (isCollapsed) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                                        contentDescription = null,
                                        tint = Color(0xFF666B75),
                                        modifier = Modifier.size(20.dp)
                                    )
                                }

                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.clickable {
                                        vm.toggleGroupSelection(groupFiles)
                                    }
                                ) {
                                    Text(
                                        text = "Select",
                                        fontSize = 15.sp,
                                        color = Color(0xFF444444)
                                    )
                                    Spacer(Modifier.width(10.dp))
                                    RoundCheckButton(
                                        checked = groupSelected,
                                        onToggle = { vm.toggleGroupSelection(groupFiles) }
                                    )
                                }
                            }
                        }

                        if (!isCollapsed) {
                            if (category == FileCategory.PHOTO || category == FileCategory.VIDEO) {
                                // 3-column grid rows inside the date section
                                val rows = groupFiles.chunked(3)
                                items(rows, key = { it.first().path }) { rowFiles ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(vertical = 4.dp),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        rowFiles.forEach { file ->
                                            FileGridItem(
                                                file = file,
                                                checked = selected.contains(file.path),
                                                onToggle = { vm.toggleSelect(file) },
                                                onOpen = {
                                                    vm.currentFile = file
                                                    nav.navigate("detail")
                                                },
                                                modifier = Modifier.weight(1f)
                                            )
                                        }
                                        repeat(3 - rowFiles.size) {
                                            Spacer(Modifier.weight(1f))
                                        }
                                    }
                                }
                            } else {
                                // Document / Audio rows matching Screenshots 12, 13, 14
                                items(groupFiles, key = { it.path }) { file ->
                                    DocumentOrAudioListItem(
                                        file = file,
                                        checked = selected.contains(file.path),
                                        onToggle = { vm.toggleSelect(file) },
                                        onOpen = {
                                            vm.currentFile = file
                                            nav.navigate("detail")
                                        }
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

@Composable
private fun DocumentOrAudioListItem(
    file: RecoverableFile,
    checked: Boolean,
    onToggle: () -> Unit,
    onOpen: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpen() }
            .padding(horizontal = 8.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        FileTypeBadgeIcon(
            extension = file.extension,
            category = file.category
        )
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = middleEllipsize(file.name, 29),
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = Color(0xFF1A1A1A),
                maxLines = 1
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = formatSize(file.size),
                fontSize = 13.sp,
                color = Color(0xFF888888)
            )
        }
        Spacer(Modifier.width(12.dp))
        RoundCheckButton(
            checked = checked,
            onToggle = onToggle
        )
    }
}

@Composable
private fun FileGridItem(
    file: RecoverableFile,
    checked: Boolean,
    onToggle: () -> Unit,
    onOpen: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .aspectRatio(1f)
            .clip(RoundedCornerShape(12.dp))
            .clickable { onOpen() }
    ) {
        FileThumb(file, Modifier.fillMaxSize())
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(6.dp)
        ) {
            RoundCheckButton(
                checked = checked,
                onToggle = onToggle,
                size = 22.dp
            )
        }
        Text(
            text = formatSize(file.size),
            color = Color.White,
            fontSize = 10.sp,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .background(Color.Black.copy(alpha = 0.55f), RoundedCornerShape(topEnd = 6.dp))
                .padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

// ---------------- Detail / preview ----------------

@Composable
fun DetailScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val file = vm.currentFile
    val isRecovering by vm.isRecovering.collectAsState()
    val lastRecovered by vm.lastRecoveredCount.collectAsState()

    if (file == null) {
        LaunchedEffect(Unit) { nav.popBackStack() }
        return
    }

    if (lastRecovered != null) {
        AlertDialog(
            onDismissRequest = { vm.consumeRecoveredEvent() },
            title = { Text("File Recovered", fontWeight = FontWeight.Bold) },
            text = { Text("${file.name} has been restored to your public FilesRecovery/${file.category.title} folder.") },
            confirmButton = {
                Button(
                    onClick = {
                        vm.consumeRecoveredEvent()
                        nav.navigate("recovered")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen)
                ) {
                    Text("View Recovered")
                }
            },
            dismissButton = {
                TextButton(onClick = { vm.consumeRecoveredEvent() }) {
                    Text("OK")
                }
            }
        )
    }

    SimpleScaffold(
        title = middleEllipsize(file.name, 24),
        onBack = { nav.popBackStack() },
        bottomBar = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.White)
                    .padding(horizontal = 20.dp, vertical = 12.dp)
            ) {
                Button(
                    onClick = { vm.recoverSingle(file) },
                    enabled = !isRecovering,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp)
                        .testTag("recover_single_button"),
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                    shape = RoundedCornerShape(50)
                ) {
                    Text(
                        if (isRecovering) "Recovering…" else "Recover",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    ) { mod ->
        Column(mod.fillMaxSize().padding(18.dp)) {
            when (file.category) {
                FileCategory.PHOTO -> {
                    val bmpState = produceState<android.graphics.Bitmap?>(null, file.path) {
                        value = withContext(Dispatchers.IO) {
                            runCatching { android.graphics.BitmapFactory.decodeFile(file.path) }.getOrNull()
                        }
                    }
                    val bmp = bmpState.value
                    if (bmp != null) {
                        androidx.compose.foundation.Image(
                            bitmap = bmp.asImageBitmap(),
                            contentDescription = file.name,
                            contentScale = ContentScale.Fit,
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f)
                                .clip(RoundedCornerShape(16.dp))
                        )
                    } else {
                        FileThumb(
                            file,
                            Modifier
                                .fillMaxWidth()
                                .height(260.dp)
                                .clip(RoundedCornerShape(16.dp))
                        )
                    }
                }
                FileCategory.VIDEO -> {
                    AndroidView(
                        factory = { ctx ->
                            VideoView(ctx).apply {
                                setVideoPath(file.path)
                                val mc = MediaController(ctx)
                                mc.setAnchorView(this)
                                setMediaController(mc)
                                setOnPreparedListener { start() }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .aspectRatio(16f / 9f)
                            .background(Color.Black, RoundedCornerShape(16.dp))
                    )
                }
                FileCategory.AUDIO -> {
                    AudioPlayer(path = file.path)
                }
                FileCategory.DOCUMENT -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(180.dp)
                            .clip(RoundedCornerShape(18.dp))
                            .background(Color(0xFFF6F7F9)),
                        contentAlignment = Alignment.Center
                    ) {
                        FileTypeBadgeIcon(
                            extension = file.extension,
                            category = file.category,
                            modifier = Modifier.size(72.dp)
                        )
                    }
                    Spacer(Modifier.height(14.dp))
                    Button(
                        onClick = { openFile(context, File(file.path), mimeFor(file)) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CapacityBlue),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text("Open / Preview File", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
            Spacer(Modifier.height(18.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(16.dp)) {
                    InfoRow("Name", file.name)
                    InfoRow("Folder", file.folderName)
                    InfoRow("Source", file.recoveryOrigin)
                    InfoRow("Size", formatSize(file.size))
                    InfoRow("Modified", formatDate(file.lastModified))
                    InfoRow("Path", file.path)
                }
            }
        }
    }
}

@Composable
private fun AudioPlayer(path: String) {
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var playing by remember { mutableStateOf(false) }
    DisposableEffect(path) {
        val p = runCatching { MediaPlayer().apply { setDataSource(path); prepare() } }.getOrNull()
        player = p
        onDispose { runCatching { p?.release() } }
    }
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .padding(24.dp)
    ) {
        IconButton(
            onClick = {
                player?.let {
                    if (it.isPlaying) {
                        it.pause()
                        playing = false
                    } else {
                        it.start()
                        playing = true
                    }
                }
            },
            modifier = Modifier
                .size(76.dp)
                .background(PrimaryGreen, CircleShape)
        ) {
            Icon(
                if (playing) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                contentDescription = "Play/Pause",
                tint = Color.White,
                modifier = Modifier.size(40.dp)
            )
        }
        Text(
            if (playing) "Playing audio…" else "Tap to play preview",
            color = Color(0xFF666B75),
            modifier = Modifier.padding(top = 10.dp)
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            label,
            color = Color(0xFF7A7F87),
            fontSize = 13.sp,
            modifier = Modifier.width(82.dp)
        )
        Text(
            value,
            fontSize = 13.sp,
            color = Color(0xFF1A1A1A),
            fontWeight = FontWeight.Medium
        )
    }
}

// ---------------- Recovered files ----------------

@Composable
fun RecoveredScreen(nav: NavController, vm: AppViewModel) {
    val recovered by vm.recovered.collectAsState()
    LaunchedEffect(Unit) { vm.loadRecovered() }

    SimpleScaffold(
        title = "Recovered Files",
        onBack = { nav.popBackStack() }
    ) { mod ->
        if (recovered.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CuteRecoveredBoxIllustration(Modifier.size(110.dp))
                Spacer(Modifier.height(14.dp))
                Text("No recovered files yet", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Files you recover will appear here for easy access.",
                    color = Color(0xFF7A7F87),
                    fontSize = 14.sp
                )
            }
        } else {
            LazyColumn(
                mod.fillMaxSize().padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(vertical = 12.dp)
            ) {
                items(recovered, key = { it.recoveredPath + it.recoveredAt }) { rec ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val f = File(rec.originalPath)
                                if (f.exists()) {
                                    vm.currentFile = RecoverableFile(
                                        path = rec.originalPath,
                                        name = rec.name,
                                        category = rec.category,
                                        size = rec.size,
                                        lastModified = rec.recoveredAt
                                    )
                                    nav.navigate("detail")
                                }
                            },
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                        shape = RoundedCornerShape(16.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                    ) {
                        Row(
                            Modifier.padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            FileTypeBadgeIcon(
                                extension = rec.name.substringAfterLast('.', ""),
                                category = rec.category
                            )
                            Column(Modifier.padding(start = 14.dp).weight(1f)) {
                                Text(
                                    middleEllipsize(rec.name, 28),
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 15.sp,
                                    maxLines = 1
                                )
                                Text(
                                    "Saved to: ${rec.recoveredPath}",
                                    color = Color(0xFF666B75),
                                    fontSize = 12.sp
                                )
                                Text(
                                    "${formatSize(rec.size)} • ${formatDate(rec.recoveredAt)}",
                                    color = Color(0xFF888888),
                                    fontSize = 11.sp
                                )
                            }
                            Icon(
                                Icons.Filled.CheckCircle,
                                contentDescription = null,
                                tint = PrimaryGreen
                            )
                        }
                    }
                }
            }
        }
    }
}
