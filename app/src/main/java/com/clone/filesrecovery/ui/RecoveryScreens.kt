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
import androidx.compose.material3.OutlinedButton
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
import com.clone.filesrecovery.forensics.OperatingMode
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
    val envAssessment by vm.environmentAssessment.collectAsState()
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
            PhoneLaserScannerView(
                category = category,
                isPreparing = isPreparing,
                foundCount = foundLive,
                scanningPath = progressText,
                isRootEnabledMode = envAssessment.activeOperatingMode == OperatingMode.ROOT_ENABLED && envAssessment.rootShellVerifiedUid0,
                modeLabel = envAssessment.recoveryModeLabel,
                modifier = mod.fillMaxSize()
            )
        } else {
            val deletedCount = remember(results) { results.count { it.isDeletedOrCarved } }
            val buckets by vm.folderBuckets.collectAsState()
            ScanCompletedView(
                category = category,
                foundCount = results.size,
                deletedOrCarvedCount = deletedCount,
                onViewDeletedDirectClick = {
                    val deletedBucket = buckets.firstOrNull { it.id == "__DELETED_CARVED__" }
                        ?: buckets.firstOrNull { it.isDeletedBucket }
                    if (deletedBucket != null) {
                        vm.selectBucket(deletedBucket)
                        nav.navigate("results") {
                            popUpTo("home") { inclusive = false }
                        }
                    } else {
                        nav.navigate("folders") {
                            popUpTo("home") { inclusive = false }
                        }
                    }
                },
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
    isRootEnabledMode: Boolean = false,
    modeLabel: String = "Standard",
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
                    text = if (isPreparing) "Preparing Deep Carve Engine ($modeLabel)…" else "Active Deep Recovery Pipeline ($modeLabel)",
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 15.sp,
                    color = TextPrimary
                )

                PipelineStageRow("Stage 1 • Priority Trash, .Trash & .nomedia Dig", active = true)
                PipelineStageRow("Stage 2 • .thumbdata Embedded JPEG Binary Carve", active = !isPreparing)
                PipelineStageRow("Stage 3 • MediaStore IS_TRASHED & Pending Query", active = !isPreparing && foundCount > 0)
                PipelineStageRow("Stage 4 • Orphaned Cache & LOST.DIR Signature Scan", active = !isPreparing)
                if (isRootEnabledMode) {
                    PipelineStageRow("Stage 5 • Root Read-Only Privileged VFS Scan", active = !isPreparing)
                }

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
    deletedOrCarvedCount: Int,
    onViewDeletedDirectClick: () -> Unit,
    onViewClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val activeGalleryCount = (foundCount - deletedOrCarvedCount).coerceAtLeast(0)
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
                        .size(84.dp)
                        .clip(RoundedCornerShape(24.dp))
                        .background(Brush.linearGradient(listOf(AccentEmerald, AccentCyan))),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.Check,
                        contentDescription = "Scan Completed",
                        tint = Color.White,
                        modifier = Modifier.size(44.dp)
                    )
                }

                Spacer(Modifier.height(16.dp))

                Text(
                    text = "Deep Forensic Dig Complete",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = TextPrimary
                )

                Spacer(Modifier.height(8.dp))

                Text(
                    text = buildAnnotatedString {
                        withStyle(SpanStyle(color = TextSecondary, fontSize = 14.sp, fontWeight = FontWeight.Medium)) {
                            append("Dug up ")
                        }
                        withStyle(SpanStyle(color = Color(0xFFDC2626), fontSize = 24.sp, fontWeight = FontWeight.ExtraBold)) {
                            append("$deletedOrCarvedCount")
                        }
                        withStyle(SpanStyle(color = TextSecondary, fontSize = 14.sp, fontWeight = FontWeight.Medium)) {
                            append(" deleted/carved remnants ")
                        }
                        withStyle(SpanStyle(color = TextSecondary, fontSize = 13.sp, fontWeight = FontWeight.Normal)) {
                            append("(+ $activeGalleryCount active files)")
                        }
                    }
                )

                Spacer(Modifier.height(14.dp))

                // Forensic Breakdown Pill Row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFFF8FAFC))
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(14.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$deletedOrCarvedCount",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = Color(0xFFDC2626)
                        )
                        Text(
                            text = "Deleted / Carved",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextSecondary
                        )
                    }
                    Box(
                        modifier = Modifier
                            .width(1.dp)
                            .height(28.dp)
                            .background(Color(0xFFCBD5E1))
                    )
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$activeGalleryCount",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Active Storage",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium,
                            color = TextSecondary
                        )
                    }
                }

                Spacer(Modifier.height(20.dp))

                if (deletedOrCarvedCount > 0) {
                    Button(
                        onClick = onViewDeletedDirectClick,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Text(
                            text = "View Deleted & Dug-Up ($deletedOrCarvedCount)",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                }

                Button(
                    onClick = onViewClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                        .testTag("scan_completed_view_button"),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (deletedOrCarvedCount > 0) PrimaryGreen else PrimaryGreen
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Text(
                        text = if (deletedOrCarvedCount > 0) "Browse By Folder & Category" else "Inspect & Recover Files",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
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
    val deletedTotal = remember(results) { results.count { it.isDeletedOrCarved } }
    val distinctFoldersCount = remember(results) {
        results.map { it.folderName }.distinct().size
    }

    var showDeletedBucketsOnly by remember(deletedTotal) {
        mutableStateOf(deletedTotal > 0)
    }

    val displayedBuckets = remember(buckets, showDeletedBucketsOnly) {
        if (showDeletedBucketsOnly) {
            buckets.filter { it.isDeletedBucket }
                .ifEmpty { buckets.filter { it.files.any { f -> f.isDeletedOrCarved } } }
        } else {
            buckets
        }
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
            // Top "Finish" Summary Card
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F6F8)),
                    shape = RoundedCornerShape(20.dp),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 18.dp, vertical = 16.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
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
                                Column {
                                    Text(
                                        text = "Deep Dig Summary",
                                        fontSize = 17.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF222222)
                                    )
                                    Text(
                                        text = "$deletedTotal Deleted/Carved • ${results.size} Total",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = if (deletedTotal > 0) Color(0xFFDC2626) else Color(0xFF666B75)
                                    )
                                }
                            }

                            // Right side mini icons + file & folder counts
                            Column(horizontalAlignment = Alignment.End) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    when (category) {
                                        FileCategory.AUDIO -> CuteMusicNoteIllustration(Modifier.size(20.dp))
                                        FileCategory.DOCUMENT -> CuteDocSheetStackIllustration(Modifier.size(20.dp))
                                        FileCategory.PHOTO -> CuteCameraIllustration(Modifier.size(20.dp))
                                        FileCategory.VIDEO -> CuteVideoProjectorIllustration(Modifier.size(20.dp))
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
                                    CuteFolderIllustration(Modifier.size(20.dp))
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

                        if (deletedTotal > 0) {
                            Spacer(Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                FilterChipPill(
                                    label = "Deleted & Unoverwritten Only",
                                    selected = showDeletedBucketsOnly,
                                    accentColor = Color(0xFFDC2626),
                                    onClick = { showDeletedBucketsOnly = true }
                                )
                                FilterChipPill(
                                    label = "Include Gallery Folders",
                                    selected = !showDeletedBucketsOnly,
                                    onClick = { showDeletedBucketsOnly = false }
                                )
                            }
                        }
                    }
                }
            }

            if (displayedBuckets.isEmpty()) {
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
                items(displayedBuckets, key = { it.id }) { bucket ->
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
private fun FilterChipPill(
    label: String,
    selected: Boolean,
    accentColor: Color = PrimaryGreen,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(if (selected) accentColor else Color.White)
            .border(
                width = 1.dp,
                color = if (selected) accentColor else Color(0xFFD0D5DD),
                shape = RoundedCornerShape(50)
            )
            .clickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            color = if (selected) Color.White else Color(0xFF344054),
            maxLines = 1,
            softWrap = false
        )
    }
}

@Composable
private fun FolderBucketCard(
    bucket: FolderBucket,
    category: FileCategory,
    onClick: () -> Unit
) {
    val isPriorityDeleted = bucket.isDeletedBucket
    val deletedInBucket = remember(bucket.files) { bucket.files.count { it.isDeletedOrCarved } }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .testTag("folder_bucket_${bucket.title}"),
        colors = CardDefaults.cardColors(
            containerColor = if (isPriorityDeleted) Color(0xFFFEF2F2) else Color(0xFFF7F8FA)
        ),
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(
                    if (isPriorityDeleted) {
                        Modifier.border(1.dp, Color(0xFFFECACA), RoundedCornerShape(20.dp))
                    } else {
                        Modifier
                    }
                )
                .padding(horizontal = 18.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
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
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = bucket.title,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isPriorityDeleted) Color(0xFF991B1B) else Color(0xFF1A1A1A),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (isPriorityDeleted) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(Color(0xFFDC2626))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = "DUG UP",
                                color = Color.White,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.ExtraBold,
                                maxLines = 1,
                                softWrap = false
                            )
                        }
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = if (isPriorityDeleted) {
                        "${bucket.files.size} recoverable deleted/carved items"
                    } else if (deletedInBucket > 0) {
                        "${bucket.files.size} items ($deletedInBucket deleted/hidden)"
                    } else {
                        "${bucket.files.size} items"
                    },
                    fontSize = 13.sp,
                    color = if (isPriorityDeleted) Color(0xFFB91C1C) else Color(0xFF8C919A),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = if (isPriorityDeleted) Color(0xFF991B1B) else Color(0xFF222222),
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

private enum class OriginFilter(val label: String) {
    ALL_IN_BUCKET("All in Folder"),
    DELETED_AND_CARVED("Deleted & Carved Only"),
    THUMB_CARVED("Carved Thumbnails"),
    TRASH_AND_HIDDEN("Trash & Hidden")
}

@Composable
fun ResultScreen(nav: NavController, vm: AppViewModel) {
    val allResults by vm.scanResults.collectAsState()
    val bucket = vm.currentBucket
    val rawFiles = bucket?.files ?: allResults
    val screenTitle = bucket?.title ?: "Deleted & Dug-Up Files"

    val selected by vm.selected.collectAsState()
    val isRecovering by vm.isRecovering.collectAsState()
    val lastRecovered by vm.lastRecoveredCount.collectAsState()
    val category = vm.currentCategory

    var sizeFilter by remember { mutableStateOf(SizeFilter.ALL) }
    val hasDeletedInRaw = remember(rawFiles) { rawFiles.any { it.isDeletedOrCarved } }
    // Default to Deleted & Unoverwritten Only whenever the folder has deleted/carved items so active gallery photos never clutter the view
    var originFilter by remember(bucket?.id, hasDeletedInRaw) {
        mutableStateOf(
            if (hasDeletedInRaw) OriginFilter.DELETED_AND_CARVED else OriginFilter.ALL_IN_BUCKET
        )
    }
    var showFilterMenu by remember { mutableStateOf(false) }

    val files = remember(rawFiles, sizeFilter, originFilter) {
        rawFiles.filter { file ->
            val sizeOk = sizeFilter == SizeFilter.ALL || file.size >= sizeFilter.minBytes
            val originOk = when (originFilter) {
                OriginFilter.ALL_IN_BUCKET -> true
                OriginFilter.DELETED_AND_CARVED -> file.isDeletedOrCarved
                OriginFilter.THUMB_CARVED ->
                    file.recoveryOrigin.contains("Carved", ignoreCase = true) ||
                        file.recoveryOrigin.contains("Cache", ignoreCase = true) ||
                        file.name.startsWith("carved_", ignoreCase = true)
                OriginFilter.TRASH_AND_HIDDEN ->
                    file.recoveryOrigin.contains("Recycle", ignoreCase = true) ||
                        file.recoveryOrigin.contains("Hidden", ignoreCase = true)
            }
            sizeOk && originOk
        }
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
            // Sub-header: Circular checkbox + "Select all" on left, Filter funnel on right
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 8.dp),
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
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = "Select all (${files.size})",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF111111),
                        maxLines = 1,
                        softWrap = false
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(
                        onClick = {
                            val chosen = files.filter { selected.contains(it.path) }.ifEmpty { files.take(40) }
                            vm.runCaseForensicAnalysis(chosen)
                            nav.navigate("forensics")
                        },
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.testTag("results_forensic_report_btn")
                    ) {
                        Text(
                            text = "Forensic Report",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = PrimaryGreen,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                    Spacer(Modifier.width(4.dp))
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
            }

            // Forensic Source Quick-Filter Bar (defaults to Deleted & Unoverwritten Only)
            if (hasDeletedInRaw && bucket?.isDeletedBucket != true) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChipPill(
                        label = "Deleted & Unoverwritten (${rawFiles.count { it.isDeletedOrCarved }})",
                        selected = originFilter == OriginFilter.DELETED_AND_CARVED,
                        accentColor = Color(0xFFDC2626),
                        onClick = { originFilter = OriginFilter.DELETED_AND_CARVED }
                    )
                    FilterChipPill(
                        label = "Include Active Gallery (${rawFiles.size})",
                        selected = originFilter == OriginFilter.ALL_IN_BUCKET,
                        onClick = { originFilter = OriginFilter.ALL_IN_BUCKET }
                    )
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

                        // Date Group Header Bar
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
                                // Document / Audio rows
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
    val badgeColor = when (file.recoveryBadgeLabel) {
        "UNOVERWRITTEN" -> Color(0xFFBE123C)
        "DELETED" -> Color(0xFFDC2626)
        "CARVED", "THUMB CACHE", "RAW CARVE" -> Color(0xFF7C3AED)
        "CACHE DIG", "HIDDEN" -> Color(0xFFD97706)
        else -> Color(0xFF64748B)
    }
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
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = middleEllipsize(file.name, 24),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF1A1A1A),
                    maxLines = 1,
                    modifier = Modifier.weight(1f, fill = false)
                )
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(badgeColor.copy(alpha = 0.14f))
                        .padding(horizontal = 5.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = file.recoveryBadgeLabel,
                        color = badgeColor,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.ExtraBold,
                        maxLines = 1,
                        softWrap = false
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                text = "${formatSize(file.size)} • ${file.recoveryOrigin}",
                fontSize = 12.sp,
                color = Color(0xFF888888),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
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
    val badgeBg = when (file.recoveryBadgeLabel) {
        "UNOVERWRITTEN" -> Color(0xFFBE123C).copy(alpha = 0.92f)
        "DELETED" -> Color(0xFFDC2626).copy(alpha = 0.88f)
        "CARVED", "THUMB CACHE", "RAW CARVE" -> Color(0xFF7C3AED).copy(alpha = 0.88f)
        "CACHE DIG", "HIDDEN" -> Color(0xFFD97706).copy(alpha = 0.88f)
        else -> Color.Black.copy(alpha = 0.55f)
    }
    Box(
        modifier = modifier
            .aspectRatio(1f)
            .clip(RoundedCornerShape(12.dp))
            .clickable { onOpen() }
    ) {
        FileThumb(file, Modifier.fillMaxSize())
        // Top-Start Origin Badge (DELETED / THUMB CACHE / CARVED / GALLERY)
        Box(
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(5.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(badgeBg)
                .padding(horizontal = 5.dp, vertical = 2.dp)
        ) {
            Text(
                text = file.recoveryBadgeLabel,
                color = Color.White,
                fontSize = 8.sp,
                fontWeight = FontWeight.ExtraBold,
                maxLines = 1,
                softWrap = false
            )
        }
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
            maxLines = 1,
            softWrap = false,
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
                    InfoRow("Status", "${file.recoveryBadgeLabel} (${file.recoveryOrigin})")
                    InfoRow("Folder", file.folderName)
                    InfoRow("Size", formatSize(file.size))
                    InfoRow("Modified", formatDate(file.lastModified))
                    InfoRow("Path", file.path)
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = {
                            vm.analyzeSingleRecoverableFile(file)
                            nav.navigate("forensics")
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("detail_forensic_inspect_btn")
                    ) {
                        Text(
                            text = "Inspect Forensic Metadata, Hashes & Export AI Report",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            color = PrimaryGreen
                        )
                    }
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
        onBack = { nav.popBackStack() },
        actions = {
            if (recovered.isNotEmpty()) {
                TextButton(
                    onClick = {
                        vm.runCaseForensicAnalysis(null)
                        nav.navigate("forensics")
                    },
                    modifier = Modifier.testTag("recovered_forensic_report_btn")
                ) {
                    Text("Forensic Report", color = PrimaryGreen, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
            }
        }
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
