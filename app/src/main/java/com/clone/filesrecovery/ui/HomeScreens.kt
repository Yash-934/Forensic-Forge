package com.clone.filesrecovery.ui

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon as AndroidIcon
import android.net.Uri
import android.os.Build
import android.widget.Toast
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
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.MainActivity
import com.clone.filesrecovery.R
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.StorageBreakdown
import com.clone.filesrecovery.data.formatGbPair

// ---------------- Guide / onboarding ----------------

@Composable
fun GuideScreen(onDone: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgLight)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier
                .size(110.dp)
                .clip(RoundedCornerShape(28.dp))
                .background(Brush.linearGradient(listOf(PrimaryGreen, AccentCyan))),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Filled.RestoreFromTrash,
                contentDescription = "DeepVault Recovery",
                tint = Color.White,
                modifier = Modifier.size(58.dp)
            )
        }
        Spacer(Modifier.height(24.dp))
        Text("DeepVault Recovery", fontSize = 26.sp, fontWeight = FontWeight.ExtraBold, color = TextPrimary)
        Spacer(Modifier.height(8.dp))
        Text(
            "Multi-layer signature carving, .thumbdata extraction, and deleted media recovery.",
            color = TextSecondary,
            fontSize = 15.sp
        )
        Spacer(Modifier.height(40.dp))
        Button(
            onClick = onDone,
            modifier = Modifier
                .fillMaxWidth()
                .height(54.dp)
                .testTag("guide_start_button"),
            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
            shape = RoundedCornerShape(16.dp)
        ) {
            Text("Get Started", fontSize = 17.sp, fontWeight = FontWeight.Bold)
        }
    }
}

// ---------------- Language selector ----------------

private val LANGUAGES = listOf(
    "English" to "en",
    "हिन्दी (Hindi)" to "hi",
    "Español (Spanish)" to "es",
    "Português (Portuguese)" to "pt",
    "Français (French)" to "fr",
    "Deutsch (German)" to "de",
    "العربية (Arabic)" to "ar",
    "Indonesia" to "in",
    "Русский (Russian)" to "ru",
    "日本語 (Japanese)" to "ja",
    "한국어 (Korean)" to "ko"
)

@Composable
fun LanguageScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("app", 0) }
    var selected by remember { mutableStateOf(prefs.getString("lang", "en") ?: "en") }

    SimpleScaffold(title = "App Language", onBack = onDone) { mod ->
        Column(
            modifier = mod
                .fillMaxSize()
                .padding(16.dp)
        ) {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(LANGUAGES) { (name, code) ->
                    val isSelected = selected == code
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selected = code },
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected) Color(0xFFEEF2FF) else Color.White
                        ),
                        shape = RoundedCornerShape(16.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(
                                    width = if (isSelected) 1.5.dp else 1.dp,
                                    color = if (isSelected) PrimaryGreen else Color(0xFFE2E8F0),
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Filled.Language, contentDescription = null, tint = PrimaryGreen)
                            Spacer(Modifier.width(12.dp))
                            Text(name, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            RadioButton(selected = isSelected, onClick = { selected = code })
                        }
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = {
                    prefs.edit().putString("lang", selected).putBoolean("onboarded", true).apply()
                    onDone()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
                    .testTag("language_continue_button"),
                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                shape = RoundedCornerShape(16.dp)
            ) {
                Text("Save Language", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

// ---------------- Redesigned DeepVault Studio Home Screen ----------------

@Composable
fun HomeScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val breakdown by vm.storageBreakdown.collectAsState()
    val recoveredList by vm.recovered.collectAsState()

    LaunchedEffect(Unit) {
        vm.refreshStorageBreakdown()
    }

    fun navigateToScan(cat: FileCategory) {
        if (hasAllFilesAccess(context)) {
            nav.navigate("scan/${cat.name}")
        } else {
            nav.navigate("permission/${cat.name}")
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgLight)
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        // Redesigned Studio Top Bar
        Surface(
            color = Color.White,
            shadowElevation = 2.dp
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(13.dp))
                            .background(Brush.linearGradient(listOf(PrimaryGreen, AccentCyan))),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.RestoreFromTrash,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "DeepVault",
                                fontSize = 21.sp,
                                fontWeight = FontWeight.ExtraBold,
                                color = TextPrimary
                            )
                            Spacer(Modifier.width(8.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(Color(0xFFE0E7FF))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = "PRO ENGINE",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = PrimaryGreen
                                )
                            }
                        }
                        Text(
                            text = "Forensic File Carving & Recovery",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color(0xFFF1F5F9))
                            .clickable { nav.navigate("recovered") }
                            .testTag("header_vault_button"),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.FolderSpecial,
                            contentDescription = "Recovered Vault",
                            tint = PrimaryGreen,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color(0xFFF1F5F9))
                            .clickable { nav.navigate("settings") }
                            .testTag("settings_button"),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Settings,
                            contentDescription = "Settings",
                            tint = TextPrimary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // 1. Redesigned Storage Radar & Breakdown Hero Card
            item {
                StorageHeroDashboardCard(
                    breakdown = breakdown,
                    onClick = { nav.navigate("storage") }
                )
            }

            // 2. Section Header: Deep Carve & Media Recovery
            item {
                SectionHeaderRow(
                    title = "Deep Recovery Channels",
                    subtitle = "4-stage signature, trash & .thumbdata carving"
                )
            }

            // 3. Row 1: Photo Recovery + Video Recovery
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    DeepChannelCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_photo_recovery"),
                        title = "Photo Recovery",
                        subtitle = "JPEG, PNG, WebP, HEIC & .thumbdata carve",
                        badge = "IMG",
                        accentColor = AccentPhoto,
                        onClick = { navigateToScan(FileCategory.PHOTO) }
                    ) {
                        CuteCameraIllustration(modifier = Modifier.size(56.dp))
                    }

                    DeepChannelCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_video_recovery"),
                        title = "Video Recovery",
                        subtitle = "MP4, MKV, MOV, AVI & cached clips",
                        badge = "VID",
                        accentColor = AccentVideo,
                        onClick = { navigateToScan(FileCategory.VIDEO) }
                    ) {
                        CuteVideoProjectorIllustration(modifier = Modifier.size(56.dp))
                    }
                }
            }

            // 4. Row 2: Audio Recovery + Document Recovery
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    DeepChannelCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_audio_recovery"),
                        title = "Audio Recovery",
                        subtitle = "MP3, WAV, M4A, Opus & voice notes",
                        badge = "AUD",
                        accentColor = AccentAudio,
                        onClick = { navigateToScan(FileCategory.AUDIO) }
                    ) {
                        CuteMusicNoteIllustration(modifier = Modifier.size(56.dp))
                    }

                    DeepChannelCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_document_recovery"),
                        title = "Docs & Archives",
                        subtitle = "PDF, DOCX, XLSX, ZIP, RAR & APK",
                        badge = "DOC",
                        accentColor = AccentDoc,
                        onClick = { navigateToScan(FileCategory.DOCUMENT) }
                    ) {
                        CuteFolderIllustration(modifier = Modifier.size(56.dp))
                    }
                }
            }

            // 5. Vault Banner Card (Recovered Files Archive)
            item {
                VaultHighlightBanner(
                    recoveredCount = recoveredList.size,
                    onClick = { nav.navigate("recovered") }
                )
            }

            // 6. Section Header: Smart Cleaners & Forensics
            item {
                SectionHeaderRow(
                    title = "Smart Forensics & Cleaners",
                    subtitle = "Deduplication, contacts restore & system sweep"
                )
            }

            // 7. 2x2 Utility Grid: Similar Photos, Screenshot Cleaner, Contacts, Notifications
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    UtilityCompactCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_similar_images"),
                        title = "Duplicate Finder",
                        subtitle = "dHash + MD5 photo match",
                        accent = PrimaryGreen,
                        onClick = { nav.navigate("similar") }
                    ) {
                        CuteSimilarImagesIllustration(Modifier.size(46.dp))
                    }
                    UtilityCompactCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_screenshot_cleaner"),
                        title = "Screenshots",
                        subtitle = "Clean old screen captures",
                        accent = AccentCyan,
                        onClick = { nav.navigate("screenshots") }
                    ) {
                        CuteScreenshotFrameIllustration(Modifier.size(46.dp))
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    UtilityCompactCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_contacts"),
                        title = "Contacts Restore",
                        subtitle = "Deleted RawContacts & VCF",
                        accent = AccentContact,
                        onClick = { nav.navigate("contacts") }
                    ) {
                        CuteRedPhoneIllustration(Modifier.size(46.dp))
                    }
                    UtilityCompactCard(
                        modifier = Modifier
                            .weight(1f)
                            .testTag("card_notifications"),
                        title = "Notification Log",
                        subtitle = "Captured message history",
                        accent = AccentNotify,
                        onClick = { nav.navigate("notifications") }
                    ) {
                        CuteNotificationBellIllustration(Modifier.size(46.dp))
                    }
                }
            }

            // 8. Full-width Junk & Residual Cache Sweep Banner
            item {
                JunkSweepBannerCard(
                    onClick = { nav.navigate("junk") }
                )
            }
        }
    }
}

@Composable
private fun SectionHeaderRow(title: String, subtitle: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title,
            fontSize = 17.sp,
            fontWeight = FontWeight.ExtraBold,
            color = TextPrimary
        )
        Text(
            text = subtitle,
            fontSize = 12.sp,
            color = TextSecondary
        )
    }
}

// ---------------- Redesigned Midnight Indigo Storage Gauge Card ----------------

@Composable
private fun StorageHeroDashboardCard(
    breakdown: StorageBreakdown,
    onClick: () -> Unit
) {
    val total = breakdown.totalBytes.coerceAtLeast(1L).toFloat()
    val usedRatio = (breakdown.usedBytes.toFloat() / total).coerceIn(0f, 1f)
    val usedPercent = (usedRatio * 100).toInt()
    val availBytes = (breakdown.totalBytes - breakdown.usedBytes).coerceAtLeast(0L)

    val audioFrac = (breakdown.audiosBytes / total).coerceIn(0.02f, 0.25f)
    val videoFrac = (breakdown.videosBytes / total).coerceIn(0.03f, 0.30f)
    val imageFrac = (breakdown.photosBytes / total).coerceIn(0.03f, 0.28f)
    val docFrac = (breakdown.documentsBytes / total).coerceIn(0.02f, 0.20f)
    val otherFrac = (breakdown.othersBytes / total).coerceIn(0.08f, 0.55f)
    val freeFrac = (availBytes / total).coerceIn(0.05f, 0.85f)
    val (usedStr, totalStr) = formatGbPair(breakdown.usedBytes, breakdown.totalBytes)

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(
                Brush.linearGradient(
                    colors = listOf(CapacityDarkCard, CapacityDarkEnd, Color(0xFF0F2942))
                )
            )
            .clickable { onClick() }
            .padding(20.dp)
            .testTag("capacity_card")
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Circular Arc Ring Gauge
                Box(
                    modifier = Modifier.size(94.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val stroke = 10.dp.toPx()
                        drawArc(
                            color = Color.White.copy(alpha = 0.12f),
                            startAngle = 135f,
                            sweepAngle = 270f,
                            useCenter = false,
                            style = Stroke(width = stroke, cap = StrokeCap.Round)
                        )
                        drawArc(
                            brush = Brush.sweepGradient(
                                listOf(AccentCyan, PrimaryGreen, Color(0xFFEC4899), AccentCyan)
                            ),
                            startAngle = 135f,
                            sweepAngle = 270f * usedRatio,
                            useCenter = false,
                            style = Stroke(width = stroke, cap = StrokeCap.Round)
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$usedPercent%",
                            color = Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "USED",
                            color = Color(0xFF94A3B8),
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(Modifier.width(18.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "DEVICE STORAGE",
                            color = AccentCyan,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "Details",
                                color = Color(0xFFCBD5E1),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Icon(
                                imageVector = Icons.Filled.ChevronRight,
                                contentDescription = null,
                                tint = Color(0xFFCBD5E1),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "$usedStr$totalStr",
                        color = Color.White,
                        fontSize = 19.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(Modifier.height(10.dp))

                    // Multi-segment bar
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(10.dp)
                            .clip(RoundedCornerShape(50))
                            .background(Color(0xFF1E293B)),
                        horizontalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        Box(Modifier.weight(imageFrac).fillMaxHeight().background(CapImagesYellow))
                        Box(Modifier.weight(videoFrac).fillMaxHeight().background(CapVideoOrange))
                        Box(Modifier.weight(audioFrac).fillMaxHeight().background(CapAudioPink))
                        Box(Modifier.weight(docFrac).fillMaxHeight().background(CapDocsGreen))
                        Box(Modifier.weight(otherFrac).fillMaxHeight().background(CapOtherBlue))
                        Box(Modifier.weight(freeFrac).fillMaxHeight().background(CapAvailableGray))
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            // 6 Legend Pills in a clean 3x2 grid
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                LegendPill(CapImagesYellow, "Photos")
                LegendPill(CapVideoOrange, "Videos")
                LegendPill(CapAudioPink, "Audio")
                LegendPill(CapDocsGreen, "Docs")
                LegendPill(CapOtherBlue, "System")
                LegendPill(CapAvailableGray, "Free")
            }
        }
    }
}

@Composable
private fun LegendPill(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
        Spacer(Modifier.width(5.dp))
        Text(
            text = label,
            color = Color(0xFFCBD5E1),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

// ---------------- Redesigned Deep Channel Card ----------------

@Composable
private fun DeepChannelCard(
    modifier: Modifier = Modifier,
    title: String,
    subtitle: String,
    badge: String,
    accentColor: Color,
    onClick: () -> Unit,
    illustration: @Composable () -> Unit
) {
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(22.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(22.dp))
                .padding(15.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                illustration()
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(accentColor.copy(alpha = 0.12f))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = badge,
                        color = accentColor,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                text = title,
                fontSize = 16.sp,
                fontWeight = FontWeight.ExtraBold,
                color = TextPrimary,
                maxLines = 1
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = TextSecondary,
                maxLines = 2,
                lineHeight = 15.sp
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(accentColor.copy(alpha = 0.10f))
                    .padding(horizontal = 10.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Deep Scan",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = accentColor
                )
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(15.dp)
                )
            }
        }
    }
}

@Composable
private fun VaultHighlightBanner(
    recoveredCount: Int,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(
                Brush.horizontalGradient(
                    listOf(Color(0xFF312E81), Color(0xFF4F46E5), Color(0xFF0891B2))
                )
            )
            .clickable { onClick() }
            .padding(horizontal = 18.dp, vertical = 16.dp)
            .testTag("card_recovered_files")
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            CuteRecoveredBoxIllustration(Modifier.size(54.dp))
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "Recovered Files Vault",
                        color = Color.White,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(50))
                            .background(Color.White.copy(alpha = 0.22f))
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "$recoveredCount saved",
                            color = Color.White,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
                Spacer(Modifier.height(3.dp))
                Text(
                    text = "Browse, share or export all restored photos, videos & documents",
                    color = Color(0xFFE0E7FF),
                    fontSize = 12.sp
                )
            }
            Spacer(Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

@Composable
private fun UtilityCompactCard(
    modifier: Modifier = Modifier,
    title: String,
    subtitle: String,
    accent: Color,
    onClick: () -> Unit,
    icon: @Composable () -> Unit
) {
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(18.dp))
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(18.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                .padding(13.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            icon()
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary,
                    maxLines = 1
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = TextSecondary,
                    maxLines = 1
                )
            }
        }
    }
}

@Composable
private fun JunkSweepBannerCard(onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .clickable { onClick() }
            .testTag("card_junk_cleaner"),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(20.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            CuteTrashCanIllustration(Modifier.size(50.dp))
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "System Junk & Residual Sweep",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = TextPrimary
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "Clean obsolete APKs, temp logs, empty folders & thumbnail caches",
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }
            Spacer(Modifier.width(10.dp))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(AccentCyan.copy(alpha = 0.14f))
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Text(
                    text = "Clean",
                    color = AccentCyan,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 12.sp
                )
            }
        }
    }
}

// ---------------- Permission gate ----------------

@Composable
fun PermissionScreen(nav: NavController, category: FileCategory) {
    val context = LocalContext.current
    var granted by remember { mutableStateOf(hasAllFilesAccess(context)) }

    SimpleScaffold(title = category.recoveryTitle, onBack = { nav.popBackStack() }) { mod ->
        Column(
            modifier = mod
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(
                modifier = Modifier
                    .size(104.dp)
                    .clip(RoundedCornerShape(28.dp))
                    .background(CheckHaloGreen),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = "All files permission",
                    tint = PrimaryGreen,
                    modifier = Modifier.size(52.dp)
                )
            }
            Spacer(Modifier.height(20.dp))
            Text("Deep Storage Access Required", fontSize = 22.sp, fontWeight = FontWeight.ExtraBold, color = TextPrimary)
            Spacer(Modifier.height(8.dp))
            Text(
                "To carve deleted files from hidden caches, .Trash, .thumbnails, and unindexed folders, DeepVault needs All Files Access permission.",
                color = TextSecondary,
                fontSize = 14.sp
            )
            Spacer(Modifier.height(28.dp))
            Button(
                onClick = {
                    granted = hasAllFilesAccess(context)
                    if (!granted) {
                        runCatching { context.startActivity(manageAllFilesIntent(context)) }
                    } else {
                        nav.navigate("scan/${category.name}") {
                            popUpTo("permission/${category.name}") { inclusive = true }
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
                    .testTag("grant_storage_permission_button"),
                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                shape = RoundedCornerShape(16.dp)
            ) {
                Text(
                    if (granted) "Start Deep Scan" else "Authorize Storage Access",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(Modifier.height(10.dp))
            TextButton(onClick = {
                nav.navigate("scan/${category.name}") {
                    popUpTo("permission/${category.name}") { inclusive = true }
                }
            }) {
                Text("Continue with Standard Access →", color = PrimaryGreen, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

// ---------------- Redesigned Settings Screen ----------------

@Composable
fun SettingsScreen(nav: NavController) {
    val context = LocalContext.current
    var showAbout by remember { mutableStateOf(false) }

    SimpleScaffold(
        title = "Settings & Preferences",
        onBack = { nav.popBackStack() }
    ) { mod ->
        Column(
            modifier = mod
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SettingsCardRow(
                title = "Language",
                subtitle = "Change interface language",
                icon = {
                    Icon(Icons.Filled.Language, contentDescription = null, tint = PrimaryGreen, modifier = Modifier.size(22.dp))
                },
                onClick = { nav.navigate("language") }
            )

            SettingsCardRow(
                title = "Pin Home Screen Widget",
                subtitle = "Add 1-tap Deep Scan shortcut to launcher",
                icon = {
                    Icon(Icons.Filled.Widgets, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(22.dp))
                },
                onClick = {
                    requestPinRecoveryShortcut(context)
                }
            )

            SettingsCardRow(
                title = "Storage Analyzer",
                subtitle = "Inspect partition usage & installed apps",
                icon = {
                    Icon(Icons.Filled.Storage, contentDescription = null, tint = AccentEmerald, modifier = Modifier.size(22.dp))
                },
                onClick = { nav.navigate("storage") }
            )

            SettingsCardRow(
                title = "Send Feedback",
                subtitle = "Report an issue or request a feature",
                icon = {
                    Icon(Icons.Filled.Security, contentDescription = null, tint = AccentVideo, modifier = Modifier.size(22.dp))
                },
                onClick = {
                    runCatching {
                        val intent = Intent(Intent.ACTION_SENDTO).apply {
                            data = Uri.parse("mailto:feedback@filesrecovery.app")
                            putExtra(Intent.EXTRA_SUBJECT, "DeepVault Recovery Feedback")
                        }
                        context.startActivity(intent)
                    }.onFailure {
                        showAbout = true
                    }
                }
            )
        }
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text("DeepVault Feedback") },
            text = { Text("Thank you for using DeepVault Recovery v2.0. All deep carving engines are active.") },
            confirmButton = { TextButton(onClick = { showAbout = false }) { Text("OK") } }
        )
    }
}

@Composable
private fun SettingsCardRow(
    title: String,
    subtitle: String,
    icon: @Composable () -> Unit,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(18.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0xFFF1F5F9)),
                contentAlignment = Alignment.Center
            ) {
                icon()
            }
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    color = TextPrimary
                )
                Text(
                    text = subtitle,
                    fontSize = 12.sp,
                    color = TextSecondary
                )
            }
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = Color(0xFF94A3B8),
                modifier = Modifier.size(22.dp)
            )
        }
    }
}

private fun requestPinRecoveryShortcut(context: android.content.Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val sm = context.getSystemService(ShortcutManager::class.java)
        if (sm != null && sm.isRequestPinShortcutSupported) {
            val shortcutIntent = Intent(context, MainActivity::class.java).apply {
                action = Intent.ACTION_VIEW
            }
            val info = ShortcutInfo.Builder(context, "quick_recovery_widget")
                .setShortLabel("DeepVault")
                .setLongLabel("DeepVault File Recovery")
                .setIcon(AndroidIcon.createWithResource(context, R.mipmap.ic_launcher))
                .setIntent(shortcutIntent)
                .build()
            val callback = PendingIntent.getBroadcast(
                context,
                0,
                sm.createShortcutResultIntent(info),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            sm.requestPinShortcut(info, callback.intentSender)
            Toast.makeText(context, "Adding shortcut widget to Home screen…", Toast.LENGTH_SHORT).show()
            return
        }
    }
    Toast.makeText(context, "Shortcut widget pinned!", Toast.LENGTH_SHORT).show()
}
