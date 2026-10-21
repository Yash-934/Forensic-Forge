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
import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FolderShared
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material.icons.outlined.AutoAwesome
import androidx.compose.material.icons.outlined.FolderSpecial
import androidx.compose.material.icons.outlined.RestoreFromTrash
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
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
import com.clone.filesrecovery.forensics.CapabilityAvailability
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessment
import com.clone.filesrecovery.forensics.DeviceRootState
import com.clone.filesrecovery.forensics.OperatingMode
import com.clone.filesrecovery.forensics.RecoveryMethodCapability

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

// ---------------- Redesigned DeepVault Studio with Material 3 Bottom Menu ----------------

enum class MainTab(
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
) {
    RECOVERY(
        label = "Recovery",
        selectedIcon = Icons.Filled.RestoreFromTrash,
        unselectedIcon = Icons.Outlined.RestoreFromTrash,
        testTag = "bottom_nav_recovery"
    ),
    FORENSICS(
        label = "Forensics",
        selectedIcon = Icons.Filled.Security,
        unselectedIcon = Icons.Outlined.Security,
        testTag = "bottom_nav_forensics"
    ),
    CLEANERS(
        label = "Cleaners",
        selectedIcon = Icons.Filled.AutoAwesome,
        unselectedIcon = Icons.Outlined.AutoAwesome,
        testTag = "bottom_nav_cleaners"
    ),
    TOOLS(
        label = "Vault & Tools",
        selectedIcon = Icons.Filled.FolderSpecial,
        unselectedIcon = Icons.Outlined.FolderSpecial,
        testTag = "bottom_nav_tools"
    )
}

@Composable
fun HomeScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val breakdown by vm.storageBreakdown.collectAsState()
    val recoveredList by vm.recovered.collectAsState()
    val envAssessment by vm.environmentAssessment.collectAsState()
    var currentTab by rememberSaveable { mutableStateOf(MainTab.RECOVERY) }

    LaunchedEffect(Unit) {
        vm.refreshEnvironmentAssessment()
        vm.refreshStorageBreakdown()
    }

    if (currentTab != MainTab.RECOVERY) {
        BackHandler { currentTab = MainTab.RECOVERY }
    }

    fun navigateToScan(cat: FileCategory) {
        if (hasAllFilesAccess(context)) {
            nav.navigate("scan/${cat.name}")
        } else {
            nav.navigate("permission/${cat.name}")
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        bottomBar = {
            Surface(
                color = Color.White,
                shadowElevation = 8.dp,
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                NavigationBar(
                    containerColor = Color.White,
                    tonalElevation = 0.dp,
                    windowInsets = WindowInsets(0, 0, 0, 0),
                    modifier = Modifier.navigationBarsPadding()
                ) {
                    MainTab.entries.forEach { tab ->
                        val selected = currentTab == tab
                        NavigationBarItem(
                            selected = selected,
                            onClick = { currentTab = tab },
                            icon = {
                                Icon(
                                    imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                    contentDescription = tab.label,
                                    modifier = Modifier.size(24.dp)
                                )
                            },
                            label = {
                                Text(
                                    text = tab.label,
                                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                                    fontSize = 11.sp
                                )
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = PrimaryGreen,
                                selectedTextColor = PrimaryGreen,
                                indicatorColor = Color(0xFFEEF2FF),
                                unselectedIconColor = TextSecondary,
                                unselectedTextColor = TextSecondary
                            ),
                            modifier = Modifier.testTag(tab.testTag)
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(BgLight)
                .padding(bottom = innerPadding.calculateBottomPadding())
        ) {
            Crossfade(targetState = currentTab, label = "tab_crossfade") { tab ->
                when (tab) {
                    MainTab.RECOVERY -> RecoveryTabContent(
                        nav = nav,
                        vm = vm,
                        envAssessment = envAssessment,
                        recoveredCount = recoveredList.size,
                        onNavigateToScan = { cat -> navigateToScan(cat) },
                        onSwitchTab = { target -> currentTab = target }
                    )
                    MainTab.FORENSICS -> ForensicsTabContent(
                        nav = nav,
                        vm = vm
                    )
                    MainTab.CLEANERS -> CleanersTabContent(
                        nav = nav,
                        vm = vm,
                        breakdown = breakdown
                    )
                    MainTab.TOOLS -> ToolsVaultTabContent(
                        nav = nav,
                        vm = vm,
                        recoveredCount = recoveredList.size
                    )
                }
            }
        }
    }
}

@Composable
private fun RecoveryTabContent(
    nav: NavController,
    vm: AppViewModel,
    envAssessment: DeviceEnvironmentAssessment,
    recoveredCount: Int,
    onNavigateToScan: (FileCategory) -> Unit,
    onSwitchTab: (MainTab) -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // Redesigned Top Bar for Recovery
        Surface(color = Color.White, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
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
                    Spacer(Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = "DeepVault",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.ExtraBold,
                                color = TextPrimary,
                                maxLines = 1
                            )
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(Color(0xFFE0E7FF))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = "PRO",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = PrimaryGreen,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        }
                        Text(
                            text = "Forensic Carving & Recovery",
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
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
            contentPadding = PaddingValues(top = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Adaptive Dual-Mode Root & Capability Status Card
            item {
                AdaptiveModeStatusCard(
                    assessment = envAssessment,
                    onViewCapabilities = { nav.navigate("capabilities") },
                    onVerifyRoot = { vm.requestRootModeVerification() },
                    onForceStandard = { vm.setForceStandardMode(true) }
                )
            }

            // Section Header: Deep Recovery Channels
            item {
                SectionHeaderRow(
                    title = "Deep Recovery Channels",
                    subtitle = "4-stage signature, trash & .thumbdata carving"
                )
            }

            // Row 1: Photo Recovery + Video Recovery
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
                        onClick = { onNavigateToScan(FileCategory.PHOTO) }
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
                        onClick = { onNavigateToScan(FileCategory.VIDEO) }
                    ) {
                        CuteVideoProjectorIllustration(modifier = Modifier.size(56.dp))
                    }
                }
            }

            // Row 2: Audio Recovery + Document Recovery
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
                        onClick = { onNavigateToScan(FileCategory.AUDIO) }
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
                        onClick = { onNavigateToScan(FileCategory.DOCUMENT) }
                    ) {
                        CuteFolderIllustration(modifier = Modifier.size(56.dp))
                    }
                }
            }

            // Vault Banner Card
            item {
                VaultHighlightBanner(
                    recoveredCount = recoveredCount,
                    onClick = { nav.navigate("recovered") }
                )
            }

            // Quick Nav Shortcuts
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Card(
                        modifier = Modifier
                            .weight(1f)
                            .height(64.dp)
                            .clickable { onSwitchTab(MainTab.FORENSICS) },
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(16.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxSize()
                                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(34.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFFEEF2FF)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Filled.Security, contentDescription = null, tint = PrimaryGreen, modifier = Modifier.size(18.dp))
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Forensics", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1)
                                Text("Labs & Reports →", fontSize = 10.sp, color = PrimaryGreen, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            }
                        }
                    }

                    Card(
                        modifier = Modifier
                            .weight(1f)
                            .height(64.dp)
                            .clickable { onSwitchTab(MainTab.CLEANERS) },
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(16.dp),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxSize()
                                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(34.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color(0xFFF0FDF4)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Filled.AutoAwesome, contentDescription = null, tint = AccentEmerald, modifier = Modifier.size(18.dp))
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Cleaners", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1)
                                Text("Radar & Sweep →", fontSize = 10.sp, color = AccentEmerald, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ForensicsTabContent(
    nav: NavController,
    vm: AppViewModel
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // Forensics Top Bar
        Surface(color = Color.White, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(13.dp))
                            .background(Brush.linearGradient(listOf(Color(0xFF0F172A), PrimaryGreen))),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Security,
                            contentDescription = null,
                            tint = AccentCyan,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "Forensics Suite",
                                fontSize = 21.sp,
                                fontWeight = FontWeight.ExtraBold,
                                color = TextPrimary
                            )
                            Spacer(Modifier.width(8.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(Color(0xFFDCFCE7))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = "100% LOCAL",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = AccentEmerald
                                )
                            }
                        }
                        Text(
                            text = "Deterministic On-Device Digital Forensics",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    }
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

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Storage Forensics Intelligence Hero Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { nav.navigate("storage_forensics") }
                        .testTag("card_storage_forensics_intelligence"),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.2.dp, PrimaryGreen.copy(alpha = 0.25f), RoundedCornerShape(20.dp))
                            .padding(18.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.weight(1f)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .clip(RoundedCornerShape(13.dp))
                                        .background(PrimaryGreen.copy(alpha = 0.12f)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Storage,
                                        contentDescription = "Storage Forensics",
                                        tint = PrimaryGreen,
                                        modifier = Modifier.size(24.dp)
                                    )
                                }
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "Storage Forensics",
                                            fontWeight = FontWeight.ExtraBold,
                                            fontSize = 15.sp,
                                            color = TextPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Spacer(Modifier.width(6.dp))
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(AccentEmerald.copy(alpha = 0.15f))
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                text = "NEW",
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = AccentEmerald,
                                                maxLines = 1,
                                                softWrap = false
                                            )
                                        }
                                    }
                                    Text(
                                        text = "Deterministic storage auditing & entropy analysis",
                                        fontSize = 11.sp,
                                        color = TextSecondary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            Icon(Icons.Filled.ChevronRight, contentDescription = null, tint = PrimaryGreen)
                        }

                        Spacer(Modifier.height(14.dp))

                        // Features chips: 2x2 grid so text never cramps or overflows
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ForensicFeaturePill("Scope Coverage", Modifier.weight(1f))
                                ForensicFeaturePill(".nomedia Audit", Modifier.weight(1f))
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ForensicFeaturePill("Entropy & FBE", Modifier.weight(1f))
                                ForensicFeaturePill("Signature Mismatches", Modifier.weight(1f))
                            }
                        }

                        Spacer(Modifier.height(14.dp))

                        Button(
                            onClick = { nav.navigate("storage_forensics") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(42.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Launch Storage Forensics Dashboard", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            // Forensic Lab & AI-Ready Reports Banner Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { nav.navigate("forensics") }
                        .testTag("card_forensic_lab"),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .clip(RoundedCornerShape(12.dp))
                                .background(AccentCyan.copy(alpha = 0.18f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = "Forensic Lab",
                                tint = AccentCyan,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "Forensic Lab & Reports",
                                    color = Color.White,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 14.sp,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                Spacer(Modifier.width(8.dp))
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(AccentEmerald.copy(alpha = 0.22f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = "OFFLINE",
                                        color = AccentEmerald,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        maxLines = 1,
                                        softWrap = false
                                    )
                                }
                            }
                            Spacer(Modifier.height(3.dp))
                            Text(
                                text = "Hashes • EXIF Metadata • Offline Export Bundles",
                                color = Color(0xFF94A3B8),
                                fontSize = 11.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                            contentDescription = "Open Forensic Lab",
                            tint = AccentCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            // Section Header: Specialized Labs & Custody
            item {
                SectionHeaderRow(
                    title = "Specialized Labs & Evidence",
                    subtitle = "Deep binary examination, repair & chain of custody"
                )
            }

            // Specialized Labs: Perfectly aligned full-width cards with icons, clear text & chevrons
            item {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ForensicSpecializedLabCard(
                        title = "Hex & SQLite Database Lab",
                        subtitle = "Deep binary inspector, file structure & SQLite table parser",
                        badge = "HEX",
                        accentColor = PrimaryGreen,
                        icon = Icons.Filled.Code,
                        testTag = "home_card_advanced_lab",
                        onClick = { nav.navigate("advanced_forensics_lab") }
                    )

                    ForensicSpecializedLabCard(
                        title = "Corrupted File Repair Lab",
                        subtitle = "Header reconstruction & safe EOI / IEND validation",
                        badge = "REPAIR",
                        accentColor = SelectionOrange,
                        icon = Icons.Filled.Build,
                        testTag = "home_card_repair_lab",
                        onClick = { nav.navigate("file_repair_lab") }
                    )

                    ForensicSpecializedLabCard(
                        title = "Forensic Cases & Chain of Custody",
                        subtitle = "Case dossier management, hash timelines & evidence verification",
                        badge = "CUSTODY",
                        accentColor = AccentEmerald,
                        icon = Icons.Filled.FolderShared,
                        testTag = "home_card_case_manager",
                        onClick = { nav.navigate("case_manager") }
                    )
                }
            }

            // Zero-Cloud Integrity Statement
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF1F5F9))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Security,
                            contentDescription = null,
                            tint = PrimaryGreen,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = "Zero-Cloud Guarantee: DeepVault operates 100% deterministically on-device. No telemetry, cloud sync, or external AI connections.",
                            fontSize = 11.sp,
                            color = TextSecondary,
                            lineHeight = 16.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ForensicFeaturePill(text: String, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(Color(0xFFF1F5F9))
            .padding(vertical = 8.dp, horizontal = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun ForensicSpecializedLabCard(
    title: String,
    subtitle: String,
    badge: String,
    accentColor: Color,
    icon: ImageVector,
    testTag: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(testTag),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(accentColor.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = accentColor,
                    modifier = Modifier.size(22.dp)
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = title,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 13.sp,
                        color = TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(accentColor.copy(alpha = 0.15f))
                            .padding(horizontal = 5.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = badge,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = accentColor,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }
                Spacer(Modifier.height(3.dp))
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = Color(0xFF94A3B8),
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

@Composable
private fun CleanersTabContent(
    nav: NavController,
    vm: AppViewModel,
    breakdown: StorageBreakdown
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // Cleaners Top Bar
        Surface(color = Color.White, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(13.dp))
                            .background(Brush.linearGradient(listOf(AccentCyan, AccentEmerald))),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.AutoAwesome,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "Storage & Cleaners",
                            fontSize = 21.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Storage Breakdown & Smart System Sweep",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    }
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

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Storage Radar & Breakdown Card
            item {
                StorageHeroDashboardCard(
                    breakdown = breakdown,
                    onClick = { nav.navigate("storage_forensics") }
                )
            }

            // Junk & Residual Sweep Banner Card
            item {
                JunkSweepBannerCard(
                    onClick = { nav.navigate("junk") }
                )
            }

            // Section Header: Smart Cleaners & Deduplication
            item {
                SectionHeaderRow(
                    title = "Smart Cleaners & Deduplication",
                    subtitle = "Perceptual hashing & storage hygiene"
                )
            }

            // 2x1 Utility Grid: Duplicate Finder & Screenshots
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

            // Deep Folder Breakdown Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { nav.navigate("folders") },
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CuteFolderIllustration(Modifier.size(46.dp))
                        Spacer(Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Directory & Folder Breakdown",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = "Inspect heavy directories, caches & download folders",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                        Icon(
                            imageVector = Icons.Filled.ChevronRight,
                            contentDescription = null,
                            tint = PrimaryGreen
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ToolsVaultTabContent(
    nav: NavController,
    vm: AppViewModel,
    recoveredCount: Int
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // Tools & Vault Top Bar
        Surface(color = Color.White, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(RoundedCornerShape(13.dp))
                            .background(Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFF8B5CF6)))),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.FolderSpecial,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "Vault & Utilities",
                            fontSize = 21.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Restored Artifacts, System Logs & Device Audit",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    }
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

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Recovered Files Vault Hero Banner
            item {
                VaultHighlightBanner(
                    recoveredCount = recoveredCount,
                    onClick = { nav.navigate("recovered") }
                )
            }

            // Section Header: Communication & System Recovery
            item {
                SectionHeaderRow(
                    title = "System Recovery & Logs",
                    subtitle = "Deleted contacts & captured notification history"
                )
            }

            // Row: Contacts Restore + Notification Log
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

            // Section Header: Device Environment & Configuration
            item {
                SectionHeaderRow(
                    title = "Device Environment & Configuration",
                    subtitle = "Root privileges, capabilities & app preferences"
                )
            }

            // Capabilities Card
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { nav.navigate("capabilities") },
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(18.dp))
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(46.dp)
                                .clip(RoundedCornerShape(14.dp))
                                .background(Color(0xFFEEF2FF)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = PrimaryGreen,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        Spacer(Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Device Capabilities & Root Audit",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = "Audit root privileges, SELinux status, and recovery methods",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                        Icon(
                            imageVector = Icons.Filled.ChevronRight,
                            contentDescription = null,
                            tint = PrimaryGreen
                        )
                    }
                }
            }

            // Settings & Language Row
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Card(
                        modifier = Modifier
                            .weight(1f)
                            .clickable { nav.navigate("language") },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Filled.Language, contentDescription = null, tint = PrimaryGreen, modifier = Modifier.size(22.dp))
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text("Language", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                                Text("English, etc.", fontSize = 11.sp, color = TextSecondary)
                            }
                        }
                    }

                    Card(
                        modifier = Modifier
                            .weight(1f)
                            .clickable { nav.navigate("settings") },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Filled.Settings, contentDescription = null, tint = TextPrimary, modifier = Modifier.size(22.dp))
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text("Settings", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                                Text("Vault & Theme", fontSize = 11.sp, color = TextSecondary)
                            }
                        }
                    }
                }
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
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Recovered Vault",
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.ExtraBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(50))
                            .background(Color.White.copy(alpha = 0.25f))
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "$recoveredCount items",
                            color = Color.White,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }
                Spacer(Modifier.height(3.dp))
                Text(
                    text = "Browse, share or export restored evidence",
                    color = Color(0xFFE0E7FF),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
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
                title = "Operating Mode & Capabilities",
                subtitle = "Inspect Standard vs Root-Enabled mode & forensic limits",
                icon = {
                    Icon(Icons.Filled.Security, contentDescription = null, tint = PrimaryGreen, modifier = Modifier.size(22.dp))
                },
                onClick = { nav.navigate("capabilities") }
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

// ---------------- Adaptive Dual-Mode Status Card & Capabilities Screen ----------------

@Composable
fun AdaptiveModeStatusCard(
    assessment: DeviceEnvironmentAssessment,
    onViewCapabilities: () -> Unit,
    onVerifyRoot: () -> Unit,
    onForceStandard: () -> Unit
) {
    val isRootActive = assessment.activeOperatingMode == OperatingMode.ROOT_ENABLED
    val accentColor = when (assessment.rootState) {
        DeviceRootState.NON_ROOTED -> PrimaryGreen
        DeviceRootState.ROOT_DETECTED_NOT_GRANTED -> Color(0xFFF59E0B)
        DeviceRootState.ROOT_ACCESS_DENIED -> CoralRed
        DeviceRootState.ROOT_ENABLED -> AccentEmerald
        DeviceRootState.ROOT_RESTRICTED -> AccentCyan
        DeviceRootState.ROOT_STATUS_UNKNOWN -> TextSecondary
    }

    val availableSummary = remember(assessment.availableMethods) {
        if (assessment.availableMethods.isEmpty()) {
            "Standard Android MediaStore & accessible storage"
        } else {
            val names = assessment.availableMethods.take(3).joinToString(", ") { it.title }
            val extra = (assessment.availableMethods.size - 3).coerceAtLeast(0)
            if (extra > 0) "$names (+$extra more)" else names
        }
    }

    val restrictedSummary = remember(assessment.restrictedCapabilities) {
        if (assessment.restrictedCapabilities.isEmpty()) {
            "Hardware FBE evicted keys & TRIMmed flash blocks"
        } else {
            assessment.restrictedCapabilities.joinToString(", ") { it.title }
        }
    }

    var isExpanded by rememberSaveable { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("root_status_card"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, accentColor.copy(alpha = 0.28f), RoundedCornerShape(16.dp))
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            // Header Row: Status dot, Title, Badge, and Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(accentColor)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = assessment.cardTitle,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = accentColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .weight(1f, fill = false)
                            .testTag("root_status_card_title")
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (isRootActive) {
                        OutlinedButton(
                            onClick = onForceStandard,
                            modifier = Modifier
                                .height(26.dp)
                                .testTag("switch_standard_mode_button"),
                            shape = RoundedCornerShape(6.dp),
                            contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp)
                        ) {
                            Text(
                                text = "STANDARD",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextSecondary
                            )
                        }
                        Spacer(Modifier.width(4.dp))
                    }
                    IconButton(
                        onClick = { isExpanded = !isExpanded },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = "Toggle Details",
                            tint = TextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }

            // Row 2: Status line + Capabilities button
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = assessment.cardStatusLine,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("root_status_line")
                )
                Spacer(Modifier.width(8.dp))
                TextButton(
                    onClick = onViewCapabilities,
                    modifier = Modifier
                        .height(28.dp)
                        .testTag("view_capabilities_button"),
                    contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp)
                ) {
                    Text(
                        text = "Capabilities →",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = PrimaryGreen
                    )
                }
            }

            // 3 Compact Status Badges
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                StatusCompactBadge(
                    label = if (isRootActive) "Root: Active" else "Root: None",
                    color = if (isRootActive) AccentEmerald else TextSecondary,
                    modifier = Modifier.weight(1f)
                )
                StatusCompactBadge(
                    label = if (assessment.hasStorageAccess) "Access: Granted" else "Access: Standard",
                    color = if (assessment.hasStorageAccess) AccentEmerald else Color(0xFFF59E0B),
                    modifier = Modifier.weight(1f)
                )
                StatusCompactBadge(
                    label = "${assessment.availableMethods.size} Methods",
                    color = PrimaryGreen,
                    modifier = Modifier.weight(1f)
                )
            }

            // If root detected but not granted, show quick action right away
            if (assessment.rootState == DeviceRootState.ROOT_DETECTED_NOT_GRANTED) {
                Button(
                    onClick = onVerifyRoot,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(34.dp)
                        .testTag("verify_root_button"),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF59E0B)),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text("Grant Root Permissions", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            // Expanded details section (collapsible to save space)
            if (isExpanded) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = assessment.cardDescription,
                    fontSize = 11.sp,
                    color = TextSecondary,
                    lineHeight = 15.sp
                )

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFFF8FAFC))
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                        .padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    StatusKeyValueLine("Device root status", assessment.deviceRootStatusLabel)
                    StatusKeyValueLine("Storage access", assessment.storageAccessStatusLabel)
                    StatusKeyValueLine("Recovery mode", assessment.recoveryModeLabel)
                    StatusKeyValueLine("Available recovery methods", availableSummary)
                    StatusKeyValueLine("Restricted capabilities", restrictedSummary)
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onViewCapabilities,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(36.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(0.dp)
                    ) {
                        Text(
                            text = "FULL CAPABILITIES AUDIT",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusKeyValueLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = "• $label: ",
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary
        )
        Text(
            text = value,
            fontSize = 11.sp,
            color = TextSecondary,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun StatusCompactBadge(label: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.08f))
            .padding(vertical = 4.dp, horizontal = 4.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            color = color,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun CapabilitiesScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val assessment by vm.environmentAssessment.collectAsState()
    val isAssessing by vm.isAssessingEnvironment.collectAsState()
    val forceStandard by vm.forceStandardMode.collectAsState()

    SimpleScaffold(
        title = "Operating Mode & Capabilities",
        onBack = { nav.popBackStack() }
    ) { mod ->
        LazyColumn(
            modifier = mod
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
                ) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = assessment.cardTitle,
                            color = AccentCyan,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = assessment.cardStatusLine,
                            color = Color.White,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = assessment.cardDescription,
                            color = Color(0xFFCBD5E1),
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )
                        Spacer(Modifier.height(4.dp))
                        EnvironmentSpecLine("Device / OS", "${assessment.deviceModel} (Android ${assessment.androidRelease}, SDK ${assessment.sdkInt})")
                        EnvironmentSpecLine("Root Status", assessment.deviceRootStatusLabel)
                        EnvironmentSpecLine("Active Recovery Mode", assessment.recoveryModeLabel)
                        EnvironmentSpecLine("Storage Access", assessment.storageAccessStatusLabel)
                        EnvironmentSpecLine("SELinux Mode", assessment.selinuxMode)
                        EnvironmentSpecLine("Storage Encryption", assessment.encryptionState)
                        EnvironmentSpecLine("Raw Block Access", assessment.rawBlockAccessStatus)

                        Spacer(Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { vm.refreshEnvironmentAssessment() },
                                enabled = !isAssessing,
                                colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("reassess_environment_button")
                            ) {
                                Text(if (isAssessing) "Assessing…" else "Re-Assess Device", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                            if (!assessment.rootShellVerifiedUid0) {
                                OutlinedButton(
                                    onClick = { vm.requestRootModeVerification() },
                                    enabled = !isAssessing,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("probe_root_shell_button")
                                ) {
                                    Text("Check Root (su)", color = AccentCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }

                        if (!assessment.hasStorageAccess) {
                            Button(
                                onClick = {
                                    runCatching { context.startActivity(manageAllFilesIntent(context)) }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = AccentEmerald),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Grant All Files Access Permission", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Force Standard Mode safe switch
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Lock Standard Non-Root Mode",
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = TextPrimary
                            )
                            Text(
                                text = "Always use standard Android storage APIs even if root indicators are present",
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        }
                        Switch(
                            checked = forceStandard,
                            onCheckedChange = { vm.setForceStandardMode(it) },
                            modifier = Modifier.testTag("lock_standard_mode_switch")
                        )
                    }
                }
            }

            // Available Recovery Methods
            item {
                SectionHeaderRow(
                    title = "Available Recovery Methods (${assessment.availableMethods.size})",
                    subtitle = "Dynamically verified capabilities active on this device"
                )
            }

            items(assessment.availableMethods, key = { it.id }) { cap ->
                CapabilityItemCard(cap)
            }

            // Restricted Capabilities
            item {
                SectionHeaderRow(
                    title = "Restricted Capabilities (${assessment.restrictedCapabilities.size})",
                    subtitle = "Capabilities unavailable in current mode or blocked by OS security"
                )
            }

            items(assessment.restrictedCapabilities, key = { it.id }) { cap ->
                CapabilityItemCard(cap)
            }

            // Honest Forensic & Encryption Disclosures
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFFFBEB))
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFFFDE68A), RoundedCornerShape(18.dp))
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "Forensic Reality & Platform Constraints",
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 14.sp,
                            color = Color(0xFF92400E)
                        )
                        assessment.forensicLimitationsNotes.forEach { note ->
                            Text(
                                text = "• $note",
                                fontSize = 12.sp,
                                color = Color(0xFF78350F),
                                lineHeight = 16.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EnvironmentSpecLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            color = Color(0xFF94A3B8),
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(0.42f)
        )
        Text(
            text = value,
            color = Color.White,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.weight(0.58f)
        )
    }
}

@Composable
private fun CapabilityItemCard(cap: RecoveryMethodCapability) {
    val badgeColor = when (cap.availability) {
        CapabilityAvailability.AVAILABLE -> AccentEmerald
        CapabilityAvailability.LIMITED -> Color(0xFFF59E0B)
        CapabilityAvailability.RESTRICTED -> CoralRed
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = cap.title,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = TextPrimary,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(badgeColor.copy(alpha = 0.14f))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = cap.availability.label.uppercase(),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = badgeColor
                    )
                }
            }
            Text(
                text = cap.description,
                fontSize = 12.sp,
                color = TextSecondary,
                lineHeight = 16.sp
            )
            Text(
                text = "Status: ${cap.statusReason}",
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = badgeColor
            )
        }
    }
}

