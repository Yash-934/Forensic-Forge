package com.clone.filesrecovery.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.data.ContactsHelper
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.FileScanner
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.SimilarImageGroup
import com.clone.filesrecovery.data.formatDate
import com.clone.filesrecovery.data.formatSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ---------------- Similar Images Screen ----------------

@Composable
fun SimilarImagesScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var scanning by remember { mutableStateOf(true) }
    var groups by remember { mutableStateOf<List<SimilarImageGroup>>(emptyList()) }
    var selectedPaths by remember { mutableStateOf<Set<String>>(emptySet()) }

    LaunchedEffect(Unit) {
        scanning = true
        val found = FileScanner.findSimilarImages(context)
        groups = found
        // Auto-select all except the first photo in each duplicate group
        selectedPaths = found.flatMap { it.files.drop(1).map { f -> f.path } }.toSet()
        scanning = false
    }

    SimpleScaffold(
        title = "Similar Images",
        onBack = { nav.popBackStack() },
        warmBackground = true,
        bottomBar = {
            if (selectedPaths.isNotEmpty()) {
                val totalBytes = groups.flatMap { it.files }
                    .filter { selectedPaths.contains(it.path) }
                    .sumOf { it.size }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White)
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Button(
                        onClick = {
                            scope.launch {
                                var deleted = 0
                                withContext(Dispatchers.IO) {
                                    selectedPaths.forEach { p ->
                                        if (FileScanner.deleteWithUnoverwrittenRetention(context, File(p))) deleted++
                                    }
                                }
                                Toast.makeText(context, "Cleaned $deleted duplicate photos", Toast.LENGTH_SHORT).show()
                                val updated = FileScanner.findSimilarImages(context)
                                groups = updated
                                selectedPaths = emptySet()
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            "Clean (${selectedPaths.size} • ${formatSize(totalBytes)})",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    ) { mod ->
        if (scanning) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator(color = PrimaryGreen, modifier = Modifier.size(56.dp))
                Spacer(Modifier.height(16.dp))
                Text("Analyzing similar & duplicate photos…", fontWeight = FontWeight.Bold, fontSize = 17.sp)
            }
        } else if (groups.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CuteSimilarImagesIllustration(Modifier.size(110.dp))
                Spacer(Modifier.height(16.dp))
                Text("No duplicate or similar photos found", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text("Your gallery has no redundant copies.", color = Color(0xFF7A7F87), fontSize = 14.sp)
            }
        } else {
            LazyColumn(
                mod.fillMaxSize().padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(vertical = 12.dp)
            ) {
                items(groups, key = { it.id }) { group ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                        shape = RoundedCornerShape(18.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "${group.title} (${group.files.size})",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 15.sp
                                )
                                Text(
                                    formatSize(group.files.sumOf { it.size }),
                                    color = Color(0xFF7A7F87),
                                    fontSize = 13.sp
                                )
                            }
                            Spacer(Modifier.height(10.dp))
                            val rows = group.files.chunked(3)
                            rows.forEach { rowFiles ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    rowFiles.forEach { file ->
                                        val isChecked = selectedPaths.contains(file.path)
                                        Box(
                                            modifier = Modifier
                                                .weight(1f)
                                                .aspectRatio(1f)
                                                .clip(RoundedCornerShape(12.dp))
                                                .clickable {
                                                    vm.currentFile = file
                                                    nav.navigate("detail")
                                                }
                                        ) {
                                            FileThumb(file, Modifier.fillMaxSize())
                                            Box(
                                                modifier = Modifier
                                                    .align(Alignment.TopEnd)
                                                    .padding(6.dp)
                                            ) {
                                                RoundCheckButton(
                                                    checked = isChecked,
                                                    onToggle = {
                                                        selectedPaths = if (isChecked) {
                                                            selectedPaths - file.path
                                                        } else {
                                                            selectedPaths + file.path
                                                        }
                                                    },
                                                    size = 22.dp
                                                )
                                            }
                                        }
                                    }
                                    repeat(3 - rowFiles.size) {
                                        Spacer(Modifier.weight(1f))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Screenshot Cleaner Screen ----------------

@Composable
fun ScreenshotCleanerScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var scanning by remember { mutableStateOf(true) }
    var screenshots by remember { mutableStateOf<List<RecoverableFile>>(emptyList()) }
    var selectedPaths by remember { mutableStateOf<Set<String>>(emptySet()) }

    LaunchedEffect(Unit) {
        scanning = true
        val list = FileScanner.findScreenshots(context)
        screenshots = list
        selectedPaths = list.map { it.path }.toSet()
        scanning = false
    }

    val allSelected = screenshots.isNotEmpty() && screenshots.all { selectedPaths.contains(it.path) }

    SimpleScaffold(
        title = "Screenshot Cleaner",
        onBack = { nav.popBackStack() },
        warmBackground = true,
        bottomBar = {
            if (selectedPaths.isNotEmpty()) {
                val totalBytes = screenshots.filter { selectedPaths.contains(it.path) }.sumOf { it.size }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White)
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Button(
                        onClick = {
                            scope.launch {
                                var deleted = 0
                                withContext(Dispatchers.IO) {
                                    selectedPaths.forEach { p ->
                                        if (FileScanner.deleteWithUnoverwrittenRetention(context, File(p))) deleted++
                                    }
                                }
                                Toast.makeText(context, "Cleaned $deleted screenshots", Toast.LENGTH_SHORT).show()
                                screenshots = FileScanner.findScreenshots(context)
                                selectedPaths = emptySet()
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            "Clean (${selectedPaths.size} • ${formatSize(totalBytes)})",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    ) { mod ->
        if (scanning) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator(color = PrimaryGreen, modifier = Modifier.size(56.dp))
                Spacer(Modifier.height(16.dp))
                Text("Scanning screenshots…", fontWeight = FontWeight.Bold, fontSize = 17.sp)
            }
        } else if (screenshots.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CuteScreenshotFrameIllustration(Modifier.size(110.dp))
                Spacer(Modifier.height(14.dp))
                Text("No screenshots found", fontWeight = FontWeight.Bold, fontSize = 17.sp)
            }
        } else {
            Column(mod.fillMaxSize()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 18.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RoundCheckButton(
                        checked = allSelected,
                        onToggle = {
                            selectedPaths = if (allSelected) emptySet() else screenshots.map { it.path }.toSet()
                        }
                    )
                    Spacer(Modifier.width(12.dp))
                    Text("Select all (${screenshots.size})", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }

                val rows = screenshots.chunked(3)
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 14.dp),
                    contentPadding = PaddingValues(bottom = 24.dp)
                ) {
                    items(rows, key = { it.first().path }) { rowFiles ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            rowFiles.forEach { file ->
                                val isChecked = selectedPaths.contains(file.path)
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .aspectRatio(1f)
                                        .clip(RoundedCornerShape(12.dp))
                                        .clickable {
                                            vm.currentFile = file
                                            nav.navigate("detail")
                                        }
                                ) {
                                    FileThumb(file, Modifier.fillMaxSize())
                                    Box(
                                        modifier = Modifier
                                            .align(Alignment.TopEnd)
                                            .padding(6.dp)
                                    ) {
                                        RoundCheckButton(
                                            checked = isChecked,
                                            onToggle = {
                                                selectedPaths = if (isChecked) {
                                                    selectedPaths - file.path
                                                } else {
                                                    selectedPaths + file.path
                                                }
                                            },
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
                            repeat(3 - rowFiles.size) {
                                Spacer(Modifier.weight(1f))
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Contacts Recovery / Backup ----------------

@Composable
fun ContactsScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val contacts by vm.contacts.collectAsState()
    val scope = rememberCoroutineScope()
    var granted by remember {
        mutableStateOf(
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.READ_CONTACTS
            ) == PackageManager.PERMISSION_GRANTED
        )
    }
    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        granted = result[android.Manifest.permission.READ_CONTACTS] == true
        if (granted) vm.loadContacts()
    }
    val pickVcf = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                val count = ContactsHelper.importVcf(context, uri)
                Toast.makeText(context, "Restored $count contacts", Toast.LENGTH_LONG).show()
                vm.loadContacts()
            }
        }
    }
    LaunchedEffect(granted) { if (granted) vm.loadContacts() }

    SimpleScaffold(
        title = "Contacts Recovery",
        onBack = { nav.popBackStack() },
        warmBackground = true,
        bottomBar = {
            if (granted) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(Color.White)
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Button(
                        onClick = {
                            scope.launch {
                                val path = ContactsHelper.backupToDownloads(context, contacts)
                                Toast.makeText(
                                    context,
                                    if (path != null) "Backup saved: $path" else "Backup failed",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        },
                        modifier = Modifier
                            .weight(1f)
                            .height(52.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(50)
                    ) { Text("Backup (.vcf)", fontWeight = FontWeight.Bold) }
                    Button(
                        onClick = { pickVcf.launch(arrayOf("text/vcard", "text/x-vcard", "*/*")) },
                        modifier = Modifier
                            .weight(1f)
                            .height(52.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CapacityBlue),
                        shape = RoundedCornerShape(50)
                    ) { Text("Restore VCF", fontWeight = FontWeight.Bold) }
                }
            }
        }
    ) { mod ->
        if (!granted) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CuteRedPhoneIllustration(Modifier.size(96.dp))
                Spacer(Modifier.height(16.dp))
                Text("Contacts Permission Required", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Grant permission to scan for deleted RawContacts, VCF backups, and active contacts.",
                    color = Color(0xFF7A7F87),
                    fontSize = 14.sp
                )
                Spacer(Modifier.height(18.dp))
                Button(
                    onClick = {
                        permLauncher.launch(
                            arrayOf(
                                android.Manifest.permission.READ_CONTACTS,
                                android.Manifest.permission.WRITE_CONTACTS
                            )
                        )
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                    shape = RoundedCornerShape(50),
                    modifier = Modifier.fillMaxWidth().height(52.dp)
                ) { Text("Grant Permission", fontWeight = FontWeight.Bold) }
            }
        } else if (contacts.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                CuteRedPhoneIllustration(Modifier.size(96.dp))
                Spacer(Modifier.height(12.dp))
                Text("No contacts found", color = Color(0xFF7A7F87))
            }
        } else {
            LazyColumn(
                mod.fillMaxSize().padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(vertical = 12.dp)
            ) {
                items(contacts, key = { it.id }) { c ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            Modifier.padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(c.name, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                                    if (c.isDeletedOrBackup) {
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            text = c.sourceLabel,
                                            fontSize = 11.sp,
                                            color = CoralRed,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                }
                                c.phones.forEach { Text(it, color = Color(0xFF666B75), fontSize = 13.sp) }
                                c.emails.forEach { Text(it, color = Color(0xFF666B75), fontSize = 13.sp) }
                            }
                            if (c.isDeletedOrBackup) {
                                Button(
                                    onClick = {
                                        scope.launch {
                                            val ok = ContactsHelper.restoreContact(context, c)
                                            Toast.makeText(
                                                context,
                                                if (ok) "Recovered ${c.name}" else "Failed to restore",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                            vm.loadContacts()
                                        }
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text("Recover", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Notification Cleaner / Recovery ----------------

@Composable
fun NotificationsScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val notifications by vm.notifications.collectAsState()
    var tab by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        vm.loadNotifications()
    }

    val filtered = when (tab) {
        1 -> notifications.filter { it.isMedia }
        2 -> notifications.filter { !it.isMedia }
        else -> notifications
    }

    SimpleScaffold(
        title = "Notification & Chat Log",
        onBack = { nav.popBackStack() },
        warmBackground = true,
        actions = {
            if (notifications.isNotEmpty()) {
                IconButton(onClick = { vm.clearNotifications() }) {
                    Icon(Icons.Filled.Delete, contentDescription = "Clear all", tint = Color(0xFF222222))
                }
            }
        }
    ) { mod ->
        Column(mod.fillMaxSize()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color.White),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("System Notification History & Media", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "View Android's built-in notification log or scan cached chat & alert media without background listener permissions.",
                        color = Color(0xFF666B75),
                        fontSize = 13.sp
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = {
                                runCatching {
                                    context.startActivity(
                                        Intent("android.settings.NOTIFICATION_HISTORY")
                                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    )
                                }.onFailure {
                                    runCatching {
                                        context.startActivity(
                                            Intent(Settings.ACTION_SETTINGS)
                                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                        )
                                    }
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(12.dp)
                        ) { Text("System History", fontWeight = FontWeight.Bold) }
                        Button(
                            onClick = {
                                nav.navigate("scan/${FileCategory.PHOTO.name}")
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = CapacityBlue),
                            shape = RoundedCornerShape(12.dp)
                        ) { Text("Scan Chat Media") }
                    }
                }
            }
            TabRow(selectedTabIndex = tab, containerColor = Color.White) {
                listOf("All", "Media", "Messages").forEachIndexed { i, label ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(label) })
                }
            }
            if (filtered.isEmpty()) {
                Column(
                    Modifier.fillMaxSize().padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    CuteNotificationBellIllustration(Modifier.size(96.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("No cached alerts in local vault", color = Color(0xFF7A7F87))
                }
            } else {
                LazyColumn(
                    Modifier.fillMaxSize().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filtered, key = { it.id }) { n ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            shape = RoundedCornerShape(16.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(Modifier.padding(14.dp)) {
                                Row {
                                    Text(n.appLabel, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = CapacityBlue)
                                    Spacer(Modifier.weight(1f))
                                    Text(formatDate(n.time), color = Color(0xFF888888), fontSize = 11.sp)
                                }
                                if (n.title.isNotBlank()) Text(n.title, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                                if (n.text.isNotBlank()) Text(n.text, fontSize = 13.sp, color = Color(0xFF444444))
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Junk Cleaner ----------------

private data class JunkGroup(val title: String, val files: List<File>) {
    val totalSize: Long get() = files.sumOf { it.length() }
}

@Composable
fun JunkCleanerScreen(nav: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var scanning by remember { mutableStateOf(true) }
    var groups by remember { mutableStateOf<List<JunkGroup>>(emptyList()) }
    var selectedGroups by remember { mutableStateOf<Set<String>>(emptySet()) }
    var cleanedText by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        groups = withContext(Dispatchers.IO) { scanJunk() }
        selectedGroups = groups.map { it.title }.toSet()
        scanning = false
    }

    SimpleScaffold(
        title = "Junk Cleaner",
        onBack = { nav.popBackStack() },
        warmBackground = true,
        bottomBar = {
            if (groups.isNotEmpty()) {
                val toClean = groups.filter { selectedGroups.contains(it.title) }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White)
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Button(
                        onClick = {
                            scope.launch {
                                var freed = 0L
                                withContext(Dispatchers.IO) {
                                    toClean.forEach { g ->
                                        g.files.forEach { f ->
                                            val len = f.length()
                                            if (FileScanner.deleteWithUnoverwrittenRetention(context, f)) freed += len
                                        }
                                    }
                                }
                                cleanedText = "Cleaned ${formatSize(freed)}"
                                groups = withContext(Dispatchers.IO) { scanJunk() }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(54.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            "Clean (${formatSize(toClean.sumOf { it.totalSize })})",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    ) { mod ->
        Column(mod.fillMaxSize().padding(16.dp)) {
            if (scanning) {
                LinearProgressIndicator(Modifier.fillMaxWidth(), color = PrimaryGreen)
                Text("Scanning storage for junk files…", color = Color(0xFF7A7F87), modifier = Modifier.padding(top = 12.dp))
            } else if (groups.isEmpty()) {
                Column(
                    Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    CuteTrashCanIllustration(Modifier.size(96.dp))
                    Spacer(Modifier.height(14.dp))
                    Text("Your storage is clean!", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                }
            } else {
                if (cleanedText.isNotBlank()) {
                    Text(
                        cleanedText,
                        color = PrimaryGreen,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }
                LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(groups, key = { it.title }) { g ->
                        val isSelected = selectedGroups.contains(g.title)
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                            shape = RoundedCornerShape(18.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    selectedGroups = if (isSelected) selectedGroups - g.title else selectedGroups + g.title
                                }
                        ) {
                            Row(
                                Modifier.padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(g.title, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                    Text(
                                        "${g.files.size} files • ${formatSize(g.totalSize)}",
                                        color = Color(0xFF7A7F87),
                                        fontSize = 13.sp
                                    )
                                }
                                RoundCheckButton(
                                    checked = isSelected,
                                    onToggle = {
                                        selectedGroups = if (isSelected) selectedGroups - g.title else selectedGroups + g.title
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

private fun scanJunk(): List<JunkGroup> {
    val root = Environment.getExternalStorageDirectory() ?: return emptyList()
    val apkInstallers = ArrayList<File>()
    val tempFiles = ArrayList<File>()
    val largeFiles = ArrayList<File>()
    val imageByHash = HashMap<String, MutableList<File>>()
    root.walkTopDown().maxDepth(14).forEach { f ->
        if (!f.isFile) return@forEach
        val ext = f.extension.lowercase()
        when {
            ext in setOf("apk", "xapk", "apks") -> apkInstallers += f
            ext in setOf("tmp", "temp", "cache", "log", "bak") -> tempFiles += f
        }
        if (f.length() > 50L * 1024 * 1024) largeFiles += f
        if (FileCategory.fromExtension(ext) == FileCategory.PHOTO && f.length() in 10_000..20_000_000) {
            val key = f.length().toString() + ":" + FileScanner.md5Head(f)
            imageByHash.getOrPut(key) { ArrayList() } += f
        }
    }
    val duplicates = imageByHash.values.filter { it.size > 1 }.flatMap { it.drop(1) }
    return listOf(
        JunkGroup("Temp, Cache & Log Files", tempFiles),
        JunkGroup("Obsolete APK Installers", apkInstallers),
        JunkGroup("Duplicate Photos", duplicates),
        JunkGroup("Large Files (>50 MB)", largeFiles)
    ).filter { it.files.isNotEmpty() }
}

// ---------------- Storage & Uninstaller ----------------

@Composable
fun StorageScreen(nav: NavController) {
    val context = LocalContext.current
    val stat = remember {
        runCatching {
            val path = Environment.getExternalStorageDirectory()?.takeIf { it.exists() }
                ?: Environment.getDataDirectory()?.takeIf { it.exists() }
                ?: context.filesDir
            val s = StatFs(path.path)
            val total = s.blockCountLong * s.blockSizeLong
            val free = s.availableBlocksLong * s.blockSizeLong
            total to free
        }.getOrDefault((64L * 1024 * 1024 * 1024) to (42L * 1024 * 1024 * 1024))
    }
    var apps by remember { mutableStateOf<List<ApplicationInfo>>(emptyList()) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
                .sortedBy { pm.getApplicationLabel(it).toString().lowercase() }
        }
    }
    SimpleScaffold(title = "Capacity & Apps", onBack = { nav.popBackStack() }) { mod ->
        LazyColumn(
            mod.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(18.dp)) {
                        Text("Device Storage", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                        Spacer(Modifier.height(10.dp))
                        val used = stat.first - stat.second
                        LinearProgressIndicator(
                            progress = { if (stat.first > 0) used.toFloat() / stat.first else 0f },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(10.dp)
                                .clip(RoundedCornerShape(50)),
                            color = CapacityBlue
                        )
                        Spacer(Modifier.height(10.dp))
                        Text(
                            "${formatSize(used)} used of ${formatSize(stat.first)} • ${formatSize(stat.second)} free",
                            color = Color(0xFF666B75),
                            fontSize = 13.sp
                        )
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = { nav.navigate("storage_forensics") },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryGreen),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Open Storage Forensics Intelligence", fontWeight = FontWeight.Bold)
                        }
                    }
                }
                Text(
                    "Installed Apps (${apps.size})",
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    modifier = Modifier.padding(top = 14.dp, bottom = 4.dp)
                )
            }
            items(apps, key = { it.packageName }) { appInfo ->
                val pm = context.packageManager
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F7F9)),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Filled.Apps, contentDescription = null, tint = CapacityBlue)
                        Column(Modifier.padding(start = 12.dp).weight(1f)) {
                            Text(
                                pm.getApplicationLabel(appInfo).toString(),
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp,
                                maxLines = 1
                            )
                            Text(appInfo.packageName, color = Color(0xFF888888), fontSize = 11.sp)
                        }
                        Button(
                            onClick = {
                                val intent = Intent(Intent.ACTION_DELETE).apply {
                                    data = Uri.parse("package:" + appInfo.packageName)
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                runCatching { context.startActivity(intent) }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = CoralRed),
                            shape = RoundedCornerShape(50)
                        ) { Text("Uninstall", fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                    }
                }
            }
        }
    }
}
