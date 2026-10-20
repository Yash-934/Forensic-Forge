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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Contacts
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.data.ContactsHelper
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.formatDate
import com.clone.filesrecovery.data.formatSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

// ---------------- Contacts backup / restore ----------------

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
                Toast.makeText(context, "Imported $count contacts", Toast.LENGTH_LONG).show()
                vm.loadContacts()
            }
        }
    }
    LaunchedEffect(granted) { if (granted) vm.loadContacts() }

    SimpleScaffold(
        title = "Contacts Backup (${contacts.size})",
        onBack = { nav.popBackStack() },
        bottomBar = {
            if (granted) {
                Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
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
                        modifier = Modifier.weight(1f).height(50.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
                        shape = RoundedCornerShape(12.dp)
                    ) { Text("Backup (.vcf)") }
                    Button(
                        onClick = { pickVcf.launch(arrayOf("text/vcard", "text/x-vcard", "*/*")) },
                        modifier = Modifier.weight(1f).height(50.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = BrandTeal),
                        shape = RoundedCornerShape(12.dp)
                    ) { Text("Restore") }
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
                Icon(Icons.Filled.Contacts, contentDescription = null, tint = BrandViolet, modifier = Modifier.size(64.dp))
                Spacer(Modifier.height(12.dp))
                Text("Contacts permission needed", fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    permLauncher.launch(
                        arrayOf(
                            android.Manifest.permission.READ_CONTACTS,
                            android.Manifest.permission.WRITE_CONTACTS
                        )
                    )
                }) { Text("Grant Permission") }
            }
        } else if (contacts.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) { Text("No contacts found", color = Color.Gray) }
        } else {
            LazyColumn(mod.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(contacts, key = { it.id }) { c ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(14.dp)) {
                            Text(c.name, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            c.phones.forEach { Text(it, color = Color.Gray, fontSize = 13.sp) }
                            c.emails.forEach { Text(it, color = Color.Gray, fontSize = 13.sp) }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Notification recovery ----------------

private fun isListenerEnabled(context: android.content.Context): Boolean {
    val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
    return flat.contains(context.packageName)
}

@Composable
fun NotificationsScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val notifications by vm.notifications.collectAsState()
    var enabled by remember { mutableStateOf(isListenerEnabled(context)) }
    var tab by remember { mutableStateOf(0) } // 0 all, 1 media, 2 message
    LaunchedEffect(Unit) { vm.loadNotifications(); enabled = isListenerEnabled(context) }

    val filtered = when (tab) {
        1 -> notifications.filter { it.isMedia }
        2 -> notifications.filter { !it.isMedia }
        else -> notifications
    }

    SimpleScaffold(
        title = "Notification Recovery",
        onBack = { nav.popBackStack() },
        actions = {
            if (notifications.isNotEmpty()) {
                androidx.compose.material3.IconButton(onClick = { vm.clearNotifications() }) {
                    Icon(Icons.Filled.Delete, contentDescription = "Clear all")
                }
            }
        }
    ) { mod ->
        Column(mod.fillMaxSize()) {
            if (!enabled) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().padding(12.dp)
                ) {
                    Column(Modifier.padding(14.dp)) {
                        Text("Notification access is OFF", fontWeight = FontWeight.Bold)
                        Text(
                            "Turn it on so deleted messages/notifications can be recorded and read here later.",
                            color = Color.Gray, fontSize = 13.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(
                            onClick = {
                                context.startActivity(
                                    Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = BrandOrange)
                        ) { Text("Open Settings") }
                        Button(
                            onClick = { enabled = isListenerEnabled(context); vm.loadNotifications() },
                            colors = ButtonDefaults.buttonColors(containerColor = BrandViolet)
                        ) { Text("I enabled it — Refresh") }
                    }
                }
            }
            TabRow(selectedTabIndex = tab) {
                listOf("All", "Media", "Message").forEachIndexed { i, label ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(label) })
                }
            }
            if (filtered.isEmpty()) {
                Column(
                    Modifier.fillMaxSize().padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Filled.Notifications, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(56.dp))
                    Spacer(Modifier.height(10.dp))
                    Text("No notifications recorded yet", color = Color.Gray)
                }
            } else {
                LazyColumn(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(filtered, key = { it.id }) { n ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(Modifier.padding(14.dp)) {
                                Row {
                                    Text(n.appLabel, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = BrandViolet)
                                    Spacer(Modifier.weight(1f))
                                    Text(formatDate(n.time), color = Color.Gray, fontSize = 11.sp)
                                }
                                if (n.title.isNotBlank()) Text(n.title, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                                if (n.text.isNotBlank()) Text(n.text, fontSize = 13.sp, color = Color.DarkGray)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Junk cleaner ----------------

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
        bottomBar = {
            if (groups.isNotEmpty()) {
                val toClean = groups.filter { selectedGroups.contains(it.title) }
                Button(
                    onClick = {
                        scope.launch {
                            var freed = 0L
                            withContext(Dispatchers.IO) {
                                toClean.forEach { g -> g.files.forEach { f -> val len = f.length(); if (f.delete()) freed += len } }
                            }
                            cleanedText = "Cleaned ${formatSize(freed)}"
                            groups = withContext(Dispatchers.IO) { scanJunk() }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().padding(16.dp).height(52.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = BrandOrange),
                    shape = RoundedCornerShape(14.dp)
                ) { Text("Clean (${formatSize(toClean.sumOf { it.totalSize })})") }
            }
        }
    ) { mod ->
        Column(mod.fillMaxSize().padding(16.dp)) {
            if (scanning) {
                LinearProgressIndicator(Modifier.fillMaxWidth(), color = BrandOrange)
                Text("Scanning for junk…", color = Color.Gray, modifier = Modifier.padding(top = 10.dp))
            } else if (groups.isEmpty()) {
                Text("No junk found. Your storage is clean 🎉", modifier = Modifier.padding(8.dp))
            } else {
                if (cleanedText.isNotBlank()) {
                    Text(cleanedText, color = BrandTeal, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
                }
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(groups, key = { it.title }) { g ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(g.title, fontWeight = FontWeight.SemiBold)
                                    Text("${g.files.size} files • ${formatSize(g.totalSize)}", color = Color.Gray, fontSize = 12.sp)
                                }
                                Checkbox(
                                    checked = selectedGroups.contains(g.title),
                                    onCheckedChange = { checked ->
                                        selectedGroups = if (checked) selectedGroups + g.title else selectedGroups - g.title
                                    }
                                )
                            }
                        }
                    }
                }
            }
            if (!hasAllFilesAccess(context)) {
                Text(
                    "Tip: grant All Files Access from the home screen scan flow for a complete junk scan.",
                    color = Color.Gray, fontSize = 12.sp, modifier = Modifier.padding(top = 12.dp)
                )
            }
        }
    }
}

private fun scanJunk(): List<JunkGroup> {
    val root = Environment.getExternalStorageDirectory() ?: return emptyList()
    val screenshots = ArrayList<File>()
    val tempFiles = ArrayList<File>()
    val largeFiles = ArrayList<File>()
    val imageByHash = HashMap<String, MutableList<File>>()
    root.walkTopDown().maxDepth(12).forEach { f ->
        if (!f.isFile) return@forEach
        val path = f.path.replace('\\', '/')
        when {
            path.contains("/Screenshots/", true) -> screenshots += f
            f.extension.lowercase() in setOf("tmp", "cache", "log") -> tempFiles += f
        }
        if (f.length() > 50L * 1024 * 1024) largeFiles += f
        if (FileCategory.fromExtension(f.extension) == FileCategory.PHOTO && f.length() in 10_000..20_000_000) {
            val key = f.length().toString() + ":" + md5Head(f)
            imageByHash.getOrPut(key) { ArrayList() } += f
        }
    }
    val duplicates = imageByHash.values.filter { it.size > 1 }.flatMap { it.drop(1) }
    return listOf(
        JunkGroup("Screenshots", screenshots),
        JunkGroup("Duplicate Photos", duplicates),
        JunkGroup("Large Files (>50 MB) — review before deleting", largeFiles),
        JunkGroup("Temp & Log Files", tempFiles)
    ).filter { it.files.isNotEmpty() }
}

private fun md5Head(f: File): String = runCatching {
    val md = MessageDigest.getInstance("MD5")
    f.inputStream().use { input ->
        val buf = ByteArray(64 * 1024)
        val read = input.read(buf)
        if (read > 0) md.update(buf, 0, read)
    }
    md.digest().joinToString("") { "%02x".format(it) }
}.getOrDefault("")

// ---------------- Storage & uninstaller ----------------

@Composable
fun StorageScreen(nav: NavController) {
    val context = LocalContext.current
    val stat = remember {
        val path = Environment.getDataDirectory()
        val s = StatFs(path.path)
        val total = s.blockCountLong * s.blockSizeLong
        val free = s.availableBlocksLong * s.blockSizeLong
        total to free
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
    SimpleScaffold(title = "Storage & Apps", onBack = { nav.popBackStack() }) { mod ->
        LazyColumn(mod.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Internal Storage", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        Spacer(Modifier.height(8.dp))
                        val used = stat.first - stat.second
                        LinearProgressIndicator(
                            progress = { if (stat.first > 0) used.toFloat() / stat.first else 0f },
                            modifier = Modifier.fillMaxWidth(),
                            color = BrandViolet
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("${formatSize(used)} used of ${formatSize(stat.first)} • ${formatSize(stat.second)} free", color = Color.Gray, fontSize = 13.sp)
                    }
                }
                Text("Installed Apps (${apps.size}) — tap Uninstall to remove", fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 14.dp, bottom = 4.dp))
            }
            items(apps, key = { it.packageName }) { appInfo ->
                val pm = context.packageManager
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Apps, contentDescription = null, tint = BrandViolet)
                        Column(Modifier.padding(start = 10.dp).weight(1f)) {
                            Text(pm.getApplicationLabel(appInfo).toString(), fontWeight = FontWeight.SemiBold, fontSize = 14.sp, maxLines = 1)
                            Text(appInfo.packageName, color = Color.Gray, fontSize = 11.sp)
                        }
                        Button(
                            onClick = {
                                val intent = Intent(Intent.ACTION_DELETE).apply {
                                    data = Uri.parse("package:" + appInfo.packageName)
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                runCatching { context.startActivity(intent) }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = BrandPink),
                            shape = RoundedCornerShape(10.dp)
                        ) { Text("Uninstall", fontSize = 12.sp) }
                    }
                }
            }
        }
    }
}
