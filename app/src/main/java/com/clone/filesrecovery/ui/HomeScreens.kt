package com.clone.filesrecovery.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AudioFile
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Contacts
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.clone.filesrecovery.data.FileCategory

// ---------------- Guide / onboarding ----------------

@Composable
fun GuideScreen(onDone: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().background(ScreenBg).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier.size(110.dp).clip(CircleShape).background(BrandViolet),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Filled.RestoreFromTrash, contentDescription = null, tint = Color.White, modifier = Modifier.size(56.dp))
        }
        Spacer(Modifier.height(24.dp))
        Text("Files Recovery", fontSize = 28.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(
            "Recover deleted photos, videos, audios and documents.\nPlus contacts backup, notification history and a junk cleaner.",
            color = Color.Gray, fontSize = 15.sp
        )
        Spacer(Modifier.height(12.dp))
        listOf(
            "Deep scan of your storage — hidden & lost files included",
            "Preview before you recover",
            "Recovered files are saved to a visible public folder"
        ).forEach {
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Text("✓  ", color = BrandTeal, fontWeight = FontWeight.Bold)
                Text(it, fontSize = 14.sp)
            }
        }
        Spacer(Modifier.height(28.dp))
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
            shape = RoundedCornerShape(14.dp)
        ) { Text("Get Started", fontSize = 16.sp) }
    }
}

// ---------------- Language ----------------

val LANGUAGES = listOf("English", "हिन्दी (Hindi)", "Español", "Português", "العربية", "Français", "Deutsch", "Русский")

@Composable
fun LanguageScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("app", 0) }
    var selected by remember { mutableStateOf(prefs.getString("language", "English") ?: "English") }
    SimpleScaffold(title = "Choose Language", onBack = null) { mod ->
        Column(mod.fillMaxSize().padding(16.dp)) {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(LANGUAGES) { lang ->
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                            .clickable { selected = lang },
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Filled.Language, contentDescription = null, tint = BrandViolet)
                            Text(lang, modifier = Modifier.padding(start = 12.dp).weight(1f), fontSize = 16.sp)
                            RadioButton(selected = selected == lang, onClick = { selected = lang })
                        }
                    }
                }
            }
            Button(
                onClick = {
                    prefs.edit().putString("language", selected).putBoolean("onboarded", true).apply()
                    onDone()
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
                shape = RoundedCornerShape(14.dp)
            ) { Text("Continue") }
        }
    }
}

// ---------------- Home ----------------

private data class HomeAction(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val color: Color,
    val route: String
)

@Composable
fun HomeScreen(nav: NavController) {
    val context = LocalContext.current
    val recoveryActions = listOf(
        HomeAction("Recover Photos", FileCategory.PHOTO.subtitle, Icons.Filled.Image, BrandViolet, "scan/PHOTO"),
        HomeAction("Recover Videos", FileCategory.VIDEO.subtitle, Icons.Filled.VideoFile, BrandPink, "scan/VIDEO"),
        HomeAction("Recover Audios", FileCategory.AUDIO.subtitle, Icons.Filled.AudioFile, BrandTeal, "scan/AUDIO"),
        HomeAction("Recover Documents", FileCategory.DOCUMENT.subtitle, Icons.Filled.Description, BrandOrange, "scan/DOCUMENT")
    )
    val toolActions = listOf(
        HomeAction("Recovered Files", "Files you already recovered", Icons.Filled.FolderOpen, BrandViolet, "recovered"),
        HomeAction("Contacts Backup", "Backup & restore contacts (.vcf)", Icons.Filled.Contacts, BrandTeal, "contacts"),
        HomeAction("Notification Recovery", "Read deleted notifications", Icons.Filled.Notifications, BrandPink, "notifications"),
        HomeAction("Junk Cleaner", "Screenshots, duplicates, big files", Icons.Filled.CleaningServices, BrandOrange, "junk"),
        HomeAction("Storage & Apps", "Storage info & uninstall apps", Icons.Filled.Storage, BrandViolet, "storage")
    )
    SimpleScaffold(
        title = "Files Recovery",
        actions = {
            androidx.compose.material3.IconButton(onClick = { nav.navigate("settings") }) {
                Icon(Icons.Filled.Settings, contentDescription = "Settings")
            }
        }
    ) { mod ->
        LazyColumn(mod.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = BrandViolet),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp)) {
                        Text("Deleted something by mistake?", color = Color.White, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text("Scan your storage and bring it back in a few taps.", color = Color(0xFFD9D2FF), fontSize = 14.sp)
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = { if (hasAllFilesAccess(context)) nav.navigate("scan/PHOTO") else nav.navigate("permission/PHOTO") },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = BrandViolet)
                        ) { Text("Start Scan", fontWeight = FontWeight.Bold) }
                    }
                }
            }
            item { Text("File Recovery", fontWeight = FontWeight.Bold, fontSize = 17.sp, modifier = Modifier.padding(top = 8.dp)) }
            items(recoveryActions.chunked(2)) { row ->
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    row.forEach { a -> ActionCard(a, Modifier.weight(1f)) { nav.navigate(a.route.let { if (hasAllFilesAccess(context)) it else "permission/" + a.route.removePrefix("scan/") }) } }
                    if (row.size == 1) Spacer(Modifier.weight(1f))
                }
            }
            item { Text("More Tools", fontWeight = FontWeight.Bold, fontSize = 17.sp, modifier = Modifier.padding(top = 8.dp)) }
            items(toolActions) { a ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable { nav.navigate(a.route) },
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(44.dp).clip(CircleShape).background(a.color.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
                            Icon(a.icon, contentDescription = null, tint = a.color)
                        }
                        Column(Modifier.padding(start = 14.dp)) {
                            Text(a.title, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            Text(a.subtitle, color = Color.Gray, fontSize = 12.sp)
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}

@Composable
private fun ActionCard(a: HomeAction, modifier: Modifier, onClick: () -> Unit) {
    Card(
        modifier = modifier.clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            Box(Modifier.size(46.dp).clip(CircleShape).background(a.color.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
                Icon(a.icon, contentDescription = null, tint = a.color, modifier = Modifier.size(26.dp))
            }
            Spacer(Modifier.height(10.dp))
            Text(a.title, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
            Text(a.subtitle, color = Color.Gray, fontSize = 11.sp)
        }
    }
}

// ---------------- All Files Permission ----------------

@Composable
fun PermissionScreen(nav: NavController, category: FileCategory) {
    val context = LocalContext.current
    SimpleScaffold(title = "Permission Needed", onBack = { nav.popBackStack() }) { mod ->
        Column(
            mod.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(Icons.Filled.FolderOpen, contentDescription = null, tint = BrandViolet, modifier = Modifier.size(72.dp))
            Spacer(Modifier.height(16.dp))
            Text("All Files Access", fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Text(
                "To find lost ${category.title.lowercase()} anywhere on your storage, the app needs \"All files access\". " +
                    "Files are only scanned on this device — nothing is uploaded.",
                color = Color.Gray, fontSize = 14.sp
            )
            Spacer(Modifier.height(24.dp))
            Button(
                onClick = { openAllFilesAccessSettings(context) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
                shape = RoundedCornerShape(14.dp)
            ) { Text("Grant Access") }
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = { nav.navigate("scan/" + category.name) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = BrandTeal),
                shape = RoundedCornerShape(14.dp)
            ) { Text("I have granted it — Continue") }
        }
    }
}

// ---------------- Settings ----------------

@Composable
fun SettingsScreen(nav: NavController) {
    val context = LocalContext.current
    SimpleScaffold(title = "Settings", onBack = { nav.popBackStack() }) { mod ->
        LazyColumn(mod.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                SettingRow(Icons.Filled.Language, "Language") { nav.navigate("language") }
            }
            item {
                SettingRow(Icons.Filled.Star, "Rate Us") {
                    runCatching {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + context.packageName))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    }
                }
            }
            item {
                SettingRow(Icons.Filled.Description, "Feedback") {
                    val intent = Intent(Intent.ACTION_SENDTO).apply {
                        data = Uri.parse("mailto:feedback@example.com")
                        putExtra(Intent.EXTRA_SUBJECT, "Files Recovery — Feedback")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    runCatching { context.startActivity(intent) }
                }
            }
            item {
                SettingRow(Icons.Filled.DeleteSweep, "Version") { }
                Text(
                    "Files Recovery Clone v1.0.0\nClean-room re-implementation built from REA analysis of the original app's feature set.",
                    color = Color.Gray, fontSize = 12.sp, modifier = Modifier.padding(start = 16.dp, top = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun SettingRow(icon: ImageVector, title: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = BrandViolet)
            Text(title, modifier = Modifier.padding(start = 12.dp), fontSize = 15.sp)
        }
    }
}
