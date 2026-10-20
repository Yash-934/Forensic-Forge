package com.clone.filesrecovery.ui

import android.media.MediaPlayer
import android.widget.MediaController
import android.widget.VideoView
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation.NavController
import com.clone.filesrecovery.AppViewModel
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.formatDate
import com.clone.filesrecovery.data.formatSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

// ---------------- Scanning ----------------

@Composable
fun ScanScreen(nav: NavController, vm: AppViewModel, category: FileCategory) {
    val isScanning by vm.isScanning.collectAsState()
    val results by vm.scanResults.collectAsState()
    val progressText by vm.scanProgressText.collectAsState()
    val scannedCount by vm.scannedCount.collectAsState()
    var started by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (!started) {
            started = true
            vm.startScan(category)
        }
    }
    LaunchedEffect(isScanning, started) {
        if (started && !isScanning) {
            nav.navigate("results") { popUpTo("home") }
        }
    }

    SimpleScaffold(title = "Scanning ${category.title}", onBack = { nav.popBackStack() }) { mod ->
        Column(
            mod.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            CircularProgressIndicator(color = BrandViolet, modifier = Modifier.size(84.dp), strokeWidth = 7.dp)
            Spacer(Modifier.height(24.dp))
            Text("Deep scanning your storage…", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("$scannedCount files checked • ${results.size} ${category.title.lowercase()} found", color = Color.Gray)
            Spacer(Modifier.height(16.dp))
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = BrandViolet)
            Spacer(Modifier.height(12.dp))
            Text(
                progressText.substringAfterLast('/'),
                color = Color.Gray, fontSize = 12.sp, maxLines = 1
            )
        }
    }
}

// ---------------- Results ----------------

@Composable
fun ResultScreen(nav: NavController, vm: AppViewModel) {
    val results by vm.scanResults.collectAsState()
    val selected by vm.selected.collectAsState()
    val isRecovering by vm.isRecovering.collectAsState()
    val lastRecovered by vm.lastRecoveredCount.collectAsState()
    val category = vm.currentCategory

    if (lastRecovered != null) {
        AlertDialog(
            onDismissRequest = { vm.consumeRecoveredEvent() },
            icon = { Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = BrandTeal, modifier = Modifier.size(40.dp)) },
            title = { Text("Recovery Completed") },
            text = {
                Text(
                    "$lastRecovered file(s) recovered to the FilesRecovery/${category.title} folder. " +
                        "You can also find them under Recovered Files."
                )
            },
            confirmButton = {
                Button(onClick = { vm.consumeRecoveredEvent(); nav.navigate("recovered") }) { Text("View Recovered") }
            },
            dismissButton = {
                Button(
                    onClick = { vm.consumeRecoveredEvent() },
                    colors = ButtonDefaults.buttonColors(containerColor = Color.Gray)
                ) { Text("Close") }
            }
        )
    }

    SimpleScaffold(
        title = "${category.title} Found (${results.size})",
        onBack = { nav.popBackStack() },
        actions = {
            Text(
                if (selected.size == vm.scanResults.value.size && results.isNotEmpty()) "Clear" else "All",
                modifier = Modifier.clickable {
                    if (selected.size == results.size) vm.clearSelection() else vm.selectAll()
                }.padding(12.dp),
                color = Color.White, fontWeight = FontWeight.Bold
            )
        },
        bottomBar = {
            if (selected.isNotEmpty()) {
                Button(
                    onClick = { vm.recoverSelected() },
                    enabled = !isRecovering,
                    modifier = Modifier.fillMaxWidth().padding(16.dp).height(52.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Icon(Icons.Filled.RestoreFromTrash, contentDescription = null)
                    Text(
                        if (isRecovering) "  Recovering…" else "  Recover (${selected.size})",
                        modifier = Modifier.padding(start = 4.dp)
                    )
                }
            }
        }
    ) { mod ->
        if (results.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(64.dp))
                Spacer(Modifier.height(12.dp))
                Text("No ${category.title.lowercase()} found", fontWeight = FontWeight.Bold)
                Text("Nothing was found in the scanned storage.", color = Color.Gray, fontSize = 13.sp)
            }
        } else if (category == FileCategory.PHOTO || category == FileCategory.VIDEO) {
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                modifier = mod.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(results, key = { it.path }) { file ->
                    FileGridItem(
                        file = file,
                        checked = selected.contains(file.path),
                        onToggle = { vm.toggleSelect(file) },
                        onOpen = { vm.currentFile = file; nav.navigate("detail") }
                    )
                }
            }
        } else {
            LazyColumn(mod.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(results, key = { it.path }) { file ->
                    FileListItem(
                        file = file,
                        checked = selected.contains(file.path),
                        onToggle = { vm.toggleSelect(file) },
                        onOpen = { vm.currentFile = file; nav.navigate("detail") }
                    )
                }
            }
        }
    }
}

@Composable
private fun FileGridItem(file: RecoverableFile, checked: Boolean, onToggle: () -> Unit, onOpen: () -> Unit) {
    Box(
        modifier = Modifier.aspectRatio(1f).clip(RoundedCornerShape(10.dp))
            .clickable { onOpen() }
    ) {
        FileThumb(file, Modifier.fillMaxSize())
        Box(
            modifier = Modifier.align(Alignment.TopEnd).padding(4.dp)
                .background(Color.White.copy(alpha = 0.9f), RoundedCornerShape(50))
                .clickable { onToggle() }
        ) {
            Checkbox(checked = checked, onCheckedChange = { onToggle() }, modifier = Modifier.size(28.dp))
        }
        Text(
            formatSize(file.size),
            color = Color.White, fontSize = 10.sp,
            modifier = Modifier.align(Alignment.BottomStart)
                .background(Color.Black.copy(alpha = 0.55f))
                .padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
private fun FileListItem(file: RecoverableFile, checked: Boolean, onToggle: () -> Unit, onOpen: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onOpen() },
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            FileThumb(file, Modifier.size(56.dp).clip(RoundedCornerShape(8.dp)))
            Column(Modifier.padding(start = 12.dp).weight(1f)) {
                Text(file.name, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text("${file.folderName} • ${formatSize(file.size)}", color = Color.Gray, fontSize = 12.sp)
                Text(formatDate(file.lastModified), color = Color.Gray, fontSize = 11.sp)
            }
            Checkbox(checked = checked, onCheckedChange = { onToggle() })
        }
    }
}

// ---------------- Detail / preview ----------------

@Composable
fun DetailScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val file = vm.currentFile
    val isRecovering by vm.isRecovering.collectAsState()
    if (file == null) {
        LaunchedEffect(Unit) { nav.popBackStack() }
        return
    }
    SimpleScaffold(
        title = file.name,
        onBack = { nav.popBackStack() },
        bottomBar = {
            Button(
                onClick = { vm.recoverSingle(file) },
                enabled = !isRecovering,
                modifier = Modifier.fillMaxWidth().padding(16.dp).height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = BrandViolet),
                shape = RoundedCornerShape(14.dp)
            ) { Text(if (isRecovering) "Recovering…" else "Recover this file") }
        }
    ) { mod ->
        Column(mod.fillMaxSize().padding(16.dp)) {
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
                            modifier = Modifier.fillMaxWidth().weight(1f).clip(RoundedCornerShape(12.dp))
                        )
                    } else FileThumb(file, Modifier.fillMaxWidth().height(260.dp).clip(RoundedCornerShape(12.dp)))
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
                        modifier = Modifier.fillMaxWidth().aspectRatio(16f / 9f)
                            .background(Color.Black, RoundedCornerShape(12.dp))
                    )
                }
                FileCategory.AUDIO -> {
                    AudioPlayer(path = file.path)
                }
                FileCategory.DOCUMENT -> {
                    FileThumb(file, Modifier.fillMaxWidth().height(200.dp).clip(RoundedCornerShape(12.dp)))
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = { openFile(context, File(file.path), mimeFor(file)) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = BrandTeal)
                    ) { Text("Open with another app") }
                }
            }
            Spacer(Modifier.height(16.dp))
            InfoRow("Name", file.name)
            InfoRow("Folder", file.folderName)
            InfoRow("Size", formatSize(file.size))
            InfoRow("Modified", formatDate(file.lastModified))
            InfoRow("Path", file.path)
        }
    }
}

@Composable
private fun AudioPlayer(path: String) {
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var playing by remember { mutableStateOf(false) }
    DisposableEffect(path) {
        val p = MediaPlayer().apply { setDataSource(path); prepare() }
        player = p
        onDispose { p.release() }
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth().padding(24.dp)) {
        IconButton(
            onClick = {
                player?.let {
                    if (it.isPlaying) { it.pause(); playing = false } else { it.start(); playing = true }
                }
            },
            modifier = Modifier.size(76.dp).background(BrandViolet, RoundedCornerShape(50))
        ) {
            Icon(
                if (playing) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                contentDescription = "Play/Pause", tint = Color.White, modifier = Modifier.size(40.dp)
            )
        }
        Text(if (playing) "Playing…" else "Tap to play", color = Color.Gray, modifier = Modifier.padding(top = 10.dp))
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, color = Color.Gray, fontSize = 13.sp, modifier = Modifier.size(width = 84.dp, height = 20.dp))
        Text(value, fontSize = 13.sp)
    }
}

// ---------------- Recovered files ----------------

@Composable
fun RecoveredScreen(nav: NavController, vm: AppViewModel) {
    val context = LocalContext.current
    val recovered by vm.recovered.collectAsState()
    LaunchedEffect(Unit) { vm.loadRecovered() }
    SimpleScaffold(title = "Recovered Files (${recovered.size})", onBack = { nav.popBackStack() }) { mod ->
        if (recovered.isEmpty()) {
            Column(
                mod.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(60.dp))
                Spacer(Modifier.height(10.dp))
                Text("No recovered files yet", fontWeight = FontWeight.Bold)
                Text("Files you recover will appear here.", color = Color.Gray, fontSize = 13.sp)
            }
        } else {
            LazyColumn(mod.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(recovered, key = { it.recoveredPath + it.recoveredAt }) { rec ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable {
                            // Recovered files live in public folders; open via the original if still present,
                            // otherwise tell the user where the copy was saved.
                            val f = File(rec.originalPath)
                            if (f.exists()) {
                                vm.currentFile = RecoverableFile(rec.originalPath, rec.name, rec.category, rec.size, rec.recoveredAt)
                                nav.navigate("detail")
                            }
                        },
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = BrandTeal)
                            Column(Modifier.padding(start = 10.dp)) {
                                Text(rec.name, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, maxLines = 1)
                                Text("Saved to: ${rec.recoveredPath}", color = Color.Gray, fontSize = 11.sp)
                                Text("${formatSize(rec.size)} • ${formatDate(rec.recoveredAt)}", color = Color.Gray, fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}
