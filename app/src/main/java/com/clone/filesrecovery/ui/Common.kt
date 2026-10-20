package com.clone.filesrecovery.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AudioFile
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.core.content.ContextCompat
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SimpleScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    content: @Composable (Modifier) -> Unit
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = { actions() },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = BrandViolet,
                    titleContentColor = Color.White,
                    navigationIconContentColor = Color.White,
                    actionIconContentColor = Color.White
                )
            )
        },
        bottomBar = bottomBar,
        containerColor = ScreenBg
    ) { padding ->
        content(Modifier.padding(padding))
    }
}

// ---------- Permissions (mirrors the original app's AllFilePermission screen) ----------

fun hasAllFilesAccess(context: Context): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Environment.isExternalStorageManager()
    } else {
        ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED
    }

fun openAllFilesAccessSettings(context: Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
            data = Uri.parse("package:" + context.packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching { context.startActivity(intent) }.onFailure {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }
}

fun mediaPermissionsFor(sdk: Int = Build.VERSION.SDK_INT): Array<String> = when {
    sdk >= 33 -> arrayOf(
        android.Manifest.permission.READ_MEDIA_IMAGES,
        android.Manifest.permission.READ_MEDIA_VIDEO,
        android.Manifest.permission.READ_MEDIA_AUDIO
    )
    else -> arrayOf(android.Manifest.permission.READ_EXTERNAL_STORAGE)
}

// ---------- Thumbnails ----------

@Composable
fun FileThumb(file: RecoverableFile, modifier: Modifier = Modifier) {
    val bitmapState = produceState<Bitmap?>(initialValue = null, key1 = file.path) {
        value = withContext(Dispatchers.IO) { loadThumbnail(file) }
    }
    val bmp = bitmapState.value
    Box(modifier = modifier.background(Color(0xFFE9E6F7)), contentAlignment = Alignment.Center) {
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = file.name,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize()
            )
        } else {
            val (icon, tint) = when (file.category) {
                FileCategory.PHOTO -> Icons.Filled.Image to BrandViolet
                FileCategory.VIDEO -> Icons.Filled.VideoFile to BrandPink
                FileCategory.AUDIO -> Icons.Filled.AudioFile to BrandTeal
                FileCategory.DOCUMENT -> Icons.Filled.Description to BrandOrange
            }
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.fillMaxSize(0.45f))
        }
    }
}

private fun loadThumbnail(file: RecoverableFile): Bitmap? = runCatching {
    when (file.category) {
        FileCategory.PHOTO -> {
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.path, opts)
            opts.inSampleSize = calculateSampleSize(opts, 360, 360)
            opts.inJustDecodeBounds = false
            BitmapFactory.decodeFile(file.path, opts)
        }
        FileCategory.VIDEO -> {
            val r = MediaMetadataRetriever()
            r.setDataSource(file.path)
            val b = r.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            r.release()
            b
        }
        else -> null
    }
}.getOrNull()

private fun calculateSampleSize(opts: BitmapFactory.Options, reqW: Int, reqH: Int): Int {
    var size = 1
    while (opts.outWidth / (size * 2) >= reqW && opts.outHeight / (size * 2) >= reqH) size *= 2
    return size
}

fun openFile(context: Context, file: File, mime: String) {
    val uri = androidx.core.content.FileProvider.getUriForFile(
        context, context.packageName + ".fileprovider", file
    )
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, mime)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { context.startActivity(Intent.createChooser(intent, "Open with").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}

fun mimeFor(file: RecoverableFile): String = when (file.category) {
    FileCategory.PHOTO -> "image/*"
    FileCategory.VIDEO -> "video/*"
    FileCategory.AUDIO -> "audio/*"
    FileCategory.DOCUMENT -> "*/*"
}
