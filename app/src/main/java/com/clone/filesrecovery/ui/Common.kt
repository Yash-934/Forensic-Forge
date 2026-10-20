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
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.AudioFile
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Modern DeepVault Studio scaffold with elevated squircle back button,
 * crisp typography, and subtle atmospheric gradient header.
 */
@Composable
fun SimpleScaffold(
    title: String,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    warmBackground: Boolean = false,
    content: @Composable (Modifier) -> Unit
) {
    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            Surface(
                color = if (warmBackground) Color(0xFFEEF2FF) else SurfaceLight,
                shadowElevation = 2.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .statusBarsPadding()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (onBack != null) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(12.dp))
                                .background(Color(0xFFF1F5F9))
                                .clickable { onBack() },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back",
                                tint = TextPrimary,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = title,
                            fontSize = 19.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = TextPrimary,
                            maxLines = 1
                        )
                    }
                    actions()
                }
            }
        },
        bottomBar = {
            Box(modifier = Modifier.navigationBarsPadding()) {
                bottomBar()
            }
        },
        containerColor = BgLight
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    if (warmBackground) {
                        Brush.verticalGradient(
                            colors = listOf(
                                Color(0xFFEEF2FF),
                                Color(0xFFF4F6FB),
                                Color(0xFFF8FAFC)
                            )
                        )
                    } else {
                        Brush.verticalGradient(listOf(BgLight, BgLight))
                    }
                )
        ) {
            content(Modifier.padding(padding))
        }
    }
}

/**
 * Modern squircle checkbox with Royal Indigo -> Cyan gradient fill when checked.
 */
@Composable
fun RoundCheckButton(
    checked: Boolean,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
    size: Dp = 24.dp,
    uncheckedBorderColor: Color = Color(0xFF94A3B8)
) {
    val shape = RoundedCornerShape(8.dp)
    Box(
        modifier = modifier
            .size(size)
            .clip(shape)
            .background(
                brush = if (checked) {
                    Brush.linearGradient(listOf(PrimaryGreen, AccentCyan))
                } else {
                    Brush.linearGradient(listOf(Color.White.copy(alpha = 0.85f), Color.White.copy(alpha = 0.85f)))
                }
            )
            .border(
                width = if (checked) 0.dp else 1.8.dp,
                color = if (checked) Color.Transparent else uncheckedBorderColor,
                shape = shape
            )
            .clickable { onToggle() },
        contentAlignment = Alignment.Center
    ) {
        if (checked) {
            Icon(
                imageVector = Icons.Filled.Check,
                contentDescription = "Selected",
                tint = Color.White,
                modifier = Modifier.size(size * 0.68f)
            )
        }
    }
}

/**
 * Modern card container with subtle top accent bar & ambient radial glow.
 */
@Composable
fun FolderTabCard(
    modifier: Modifier = Modifier,
    backgroundColor: Color = Color.White,
    glowColor: Color? = null,
    tabWidthFraction: Float = 0.44f,
    tabHeight: Dp = 14.dp,
    cornerRadius: Dp = 22.dp,
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit
) {
    val shape = RoundedCornerShape(cornerRadius)
    Box(
        modifier = modifier
            .clip(shape)
            .background(backgroundColor)
            .border(1.dp, Color(0xFFE2E8F0), shape)
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
    ) {
        if (glowColor != null) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(glowColor.copy(alpha = 0.24f), Color.Transparent),
                        center = Offset(size.width * 0.82f, size.height * 0.22f),
                        radius = size.minDimension * 0.72f
                    ),
                    center = Offset(size.width * 0.82f, size.height * 0.22f),
                    radius = size.minDimension * 0.72f
                )
            }
        }
        content()
    }
}

/**
 * Loads a real bitmap preview for images, videos, or APKs on a background dispatcher.
 */
@Composable
fun FileThumbnail(
    file: RecoverableFile,
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 12.dp
) {
    val bitmapState = produceState<Bitmap?>(initialValue = null, key1 = file.path) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                when (file.category) {
                    FileCategory.PHOTO -> decodeSampled(file.path, 260, 260)
                    FileCategory.VIDEO -> {
                        val r = MediaMetadataRetriever()
                        try {
                            r.setDataSource(file.path)
                            r.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                        } finally {
                            runCatching { r.release() }
                        }
                    }
                    else -> null
                }
            }.getOrNull()
        }
    }

    val shape = RoundedCornerShape(cornerRadius)
    val bmp = bitmapState.value
    if (bmp != null) {
        Image(
            bitmap = bmp.asImageBitmap(),
            contentDescription = file.name,
            contentScale = ContentScale.Crop,
            modifier = modifier
                .clip(shape)
                .background(Color(0xFFE2E8F0))
        )
    } else {
        Box(
            modifier = modifier
                .clip(shape)
                .background(
                    when (file.category) {
                        FileCategory.PHOTO -> AccentPhoto.copy(alpha = 0.12f)
                        FileCategory.VIDEO -> AccentVideo.copy(alpha = 0.12f)
                        FileCategory.AUDIO -> AccentAudio.copy(alpha = 0.12f)
                        FileCategory.DOCUMENT -> Color.Transparent
                    }
                ),
            contentAlignment = Alignment.Center
        ) {
            when (file.category) {
                FileCategory.DOCUMENT -> FileTypeBadgeIcon(extension = file.extension, modifier = Modifier.size(44.dp))
                FileCategory.AUDIO -> FileTypeBadgeIcon(extension = file.extension.ifEmpty { "mp3" }, modifier = Modifier.size(44.dp))
                FileCategory.PHOTO -> Icon(
                    imageVector = Icons.Filled.Image,
                    contentDescription = file.name,
                    tint = AccentPhoto,
                    modifier = Modifier.size(28.dp)
                )
                FileCategory.VIDEO -> Icon(
                    imageVector = Icons.Filled.VideoFile,
                    contentDescription = file.name,
                    tint = AccentVideo,
                    modifier = Modifier.size(28.dp)
                )
            }
        }
    }
}

@Composable
fun FileThumb(
    file: RecoverableFile,
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 10.dp
) {
    FileThumbnail(file = file, modifier = modifier, cornerRadius = cornerRadius)
}

/**
 * Modern dual-tone file-type icon with pill badge for PDF, TXT, XLS, DOC, APK, ZIP, MP3.
 */
@Composable
fun FileTypeBadgeIcon(
    extension: String,
    category: FileCategory = FileCategory.DOCUMENT,
    modifier: Modifier = Modifier
) {
    val ext = extension.lowercase()
    val (bgColor, badgeColor, label) = when {
        ext == "pdf" -> Triple(Color(0xFFEF4444), Color(0xFFB91C1C), "PDF")
        ext in setOf("xls", "xlsx", "csv") -> Triple(Color(0xFF10B981), Color(0xFF047857), "XLS")
        ext in setOf("doc", "docx", "rtf") -> Triple(Color(0xFF3B82F6), Color(0xFF1D4ED8), "DOC")
        ext in setOf("ppt", "pptx") -> Triple(Color(0xFFF97316), Color(0xFFC2410C), "PPT")
        ext == "apk" -> Triple(Color(0xFF8B5CF6), Color(0xFF6D28D9), "APK")
        ext in setOf("zip", "rar", "7z", "tar", "gz") -> Triple(Color(0xFFF59E0B), Color(0xFFB45309), "ZIP")
        ext in setOf("mp3", "m4a", "wav", "flac", "ogg", "aac", "amr", "opus") ->
            Triple(Color(0xFFEC4899), Color(0xFFBE185D), "MP3")
        else -> Triple(Color(0xFF06B6D4), Color(0xFF0E7490), "TXT")
    }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
            // Main rounded page body
            drawRoundRect(
                brush = Brush.linearGradient(listOf(bgColor, badgeColor)),
                topLeft = Offset(w * 0.12f, h * 0.06f),
                size = Size(w * 0.76f, h * 0.88f),
                cornerRadius = CornerRadius(w * 0.18f, w * 0.18f)
            )
            // Top-right glass highlight fold
            val foldPath = Path().apply {
                moveTo(w * 0.58f, h * 0.06f)
                lineTo(w * 0.88f, h * 0.34f)
                lineTo(w * 0.66f, h * 0.34f)
                quadraticTo(w * 0.58f, h * 0.34f, w * 0.58f, h * 0.26f)
                close()
            }
            drawPath(foldPath, color = Color.White.copy(alpha = 0.35f))

            // Subtle header bars
            drawRoundRect(
                color = Color.White.copy(alpha = 0.45f),
                topLeft = Offset(w * 0.24f, h * 0.24f),
                size = Size(w * 0.26f, h * 0.06f),
                cornerRadius = CornerRadius(4f, 4f)
            )
            drawRoundRect(
                color = Color.White.copy(alpha = 0.30f),
                topLeft = Offset(w * 0.24f, h * 0.35f),
                size = Size(w * 0.44f, h * 0.05f),
                cornerRadius = CornerRadius(4f, 4f)
            )
            // Bottom pill label plate
            drawRoundRect(
                color = Color.Black.copy(alpha = 0.24f),
                topLeft = Offset(w * 0.20f, h * 0.54f),
                size = Size(w * 0.60f, h * 0.26f),
                cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
            )
        }
        Text(
            text = label,
            color = Color.White,
            fontSize = 10.sp,
            fontWeight = FontWeight.ExtraBold,
            modifier = Modifier.offset(y = 6.dp)
        )
    }
}

/**
 * Modern Indigo-Cyan gradient folder icon for Folder Breakdown rows.
 */
@Composable
fun Folder3DIcon(
    modifier: Modifier = Modifier,
    badgeLabel: String? = null,
    badgeColor: Color = PrimaryGreen
) {
    Box(modifier = modifier.size(46.dp), contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
            // Back tab
            val backPath = Path().apply {
                addRoundRect(
                    RoundRect(
                        rect = Rect(w * 0.08f, h * 0.16f, w * 0.92f, h * 0.86f),
                        cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
                    )
                )
            }
            drawPath(backPath, color = Color(0xFF4338CA))
            // Inner cyan sheet
            drawRoundRect(
                color = Color(0xFFBAE6FD),
                topLeft = Offset(w * 0.16f, h * 0.24f),
                size = Size(w * 0.68f, h * 0.32f),
                cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
            )
            // Front folder pocket
            drawRoundRect(
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFF6366F1), Color(0xFF06B6D4))
                ),
                topLeft = Offset(w * 0.06f, h * 0.34f),
                size = Size(w * 0.88f, h * 0.54f),
                cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
            )
            if (badgeLabel != null) {
                drawRoundRect(
                    color = badgeColor,
                    topLeft = Offset(w * 0.22f, h * 0.48f),
                    size = Size(w * 0.56f, h * 0.26f),
                    cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
                )
            }
        }
        if (badgeLabel != null) {
            Text(
                text = badgeLabel,
                color = Color.White,
                fontSize = 8.sp,
                fontWeight = FontWeight.ExtraBold,
                modifier = Modifier.offset(y = 5.dp)
            )
        }
    }
}

@Composable
fun YellowFolderIcon(modifier: Modifier = Modifier) {
    Folder3DIcon(modifier = modifier)
}

// ---------- Redesigned Neo-Glass & Cyber-Forensic Vector Emblem Illustrations ----------

private fun Modifier.grayscaleIf(grayscale: Boolean): Modifier =
    if (!grayscale) this else this.drawWithContent {
        val paint = Paint().apply {
            colorFilter = ColorFilter.colorMatrix(ColorMatrix().apply { setToSaturation(0f) })
        }
        drawIntoCanvas { canvas ->
            canvas.saveLayer(Rect(0f, 0f, size.width, size.height), paint)
            drawContent()
            canvas.restore()
        }
    }

@Composable
fun CuteCameraIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(84.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        // Soft sapphire ambient halo
        drawCircle(
            color = Color(0xFF3B82F6).copy(alpha = 0.15f),
            radius = w * 0.44f,
            center = Offset(w * 0.5f, h * 0.52f)
        )
        // Tilted back photo frame
        drawRoundRect(
            color = Color(0xFF93C5FD),
            topLeft = Offset(w * 0.22f, h * 0.16f),
            size = Size(w * 0.58f, h * 0.52f),
            cornerRadius = CornerRadius(w * 0.14f, w * 0.14f)
        )
        // Main sapphire-indigo camera housing
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF2563EB), Color(0xFF4F46E5))),
            topLeft = Offset(w * 0.12f, h * 0.26f),
            size = Size(w * 0.76f, h * 0.54f),
            cornerRadius = CornerRadius(w * 0.18f, w * 0.18f)
        )
        // Aperture ring
        val lens = Offset(w * 0.50f, h * 0.53f)
        drawCircle(color = Color.White.copy(alpha = 0.92f), radius = w * 0.20f, center = lens)
        drawCircle(
            brush = Brush.linearGradient(listOf(Color(0xFF06B6D4), Color(0xFF1D4ED8))),
            radius = w * 0.14f,
            center = lens
        )
        drawCircle(color = Color(0xFF0F172A), radius = w * 0.07f, center = lens)
        drawCircle(color = Color.White, radius = w * 0.028f, center = lens + Offset(-w * 0.03f, -w * 0.03f))
        // Cyan flash indicator dot
        drawCircle(color = Color(0xFF38BDF8), radius = w * 0.035f, center = Offset(w * 0.74f, h * 0.36f))
    }
}

@Composable
fun CuteVideoProjectorIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(84.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        drawCircle(
            color = Color(0xFFF97316).copy(alpha = 0.15f),
            radius = w * 0.44f,
            center = Offset(w * 0.5f, h * 0.52f)
        )
        // Back clapperboard stripe bar
        drawRoundRect(
            color = Color(0xFFFB923C),
            topLeft = Offset(w * 0.16f, h * 0.18f),
            size = Size(w * 0.68f, h * 0.16f),
            cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
        )
        // Main coral-orange cinema card
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFFF97316), Color(0xFFEA580C))),
            topLeft = Offset(w * 0.14f, h * 0.30f),
            size = Size(w * 0.72f, h * 0.50f),
            cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
        )
        // White central play triangle inside glass circle
        val c = Offset(w * 0.50f, h * 0.55f)
        drawCircle(color = Color.White.copy(alpha = 0.24f), radius = w * 0.16f, center = c)
        val play = Path().apply {
            moveTo(c.x - w * 0.05f, c.y - h * 0.08f)
            lineTo(c.x + w * 0.09f, c.y)
            lineTo(c.x - w * 0.05f, c.y + h * 0.08f)
            close()
        }
        drawPath(play, color = Color.White)
    }
}

@Composable
fun CuteMusicNoteIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(84.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        drawCircle(
            color = Color(0xFFEC4899).copy(alpha = 0.15f),
            radius = w * 0.44f,
            center = Offset(w * 0.5f, h * 0.52f)
        )
        // Rounded studio soundwave disc
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFFEC4899), Color(0xFF8B5CF6))),
            topLeft = Offset(w * 0.14f, h * 0.18f),
            size = Size(w * 0.72f, h * 0.64f),
            cornerRadius = CornerRadius(w * 0.20f, w * 0.20f)
        )
        // Equalizer bars inside capsule
        val bars = listOf(0.22f, 0.38f, 0.28f, 0.42f, 0.24f)
        bars.forEachIndexed { idx, bh ->
            val bx = w * (0.27f + idx * 0.105f)
            val top = h * (0.50f - bh / 2f)
            drawRoundRect(
                color = Color.White,
                topLeft = Offset(bx, top),
                size = Size(w * 0.06f, h * bh),
                cornerRadius = CornerRadius(w * 0.03f, w * 0.03f)
            )
        }
    }
}

@Composable
fun CuteFolderIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(84.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        drawCircle(
            color = Color(0xFF10B981).copy(alpha = 0.15f),
            radius = w * 0.44f,
            center = Offset(w * 0.5f, h * 0.52f)
        )
        // Back emerald folder tab
        drawRoundRect(
            color = Color(0xFF059669),
            topLeft = Offset(w * 0.16f, h * 0.20f),
            size = Size(w * 0.36f, h * 0.24f),
            cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
        )
        // White document sheet peeking out
        drawRoundRect(
            color = Color.White,
            topLeft = Offset(w * 0.22f, h * 0.24f),
            size = Size(w * 0.56f, h * 0.42f),
            cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
        )
        // Front emerald-teal glass folder
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF10B981), Color(0xFF0D9488))),
            topLeft = Offset(w * 0.14f, h * 0.34f),
            size = Size(w * 0.72f, h * 0.46f),
            cornerRadius = CornerRadius(w * 0.15f, w * 0.15f)
        )
        // Data lines on front
        drawRoundRect(
            color = Color.White.copy(alpha = 0.85f),
            topLeft = Offset(w * 0.26f, h * 0.48f),
            size = Size(w * 0.32f, h * 0.06f),
            cornerRadius = CornerRadius(6f, 6f)
        )
        drawRoundRect(
            color = Color.White.copy(alpha = 0.55f),
            topLeft = Offset(w * 0.26f, h * 0.59f),
            size = Size(w * 0.46f, h * 0.06f),
            cornerRadius = CornerRadius(6f, 6f)
        )
    }
}

@Composable
fun CuteSimilarImagesIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(84.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        // Back card
        drawRoundRect(
            color = Color(0xFFA5B4FC),
            topLeft = Offset(w * 0.30f, h * 0.16f),
            size = Size(w * 0.54f, h * 0.54f),
            cornerRadius = CornerRadius(w * 0.12f, w * 0.12f)
        )
        // Front card
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFF06B6D4))),
            topLeft = Offset(w * 0.14f, h * 0.28f),
            size = Size(w * 0.54f, h * 0.54f),
            cornerRadius = CornerRadius(w * 0.12f, w * 0.12f)
        )
        // Sun & mountain inside front card
        drawCircle(color = Color(0xFFFDE047), radius = w * 0.06f, center = Offset(w * 0.52f, h * 0.42f))
        val mPath = Path().apply {
            moveTo(w * 0.20f, h * 0.74f)
            lineTo(w * 0.36f, h * 0.52f)
            lineTo(w * 0.48f, h * 0.66f)
            lineTo(w * 0.56f, h * 0.58f)
            lineTo(w * 0.64f, h * 0.74f)
            close()
        }
        drawPath(mPath, color = Color.White.copy(alpha = 0.9f))
    }
}

@Composable
fun CuteRecoveredBoxIllustration(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(84.dp)) {
        val w = size.width
        val h = size.height
        // Vault base
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF4F46E5), Color(0xFF0891B2))),
            topLeft = Offset(w * 0.14f, h * 0.22f),
            size = Size(w * 0.72f, h * 0.62f),
            cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
        )
        // Inner circular vault dial + upward restore arrow
        val c = Offset(w * 0.50f, h * 0.53f)
        drawCircle(color = Color(0xFF0F172A), radius = w * 0.20f, center = c)
        val arrow = Path().apply {
            moveTo(c.x, c.y - h * 0.11f)
            lineTo(c.x + w * 0.09f, c.y - h * 0.01f)
            lineTo(c.x + w * 0.035f, c.y - h * 0.01f)
            lineTo(c.x + w * 0.035f, c.y + h * 0.10f)
            lineTo(c.x - w * 0.035f, c.y + h * 0.10f)
            lineTo(c.x - w * 0.035f, c.y - h * 0.01f)
            lineTo(c.x - w * 0.09f, c.y - h * 0.01f)
            close()
        }
        drawPath(arrow, color = Color(0xFF2DD4BF))
    }
}

@Composable
fun CuteNotificationBellIllustration(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(78.dp)) {
        val w = size.width
        val h = size.height
        // Bell dome
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFFF59E0B), Color(0xFFD97706))),
            topLeft = Offset(w * 0.22f, h * 0.22f),
            size = Size(w * 0.56f, h * 0.48f),
            cornerRadius = CornerRadius(w * 0.26f, w * 0.26f)
        )
        // Base rim
        drawRoundRect(
            color = Color(0xFFB45309),
            topLeft = Offset(w * 0.16f, h * 0.62f),
            size = Size(w * 0.68f, h * 0.11f),
            cornerRadius = CornerRadius(w * 0.06f, w * 0.06f)
        )
        drawCircle(color = Color(0xFF78350F), radius = w * 0.08f, center = Offset(w * 0.50f, h * 0.77f))
        // Live red notification dot
        drawCircle(color = Color(0xFFEF4444), radius = w * 0.10f, center = Offset(w * 0.72f, h * 0.26f))
        drawCircle(color = Color.White, radius = w * 0.04f, center = Offset(w * 0.72f, h * 0.26f))
    }
}

@Composable
fun CuteTrashCanIllustration(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(78.dp)) {
        val w = size.width
        val h = size.height
        // Cyber sweep turbine ring
        drawCircle(
            brush = Brush.linearGradient(listOf(Color(0xFF06B6D4), Color(0xFF3B82F6))),
            radius = w * 0.36f,
            center = Offset(w * 0.50f, h * 0.52f)
        )
        drawCircle(
            color = Color.White,
            radius = w * 0.24f,
            center = Offset(w * 0.50f, h * 0.52f),
            style = Stroke(width = w * 0.06f)
        )
        drawCircle(
            color = Color.White,
            radius = w * 0.08f,
            center = Offset(w * 0.50f, h * 0.52f)
        )
    }
}

@Composable
fun CuteRedPhoneIllustration(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(78.dp)) {
        val w = size.width
        val h = size.height
        // Contact ID badge card
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF8B5CF6), Color(0xFF6D28D9))),
            topLeft = Offset(w * 0.16f, h * 0.20f),
            size = Size(w * 0.68f, h * 0.62f),
            cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
        )
        // Avatar head & shoulders
        drawCircle(color = Color.White, radius = w * 0.11f, center = Offset(w * 0.50f, h * 0.42f))
        drawRoundRect(
            color = Color.White.copy(alpha = 0.9f),
            topLeft = Offset(w * 0.32f, h * 0.56f),
            size = Size(w * 0.36f, h * 0.14f),
            cornerRadius = CornerRadius(w * 0.08f, w * 0.08f)
        )
    }
}

@Composable
fun CuteScreenshotFrameIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(78.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF14B8A6), Color(0xFF0284C7))),
            topLeft = Offset(w * 0.16f, h * 0.18f),
            size = Size(w * 0.68f, h * 0.64f),
            cornerRadius = CornerRadius(w * 0.16f, w * 0.16f)
        )
        // Viewfinder crop corners
        val stroke = Stroke(width = w * 0.055f, cap = StrokeCap.Round)
        drawRoundRect(
            color = Color.White,
            topLeft = Offset(w * 0.28f, h * 0.30f),
            size = Size(w * 0.44f, h * 0.40f),
            cornerRadius = CornerRadius(w * 0.06f, w * 0.06f),
            style = stroke
        )
    }
}

@Composable
fun CuteDocSheetStackIllustration(modifier: Modifier = Modifier, grayscale: Boolean = false) {
    Canvas(
        modifier = modifier
            .size(72.dp)
            .grayscaleIf(grayscale)
    ) {
        val w = size.width
        val h = size.height
        drawRoundRect(
            color = Color(0xFFA7F3D0),
            topLeft = Offset(w * 0.16f, h * 0.14f),
            size = Size(w * 0.60f, h * 0.70f),
            cornerRadius = CornerRadius(12f, 12f)
        )
        drawRoundRect(
            brush = Brush.linearGradient(listOf(Color(0xFF10B981), Color(0xFF059669))),
            topLeft = Offset(w * 0.24f, h * 0.20f),
            size = Size(w * 0.60f, h * 0.70f),
            cornerRadius = CornerRadius(12f, 12f)
        )
        drawRoundRect(Color.White, Offset(w * 0.34f, h * 0.34f), Size(w * 0.26f, h * 0.07f), CornerRadius(8f, 8f))
        drawRoundRect(Color.White.copy(alpha = 0.8f), Offset(w * 0.34f, h * 0.48f), Size(w * 0.40f, h * 0.07f), CornerRadius(8f, 8f))
        drawRoundRect(Color.White.copy(alpha = 0.8f), Offset(w * 0.34f, h * 0.62f), Size(w * 0.40f, h * 0.07f), CornerRadius(8f, 8f))
    }
}

// ---------- Permissions ----------

fun hasAllFilesAccess(context: Context): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Environment.isExternalStorageManager()
    } else {
        ContextCompat.checkSelfPermission(
            context,
            android.Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
    }

fun manageAllFilesIntent(context: Context): Intent =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Intent(
            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
            Uri.parse("package:${context.packageName}")
        )
    } else {
        Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.parse("package:${context.packageName}")
        )
    }

private fun decodeSampled(path: String, reqW: Int, reqH: Int): Bitmap? {
    val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeFile(path, opts)
    var sample = 1
    if (opts.outHeight > reqH || opts.outWidth > reqW) {
        val halfH = opts.outHeight / 2
        val halfW = opts.outWidth / 2
        while ((halfH / sample) >= reqH && (halfW / sample) >= reqW) sample *= 2
    }
    return BitmapFactory.decodeFile(path, BitmapFactory.Options().apply { inSampleSize = sample })
}

@Composable
fun ApkIconPlaceholder() {
    Icon(
        imageVector = Icons.Filled.Android,
        contentDescription = "APK",
        tint = PrimaryGreen,
        modifier = Modifier.size(32.dp)
    )
}

fun mimeFor(file: RecoverableFile): String = mimeFor(file.category, file.name)

fun mimeFor(category: FileCategory, name: String): String {
    val ext = name.substringAfterLast('.', "").lowercase()
    return when (category) {
        FileCategory.PHOTO -> if (ext == "png") "image/png" else "image/jpeg"
        FileCategory.VIDEO -> "video/*"
        FileCategory.AUDIO -> "audio/*"
        FileCategory.DOCUMENT -> when (ext) {
            "pdf" -> "application/pdf"
            "apk" -> "application/vnd.android.package-archive"
            "txt", "log", "csv", "json", "xml", "md" -> "text/plain"
            "zip" -> "application/zip"
            else -> "*/*"
        }
    }
}

fun openFile(context: Context, file: File, mime: String) {
    runCatching {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.provider", file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(intent, file.name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

