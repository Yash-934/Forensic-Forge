package com.clone.filesrecovery.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val BrandViolet = Color(0xFF6C4CF1)
val BrandVioletDark = Color(0xFF4A2FD6)
val BrandTeal = Color(0xFF00BFA6)
val BrandOrange = Color(0xFFFF8A3D)
val BrandPink = Color(0xFFEF4E7B)
val ScreenBg = Color(0xFFF6F5FB)

private val LightColors = lightColorScheme(
    primary = BrandViolet,
    onPrimary = Color.White,
    secondary = BrandTeal,
    background = ScreenBg,
    surface = Color.White
)

@Composable
fun FilesRecoveryTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = LightColors, content = content)
}
