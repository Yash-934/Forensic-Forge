package com.clone.filesrecovery.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Redesigned "DeepVault Studio" palette — Royal Indigo, Cyber Cyan & Crisp Slate
val PrimaryGreen = Color(0xFF4F46E5)        // Royal Indigo primary accent
val PrimaryGreenDark = Color(0xFF3730A3)    // Deep Indigo
val AccentCyan = Color(0xFF06B6D4)          // Cyber Cyan secondary accent
val AccentEmerald = Color(0xFF10B981)       // Emerald success accent
val CheckGreen = Color(0xFF10B981)          // Emerald check badge
val CheckHaloGreen = Color(0xFFEEF2FF)      // Soft Indigo halo
val CoralRed = Color(0xFFF43F5E)            // Rose-Crimson accent
val SelectionOrange = Color(0xFFF59E0B)     // Amber selection accent
val CapacityBlue = Color(0xFF3B82F6)        // Sapphire Blue accent
val BgLight = Color(0xFFF4F6FB)             // Cool Slate Alabaster background
val SurfaceLight = Color(0xFFFFFFFF)
val SoftGrayCard = Color(0xFFF1F5F9)        // Slate 100 card fill
val CapacityDarkCard = Color(0xFF0F172A)    // Midnight Slate hero card
val CapacityDarkEnd = Color(0xFF1E1B4B)     // Deep Indigo hero gradient end
val TextPrimary = Color(0xFF0F172A)         // Slate 900
val TextSecondary = Color(0xFF64748B)       // Slate 500

// Storage breakdown colors
val CapAudioPink = Color(0xFFF43F5E)        // Rose
val CapVideoOrange = Color(0xFFF59E0B)      // Amber
val CapImagesYellow = Color(0xFF06B6D4)     // Cyan
val CapDocsGreen = Color(0xFF10B981)        // Emerald
val CapOtherBlue = Color(0xFF8B5CF6)        // Violet
val CapAvailableGray = Color(0xFF334155)    // Slate 700

// Category accent colors
val AccentPhoto = Color(0xFF3B82F6)         // Sapphire Blue
val AccentVideo = Color(0xFFF97316)         // Vivid Orange
val AccentAudio = Color(0xFFEC4899)         // Electric Rose
val AccentDoc = Color(0xFF10B981)           // Emerald Teal
val AccentContact = Color(0xFF8B5CF6)       // Royal Violet
val AccentNotify = Color(0xFFF59E0B)        // Amber Gold
val AccentJunk = Color(0xFF06B6D4)          // Cyber Cyan

private val ColorScheme = lightColorScheme(
    primary = PrimaryGreen,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE0E7FF),
    onPrimaryContainer = PrimaryGreenDark,
    secondary = AccentCyan,
    onSecondary = Color.White,
    background = BgLight,
    onBackground = TextPrimary,
    surface = SurfaceLight,
    onSurface = TextPrimary,
    surfaceVariant = SoftGrayCard,
    onSurfaceVariant = TextSecondary
)

@Composable
fun FilesRecoveryTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ColorScheme,
        content = content
    )
}
