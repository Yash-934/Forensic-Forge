package com.clone.filesrecovery

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.ui.ContactsScreen
import com.clone.filesrecovery.ui.DetailScreen
import com.clone.filesrecovery.ui.FilesRecoveryTheme
import com.clone.filesrecovery.ui.FolderBreakdownScreen
import com.clone.filesrecovery.ui.GuideScreen
import com.clone.filesrecovery.ui.HomeScreen
import com.clone.filesrecovery.ui.JunkCleanerScreen
import com.clone.filesrecovery.ui.LanguageScreen
import com.clone.filesrecovery.ui.NotificationsScreen
import com.clone.filesrecovery.ui.PermissionScreen
import com.clone.filesrecovery.ui.RecoveredScreen
import com.clone.filesrecovery.ui.ResultScreen
import com.clone.filesrecovery.ui.ScanScreen
import com.clone.filesrecovery.ui.ScreenshotCleanerScreen
import com.clone.filesrecovery.ui.SettingsScreen
import com.clone.filesrecovery.ui.SimilarImagesScreen
import com.clone.filesrecovery.ui.StorageScreen

/**
 * Single-activity Compose app matching the exact screen flows and UI
 * from the reference File Recovery screenshots.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            FilesRecoveryTheme {
                val nav = rememberNavController()
                val vm: AppViewModel = viewModel()
                NavHost(navController = nav, startDestination = "home") {
                    composable("guide") {
                        GuideScreen(onDone = { nav.navigate("language") { popUpTo("guide") { inclusive = true } } })
                    }
                    composable("language") {
                        LanguageScreen(onDone = {
                            if (!nav.popBackStack()) {
                                nav.navigate("home") { popUpTo(0) { inclusive = true } }
                            }
                        })
                    }
                    composable("home") { HomeScreen(nav, vm) }
                    composable(
                        "permission/{category}",
                        arguments = listOf(navArgument("category") { type = NavType.StringType })
                    ) { entry ->
                        val cat = runCatching {
                            FileCategory.valueOf(entry.arguments?.getString("category") ?: "PHOTO")
                        }.getOrDefault(FileCategory.PHOTO)
                        PermissionScreen(nav, cat)
                    }
                    composable(
                        "scan/{category}",
                        arguments = listOf(navArgument("category") { type = NavType.StringType })
                    ) { entry ->
                        val cat = runCatching {
                            FileCategory.valueOf(entry.arguments?.getString("category") ?: "PHOTO")
                        }.getOrDefault(FileCategory.PHOTO)
                        ScanScreen(nav, vm, cat)
                    }
                    composable("folders") { FolderBreakdownScreen(nav, vm) }
                    composable("results") { ResultScreen(nav, vm) }
                    composable("detail") { DetailScreen(nav, vm) }
                    composable("recovered") { RecoveredScreen(nav, vm) }
                    composable("similar") { SimilarImagesScreen(nav, vm) }
                    composable("screenshots") { ScreenshotCleanerScreen(nav, vm) }
                    composable("contacts") { ContactsScreen(nav, vm) }
                    composable("notifications") { NotificationsScreen(nav, vm) }
                    composable("junk") { JunkCleanerScreen(nav) }
                    composable("storage") { StorageScreen(nav) }
                    composable("settings") { SettingsScreen(nav) }
                }
            }
        }
    }
}
