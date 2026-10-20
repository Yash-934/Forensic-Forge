package com.clone.filesrecovery

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.clone.filesrecovery.data.AppStore
import com.clone.filesrecovery.data.ContactInfo
import com.clone.filesrecovery.data.ContactsHelper
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.FileScanner
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.RecoveredRecord
import com.clone.filesrecovery.data.SavedNotification
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AppViewModel(app: Application) : AndroidViewModel(app) {

    // ---- Scan flow ----
    private val _scanResults = MutableStateFlow<List<RecoverableFile>>(emptyList())
    val scanResults: StateFlow<List<RecoverableFile>> = _scanResults.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanProgressText = MutableStateFlow("")
    val scanProgressText: StateFlow<String> = _scanProgressText.asStateFlow()

    private val _scannedCount = MutableStateFlow(0)
    val scannedCount: StateFlow<Int> = _scannedCount.asStateFlow()

    var currentCategory: FileCategory = FileCategory.PHOTO
    var currentFile: RecoverableFile? = null

    private val _selected = MutableStateFlow<Set<String>>(emptySet())
    val selected: StateFlow<Set<String>> = _selected.asStateFlow()

    private val _isRecovering = MutableStateFlow(false)
    val isRecovering: StateFlow<Boolean> = _isRecovering.asStateFlow()

    /** Fires with the number of recovered files after a recover action finishes. */
    private val _lastRecoveredCount = MutableStateFlow<Int?>(null)
    val lastRecoveredCount: StateFlow<Int?> = _lastRecoveredCount.asStateFlow()

    fun startScan(category: FileCategory) {
        currentCategory = category
        _selected.value = emptySet()
        _scanResults.value = emptyList()
        _isScanning.value = true
        _scannedCount.value = 0
        _scanProgressText.value = ""
        viewModelScope.launch {
            val found = FileScanner.scan(getApplication(), category) { count, path ->
                _scannedCount.value = count
                _scanProgressText.value = path
            }
            _scanResults.value = found
            _isScanning.value = false
        }
    }

    fun toggleSelect(file: RecoverableFile) {
        _selected.value = if (_selected.value.contains(file.path))
            _selected.value - file.path else _selected.value + file.path
    }

    fun selectAll() {
        _selected.value = _scanResults.value.map { it.path }.toSet()
    }

    fun clearSelection() { _selected.value = emptySet() }

    fun recoverSelected() {
        val files = _scanResults.value.filter { _selected.value.contains(it.path) }
        if (files.isEmpty()) return
        _isRecovering.value = true
        viewModelScope.launch {
            val done = FileScanner.recover(getApplication(), files)
            _lastRecoveredCount.value = done.size
            _isRecovering.value = false
            _selected.value = emptySet()
        }
    }

    fun recoverSingle(file: RecoverableFile) {
        _isRecovering.value = true
        viewModelScope.launch {
            val done = FileScanner.recover(getApplication(), listOf(file))
            _lastRecoveredCount.value = done.size
            _isRecovering.value = false
        }
    }

    fun consumeRecoveredEvent() { _lastRecoveredCount.value = null }

    // ---- Recovered history ----
    private val _recovered = MutableStateFlow<List<RecoveredRecord>>(emptyList())
    val recovered: StateFlow<List<RecoveredRecord>> = _recovered.asStateFlow()

    fun loadRecovered() {
        _recovered.value = AppStore.loadRecovered(getApplication())
    }

    // ---- Notifications ----
    private val _notifications = MutableStateFlow<List<SavedNotification>>(emptyList())
    val notifications: StateFlow<List<SavedNotification>> = _notifications.asStateFlow()

    fun loadNotifications() {
        _notifications.value = AppStore.loadNotifications(getApplication())
    }

    fun clearNotifications() {
        AppStore.clearNotifications(getApplication())
        _notifications.value = emptyList()
    }

    // ---- Contacts ----
    private val _contacts = MutableStateFlow<List<ContactInfo>>(emptyList())
    val contacts: StateFlow<List<ContactInfo>> = _contacts.asStateFlow()

    fun loadContacts() {
        viewModelScope.launch { _contacts.value = ContactsHelper.loadContacts(getApplication()) }
    }
}
