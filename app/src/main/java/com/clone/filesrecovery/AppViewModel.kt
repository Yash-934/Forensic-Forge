package com.clone.filesrecovery

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.clone.filesrecovery.data.AppStore
import com.clone.filesrecovery.data.ContactInfo
import com.clone.filesrecovery.data.ContactsHelper
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.FileScanner
import com.clone.filesrecovery.data.FolderBucket
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.RecoveredRecord
import com.clone.filesrecovery.data.SavedNotification
import com.clone.filesrecovery.data.StorageBreakdown
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AppViewModel(app: Application) : AndroidViewModel(app) {

    // ---- Storage Capacity Breakdown (Home Screen) ----
    private val _storageBreakdown = MutableStateFlow(StorageBreakdown())
    val storageBreakdown: StateFlow<StorageBreakdown> = _storageBreakdown.asStateFlow()

    fun refreshStorageBreakdown() {
        viewModelScope.launch {
            _storageBreakdown.value = FileScanner.getStorageBreakdown(getApplication())
        }
    }

    // ---- Scan flow ----
    private val _scanResults = MutableStateFlow<List<RecoverableFile>>(emptyList())
    val scanResults: StateFlow<List<RecoverableFile>> = _scanResults.asStateFlow()

    private val _folderBuckets = MutableStateFlow<List<FolderBucket>>(emptyList())
    val folderBuckets: StateFlow<List<FolderBucket>> = _folderBuckets.asStateFlow()

    private val _isPreparing = MutableStateFlow(false)
    val isPreparing: StateFlow<Boolean> = _isPreparing.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanProgressText = MutableStateFlow("")
    val scanProgressText: StateFlow<String> = _scanProgressText.asStateFlow()

    private val _scannedCount = MutableStateFlow(0)
    val scannedCount: StateFlow<Int> = _scannedCount.asStateFlow()

    private val _foundLiveCount = MutableStateFlow(0)
    val foundLiveCount: StateFlow<Int> = _foundLiveCount.asStateFlow()

    var currentCategory: FileCategory = FileCategory.PHOTO
    var currentBucket: FolderBucket? = null
    var currentFile: RecoverableFile? = null

    private val _selected = MutableStateFlow<Set<String>>(emptySet())
    val selected: StateFlow<Set<String>> = _selected.asStateFlow()

    private val _isRecovering = MutableStateFlow(false)
    val isRecovering: StateFlow<Boolean> = _isRecovering.asStateFlow()

    private val _lastRecoveredCount = MutableStateFlow<Int?>(null)
    val lastRecoveredCount: StateFlow<Int?> = _lastRecoveredCount.asStateFlow()

    init {
        refreshStorageBreakdown()
    }

    fun startScan(category: FileCategory) {
        currentCategory = category
        currentBucket = null
        _selected.value = emptySet()
        _scanResults.value = emptyList()
        _folderBuckets.value = emptyList()
        _isPreparing.value = true
        _isScanning.value = true
        _scannedCount.value = 0
        _foundLiveCount.value = 0
        _scanProgressText.value = ""

        viewModelScope.launch {
            // Brief "Preparing" phase matching Screenshots 5 & 8
            delay(850)
            _isPreparing.value = false
            val found = FileScanner.scan(getApplication(), category) { count, foundSoFar, path ->
                _scannedCount.value = count
                _foundLiveCount.value = foundSoFar
                if (path.isNotBlank()) _scanProgressText.value = path
            }
            _scanResults.value = found
            _foundLiveCount.value = found.size
            val buckets = FileScanner.buildFolderBuckets(category, found)
            _folderBuckets.value = buckets
            currentBucket = buckets.firstOrNull { it.isAllBucket } ?: buckets.firstOrNull()
            _isScanning.value = false
        }
    }

    fun selectBucket(bucket: FolderBucket) {
        currentBucket = bucket
        _selected.value = emptySet()
    }

    fun toggleSelect(file: RecoverableFile) {
        _selected.value = if (_selected.value.contains(file.path))
            _selected.value - file.path else _selected.value + file.path
    }

    fun toggleGroupSelection(files: List<RecoverableFile>) {
        val paths = files.map { it.path }.toSet()
        val allSelected = paths.all { _selected.value.contains(it) }
        _selected.value = if (allSelected) {
            _selected.value - paths
        } else {
            _selected.value + paths
        }
    }

    fun selectAll(files: List<RecoverableFile> = currentBucket?.files ?: _scanResults.value) {
        _selected.value = files.map { it.path }.toSet()
    }

    fun clearSelection() {
        _selected.value = emptySet()
    }

    fun recoverSelected() {
        val pool = currentBucket?.files ?: _scanResults.value
        val files = pool.filter { _selected.value.contains(it.path) }
            .ifEmpty { _scanResults.value.filter { _selected.value.contains(it.path) } }
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

    fun consumeRecoveredEvent() {
        _lastRecoveredCount.value = null
    }

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
        viewModelScope.launch {
            _contacts.value = ContactsHelper.loadContacts(getApplication())
        }
    }
}
