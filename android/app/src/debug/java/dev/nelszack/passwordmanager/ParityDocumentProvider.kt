package dev.nelszack.passwordmanager

/** A single cache-only synthetic document. Never shipped in release builds. */
class ParityDocumentProvider : android.content.ContentProvider() {
    private fun file(uri: android.net.Uri): java.io.File {
        check(uri.lastPathSegment == "fixture")
        return requireNotNull(context).cacheDir.resolve("parity-document-fixture")
    }
    override fun onCreate() = true
    override fun getType(uri: android.net.Uri) = "application/octet-stream"
    override fun openFile(uri: android.net.Uri, mode: String) = android.os.ParcelFileDescriptor.open(file(uri), android.os.ParcelFileDescriptor.parseMode(mode))
    override fun query(uri: android.net.Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): android.database.Cursor =
        android.database.MatrixCursor(arrayOf(android.provider.OpenableColumns.DISPLAY_NAME)).apply { addRow(arrayOf("Synthetic document")) }
    override fun insert(uri: android.net.Uri, values: android.content.ContentValues?): android.net.Uri? = throw UnsupportedOperationException()
    override fun update(uri: android.net.Uri, values: android.content.ContentValues?, selection: String?, selectionArgs: Array<out String>?) = throw UnsupportedOperationException()
    override fun delete(uri: android.net.Uri, selection: String?, selectionArgs: Array<out String>?) = if (file(uri).delete()) 1 else 0
}
