import webview
import os
import sys
import threading
import base64
import zipfile
import io
from pathlib import Path
from vault_logic import Vault, VaultError, VaultLockedError, VaultOfflineError

class VaultAPI:
    def __init__(self):
        self._vault = Vault()
        self._window = None

    def set_window(self, window):
        self._window = window

    def get_all_locks(self):
        try:
            return self._vault.get_all_locks()
        except Exception as e:
            raise Exception(str(e))

    def pick_file(self):
        """Open a native file picker and return the selected path (or None)."""
        if self._window:
            result = self._window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=('All files (*.*)',)
            )
            if result and len(result) > 0:
                return result[0]
        return None

    def pick_folder(self):
        """Open a native folder picker and return the selected path (or None)."""
        if self._window:
            result = self._window.create_file_dialog(webview.FOLDER_DIALOG)
            if result and len(result) > 0:
                return result[0]
        return None

    def lock(self, name: str, secret: str, minutes: float):
        try:
            days = float(minutes) / (24 * 60)
            self._vault.lock(name, secret, days)
            return True
        except Exception as e:
            raise Exception(str(e))
            
    def lock_file(self, name: str, filepath: str, minutes: float):
        """Stream-encrypt any-size file into the vault. RAM peak: 8 MB."""
        try:
            path = Path(filepath)
            if not path.is_file():
                raise ValueError(f"Not a file: {filepath}")
            days = float(minutes) / (24 * 60)
            self._vault.lock_large(name, path, path.name, days)
            return True
        except Exception as e:
            raise Exception(str(e))

    def lock_folder(self, name: str, folderpath: str, minutes: float):
        """Zip folder to a temp file, stream-encrypt it, then delete the temp zip."""
        import tempfile
        try:
            folder = Path(folderpath)
            if not folder.is_dir():
                raise ValueError(f"Not a folder: {folderpath}")

            print("⚠️ WARNING: Folder is being zipped to your system's temp directory before encryption. If the application crashes or loses power during this process, an unencrypted ZIP of this folder may remain in your temp folder.")
            # Zip to a temp file on disk (streaming, not in memory)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                tmp_path = Path(tmp.name)

            try:
                with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for f in folder.rglob('*'):
                        if f.is_file():
                            zf.write(f, f.relative_to(folder.parent))
                days = float(minutes) / (24 * 60)
                zip_name = folder.name + '.zip'
                self._vault.lock_large(name, tmp_path, zip_name, days)
            finally:
                tmp_path.unlink(missing_ok=True)

            return True
        except Exception as e:
            raise Exception(str(e))

    def reveal_large(self, name: str, filename: str):
        """Stream-decrypt a large file lock directly to Downloads. No base64 in transit."""
        try:
            downloads = (Path.home() / 'Downloads').resolve()
            downloads.mkdir(exist_ok=True)

            safe_name = Path(filename).name or 'revealed_file'
            out_path = downloads / safe_name
            counter = 1
            while out_path.exists():
                stem, suffix = Path(safe_name).stem, Path(safe_name).suffix
                out_path = downloads / f"{stem} ({counter}){suffix}"
                counter += 1

            if not str(out_path.resolve()).startswith(str(downloads)):
                raise PermissionError("Resolved path escapes Downloads.")

            self._vault.reveal_to_file(name, out_path)
            return str(out_path)
        except Exception as e:
            raise Exception(str(e))

    def save_revealed_file(self, name: str, b64_data: str, filename: str):
        """Decode and save a revealed file to the user's Downloads folder."""
        try:
            downloads = (Path.home() / 'Downloads').resolve()
            downloads.mkdir(exist_ok=True)

            # Security: strip to basename only — prevent path traversal like ../../evil.exe
            safe_name = Path(filename).name
            if not safe_name or safe_name in ('.', '..'):
                safe_name = 'revealed_file'

            out_path = downloads / safe_name
            counter = 1
            while out_path.exists():
                stem = Path(safe_name).stem
                suffix = Path(safe_name).suffix
                out_path = downloads / f"{stem} ({counter}){suffix}"
                counter += 1

            # Final guard: resolved path must still be inside Downloads
            if not str(out_path.resolve()).startswith(str(downloads)):
                raise PermissionError("Resolved output path escapes Downloads directory.")

            out_path.write_bytes(base64.b64decode(b64_data))
            return str(out_path)
        except Exception as e:
            raise Exception(str(e))

    def reveal(self, name: str):
        try:
            return self._vault.reveal(name)
        except Exception as e:
            raise Exception(str(e))

    def delete_lock(self, name: str):
        try:
            return self._vault.delete_lock(name)
        except Exception as e:
            raise Exception(str(e))

def main():
    api = VaultAPI()
    html_path = Path(os.path.abspath('vault_v3.html')).as_uri()
    
    window = webview.create_window(
        "God's Hands",
        url=html_path,
        js_api=api,
        width=500,
        height=800,
        background_color='#0D0D0D'
    )
    api.set_window(window)
    
    # Enable debugging to allow pywebview console if preferred
    webview.start(debug=False)

if __name__ == '__main__':
    main()
