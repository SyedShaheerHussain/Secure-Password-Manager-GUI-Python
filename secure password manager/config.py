import os

# ------------------- APP SETTINGS -------------------
APP_WIDTH = 1024
APP_HEIGHT = 700
AUTO_LOCK_SECONDS = 300         # Auto-lock vault after 5 mins
CLIPBOARD_CLEAR_SECONDS = 30    # Clipboard auto-clear time

# ------------------- DATABASE -------------------
DB_FILE = os.path.join(os.getcwd(), "secure_password_manager.db")

# ------------------- BACKUPS -------------------
BACKUP_DIR = os.path.join(os.getcwd(), "vault_backups")
os.makedirs(BACKUP_DIR, exist_ok=True)  # Ensure backup folder exists
