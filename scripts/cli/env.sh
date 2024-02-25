export SOS_PROMPT='➜ '
export SOS_OFFLINE=1
export DEMO_SERVER="https://demo.saveoursecrets.com"
export RUST_LOG="sos_net=error,sos_sdk=error"

# suppress the bash is replaced by zsh on macos
# SEE: https://support.apple.com/en-us/102360
export BASH_SILENCE_DEPRECATION_WARNING=1

export SOS_DATA_DIR="target/accounts"
export ACCOUNT_NAME="Demo"
export ACCOUNT_NAME_ALT="Demo Account"
export ACCOUNT_PASSWORD="demo-test-password-case"
export ACCOUNT_BACKUP="target/demo-backup.zip"
export ACCOUNT_CONTACTS="tests/fixtures/contacts.vcf"
export CONTACTS_EXPORT="target/demo-contacts.vcf"

export DEFAULT_FOLDER_NAME="Documents"
export FOLDER_NAME="mock-folder"
export NEW_FOLDER_NAME="mock-folder-renamed"

export FILE_INPUT="tests/fixtures/sample.heic"
export FILE_OUTPUT="target/file-download.heic"

export ATTACH_INPUT="tests/fixtures/test-file.txt"
export ATTACH_OUTPUT="target/attachment-download.txt"

export NOTE_NAME="mock note"
export FILE_NAME="mock file"
export LOGIN_NAME="mock login"
export LIST_NAME="mock list"

export LOGIN_SERVICE_NAME="mock-service"
export LOGIN_URL="https://example.com"
export LOGIN_PASSWORD="mock-login-password"

export LIST_NAME="mock-list";
export LIST_KEY_1="SERVICE_1_API";
export LIST_VALUE_1="mock-key-1";
export LIST_KEY_2="SERVICE_2_API";
export LIST_VALUE_2="mock-key-2";

export FILE_ATTACHMENT="file-attachment";
export NOTE_ATTACHMENT="note-attachment";
export LINK_ATTACHMENT="link-attachment";
export PASSWORD_ATTACHMENT="password-attachment";
export LINK_VALUE="https://example.com";

export MIGRATE_1PASSWORD="tests/fixtures/migrate/1password-export.csv"
export MIGRATE_DASHLANE="tests/fixtures/migrate/dashlane-export.zip"
export MIGRATE_BITWARDEN="tests/fixtures/migrate/bitwarden-export.csv"
export MIGRATE_FIREFOX="tests/fixtures/migrate/firefox-export.csv"
export MIGRATE_MACOS="tests/fixtures/migrate/macos-export.csv"
