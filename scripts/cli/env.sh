#!/bin/sh

set -e

export SOS_DATA_DIR="target/accounts"
export ACCOUNT_NAME="Demo"
export ACCOUNT_PASSWORD="demo-test-password-case"
export ACCOUNT_BACKUP="target/demo-backup.zip"
export ACCOUNT_CONTACTS="tests/fixtures/contacts.vcf"
export CONTACTS_EXPORT="target/demo-contacts.vcf"

export DEFAULT_FOLDER_NAME="Documents"
export FOLDER_NAME="mock-folder"
export NEW_FOLDER_NAME="mock-folder-renamed"

export FILE_INPUT="tests/fixtures/sample.heic"
export FILE_OUTPUT="target/sample-download.heic"

export NOTE_NAME="mock note"
export FILE_NAME="mock file";

export MIGRATE_1PASSWORD="tests/fixtures/migrate/1password-export.csv"
export MIGRATE_DASHLANE="tests/fixtures/migrate/dashlane-export.zip"
export MIGRATE_BITWARDEN="tests/fixtures/migrate/bitwarden-export.csv"
export MIGRATE_FIREFOX="tests/fixtures/migrate/firefox-export.csv"
export MIGRATE_MACOS="tests/fixtures/migrate/macos-export.csv"
