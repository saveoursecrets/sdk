sos shell
#$ include ../includes/signin.sh
#$ wait

quit
#$ wait

sos shell
#$ include ../includes/signin.sh
#$ wait

#############################################################
# BASIC
#############################################################

whoami
#$ wait
pwd
#$ wait
cd Archive
#$ wait
cd Documents
#$ wait

#############################################################
# SWITCH
#############################################################

account new "$ACCOUNT_NAME_ALT"
#$ expect Choose a password
2
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex create a new account
y
#$ wait

switch "$ACCOUNT_NAME_ALT"
#$ include ../includes/signin.sh
#$ wait

switch "$ACCOUNT_NAME"
#$ include ../includes/signin.sh
#$ wait

#############################################################
# ACCOUNT
#############################################################

account ls -v
#$ wait

account backup --force $ACCOUNT_BACKUP
#$ regex (?i)archive created
#$ wait

account restore $ACCOUNT_BACKUP
#$ regex Overwrite all account
y
#$ include ../includes/signin.sh
#$ wait

account info -v
#$ wait

account stats
#$ wait

account stats --json
#$ wait

account rename -a $ACCOUNT_NAME NewDemo
#$ wait

account rename -a NewDemo $ACCOUNT_NAME
#$ wait

#############################################################
# MIGRATE
#############################################################

account migrate export --force target/demo-export.zip
#$ regex (?i)export unencrypted
y
#$ wait

account migrate import --format onepassword.csv $MIGRATE_1PASSWORD
#$ regex (?i)imported
#$ wait

account migrate import --format dashlane.zip $MIGRATE_DASHLANE
#$ regex (?i)imported
#$ wait

account migrate import --format bitwarden.csv $MIGRATE_BITWARDEN
#$ regex (?i)imported
#$ wait

account migrate import --format firefox.csv $MIGRATE_FIREFOX
#$ regex (?i)imported
#$ wait

account migrate import --format macos.csv $MIGRATE_MACOS
#$ regex (?i)imported
#$ wait

#############################################################
# CONTACTS
#############################################################

account contacts export --force $CONTACTS_EXPORT
#$ regex (?i)contacts exported
#$ wait

account contacts import $ACCOUNT_CONTACTS
#$ regex (?i)contacts imported
#$ wait

#############################################################
# FOLDER
#############################################################

folder new "$FOLDER_NAME"
#$ regex (?i)created
#$ wait

folder ls -v
#$ wait

folder info -v
#$ wait

folder keys -f "$FOLDER_NAME"
#$ wait

folder commits -f "$FOLDER_NAME"
#$ wait

folder rename -f "$FOLDER_NAME" "$NEW_FOLDER_NAME"
#$ wait

folder rename -f "$NEW_FOLDER_NAME" "$FOLDER_NAME"
#$ wait

folder history compact -f "$FOLDER_NAME"
#$ regex (?i)remove history
y
#$ wait

folder history check -f "$FOLDER_NAME"
#$ wait

folder history list -f "$FOLDER_NAME"
#$ wait

folder remove -f "$FOLDER_NAME"
#$ regex (?i)delete folder
y
#$ regex (?i)folder deleted
#$ wait

#############################################################
# SECRET
#############################################################

secret add note
#$ expect Name:
$NOTE_NAME
#$ expect >>
Text for the secret note.
#$ expect >>
#$ sendcontrol ^D
#$ wait

secret add file -n "$FILE_NAME" "$FILE_INPUT"
#$ regex (?i)created
#$ wait

secret add login --name "$LOGIN_NAME"
#$ expect Username:
$LOGIN_SERVICE_NAME
#$ expect Website:
$LOGIN_URL
#$ expect Password:
$LOGIN_PASSWORD
#$ regex (?i)created
#$ wait

secret add list --name "$LIST_NAME"
#$ expect Key:
$LIST_KEY_1
#$ expect Value:
$LIST_VALUE_1
#$ expect Add more
y
#$ expect Key:
$LIST_KEY_2
#$ expect Value:
$LIST_VALUE_2
#$ expect Add more
n
#$ regex (?i)created
#$ wait

secret ls -f Documents
#$ wait

secret get "$NOTE_NAME"
#$ wait

secret get "$FILE_NAME"
#$ wait

secret get "$LOGIN_NAME"
#$ wait

secret get "$LIST_NAME"
#$ wait

secret copy "$NOTE_NAME"
#$ wait

secret info "$NOTE_NAME"
#$ wait

secret info --json "$NOTE_NAME"
#$ wait

secret download --force "$FILE_NAME" "$FILE_OUTPUT"
#$ regex (?i)download complete
#$ wait

secret attach add file --name "$FILE_ATTACHMENT" --path "$ATTACH_INPUT" "$NOTE_NAME"
#$ regex (?i)updated
#$ wait

secret attach add note --name "$NOTE_ATTACHMENT" "$NOTE_NAME"
#$ expect >>
Text for the note attachment.
#$ expect >>
#$ sendcontrol ^D
#$ regex (?i)updated
#$ wait

secret attach add link --name "$LINK_ATTACHMENT" "$NOTE_NAME"
#$ expect URL:
$LINK_VALUE
#$ regex (?i)updated
#$ wait

secret attach add password --name "$PASSWORD_ATTACHMENT" "$NOTE_NAME"
#$ expect Password:
$PASSWORD_ATTACHMENT
#$ regex (?i)updated
#$ wait

secret attach get "$NOTE_NAME" "$NOTE_ATTACHMENT"
#$ wait

secret attach ls -v "$NOTE_NAME"
#$ wait

secret attach rm "$NOTE_NAME" "$NOTE_ATTACHMENT"
#$ wait

folder new "$FOLDER_NAME"
#$ regex (?i)created
#$ wait

secret move --target "$FOLDER_NAME" "$NOTE_NAME"
#$ regex (?i)moved
#$ wait

secret move --target "$DEFAULT_FOLDER_NAME" -f "$FOLDER_NAME" "$NOTE_NAME"
#$ regex (?i)moved
#$ wait

folder remove -f "$FOLDER_NAME"
#$ regex (?i)delete folder
y
#$ regex (?i)folder deleted
#$ wait

secret tags add --tags foo,bar,qux "$NOTE_NAME"
#$ wait

secret tags list "$NOTE_NAME"
#$ wait

secret tags rm --tags foo,bar "$NOTE_NAME"
#$ wait

secret tags clear "$NOTE_NAME"
#$ wait

secret favorite "$NOTE_NAME"
#$ wait

secret favorite "$NOTE_NAME"
#$ wait

secret archive "$NOTE_NAME"
#$ regex (?i)moved to archive
#$ wait

secret unarchive "$NOTE_NAME"
#$ regex (?i)restored from archive
#$ wait

secret comment --text 'Mock comment' "$NOTE_NAME"
#$ wait

secret comment --text '' "$NOTE_NAME"
#$ wait

secret rename --name "Demo Note" "$NOTE_NAME"
#$ wait

secret rename --name "$NOTE_NAME" "Demo Note"
#$ wait

secret remove "$NOTE_NAME"
#$ regex (?i)delete secret
y
#$ regex (?i)secret deleted
#$ wait

#############################################################
# TEARDOWN
#############################################################

switch "$ACCOUNT_NAME_ALT"
#$ include ../includes/signin.sh
#$ wait

account delete
#$ include ../includes/signin.sh
#$ regex (?i)delete account
y
#$ regex (?i)account deleted
#$ wait
