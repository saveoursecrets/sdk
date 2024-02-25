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
