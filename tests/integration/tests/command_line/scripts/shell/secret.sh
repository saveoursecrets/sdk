# create a note
secret add note
#$ expect Name:
$NOTE_NAME
#$ expect >>
Text for the secret note.
#$ expect >>
#$ sendcontrol ^D
#$ wait

# create a file
secret add file -n "$FILE_NAME" "$FILE_INPUT"
#$ regex (?i)created
#$ wait

# create a login
secret add login --name "$LOGIN_NAME"
#$ expect Username:
$LOGIN_SERVICE_NAME
#$ expect Website:
$LOGIN_URL
#$ expect Password:
$LOGIN_PASSWORD
#$ regex (?i)created
#$ wait

# create a list
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

# list secrets
secret ls -f Documents
#$ wait

# view secrets
secret get "$NOTE_NAME"
#$ wait

secret get "$FILE_NAME"
#$ wait

secret get "$LOGIN_NAME"
#$ wait

secret get "$LIST_NAME"
#$ wait

# copy to clipboard
secret copy "$NOTE_NAME"
#$ wait

# print secret information
secret info "$NOTE_NAME"
#$ wait

secret info --json "$NOTE_NAME"
#$ wait

# decrypt and download a file secret
secret download --force "$FILE_NAME" "$FILE_OUTPUT"
#$ regex (?i)download complete
#$ wait

# add attachments to a secret
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

# read an attachment
secret attach get "$NOTE_NAME" "$NOTE_ATTACHMENT"
#$ wait

# list attachments
secret attach ls -v "$NOTE_NAME"
#$ wait

# remove an attachment
secret attach rm "$NOTE_NAME" "$NOTE_ATTACHMENT"
#$ wait

# move a secret between folders
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

# create, list and remove tags
secret tags add --tags foo,bar,qux "$NOTE_NAME"
#$ wait

secret tags list "$NOTE_NAME"
#$ wait

secret tags rm --tags foo,bar "$NOTE_NAME"
#$ wait

secret tags clear "$NOTE_NAME"
#$ wait

# toggle favorite for a secret
secret favorite "$NOTE_NAME"
#$ wait

secret favorite "$NOTE_NAME"
#$ wait

# move a secret to and from the archive
secret archive "$NOTE_NAME"
#$ regex (?i)moved to archive
#$ wait

secret unarchive "$NOTE_NAME"
#$ regex (?i)restored from archive
#$ wait

# modify secret comments
secret comment --text 'Mock comment' "$NOTE_NAME"
#$ wait

secret comment --text '' "$NOTE_NAME"
#$ wait

# rename a secret
secret rename --name "Demo Note" "$NOTE_NAME"
#$ wait

secret rename --name "$NOTE_NAME" "Demo Note"
#$ wait

# delete a secret
secret remove "$NOTE_NAME"
#$ regex (?i)delete secret
y
#$ regex (?i)secret deleted
#$ wait
