sos secret move --target "$FOLDER_NAME" "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ regex (?i)moved
#$ wait

sos secret move --target "$DEFAULT_FOLDER_NAME" -f "$FOLDER_NAME" "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ regex (?i)moved
#$ wait
