sos secret attach download "$NOTE_NAME" "$FILE_ATTACHMENT" "$ATTACH_OUTPUT"
#$ include ../../includes/signin.sh
#$ regex (?i)download complete
#$ wait
