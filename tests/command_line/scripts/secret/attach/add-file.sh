sos secret attach add file \
  --name "$FILE_ATTACHMENT" \
  --path "$ATTACH_INPUT" "$NOTE_NAME"
#$ include ../../includes/signin.sh
#$ regex (?i)updated
#$ wait
