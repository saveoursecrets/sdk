sos secret attach add link --name "$LINK_ATTACHMENT" "$NOTE_NAME"
#$ include ../../includes/signin.sh
#$ expect URL:
$LINK_VALUE
#$ regex (?i)updated
#$ wait
