sos secret attach add password --name "$PASSWORD_ATTACHMENT" "$NOTE_NAME"
#$ include ../../includes/signin.sh
#$ expect Password:
$PASSWORD_ATTACHMENT
#$ regex (?i)updated
#$ wait
