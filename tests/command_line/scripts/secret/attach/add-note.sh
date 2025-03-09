sos secret attach add note --name "$NOTE_ATTACHMENT" "$NOTE_NAME"
#$ include ../../includes/signin.sh
#$ expect >>
Text for the note attachment.
#$ expect >>
#$ sendcontrol ^D
#$ regex (?i)updated
#$ wait
