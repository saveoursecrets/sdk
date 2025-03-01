sos secret add note
#$ include ../includes/signin.sh
#$ expect Name:
$NOTE_NAME
#$ expect >>
Text for the secret note.
#$ expect >>
#$ sendcontrol ^D
#$ wait
