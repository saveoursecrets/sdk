sos secret add note
#$ include ../includes/signin.sh
#$ expect Name:
$NOTE_NAME
#$ expect >>
This is the text for the secret note.
#$ sendcontrol ^D
#$ wait
