sos secret add note
#$ include ../includes/signin.sh
#$ expect Name:
Example Note
#$ expect >>
This is the text for the secret note.
#$ sendcontrol ^D
#$ wait
