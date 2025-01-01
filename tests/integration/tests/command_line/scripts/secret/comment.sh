sos secret comment --text 'Mock comment' "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ wait

sos secret comment --text '' "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ wait
