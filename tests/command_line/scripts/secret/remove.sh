sos secret remove "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ regex (?i)delete secret
y
#$ regex (?i)secret deleted
#$ wait
