# rename a secret
sos secret rename --name "Demo Note" "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ wait

sos secret rename --name "$NOTE_NAME" "Demo Note"
#$ include ../includes/signin.sh
#$ wait
