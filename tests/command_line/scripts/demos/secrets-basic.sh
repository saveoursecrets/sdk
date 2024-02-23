# create a new secret note
#$ include ../secret/add-note.sh
#$ include ../includes/screen.sh

# now we can list the secrets in the folder
sos secret ls
#$ include ../includes/signin.sh
#$ wait

# and view the secret
#$ include ../secret/get-note.sh

#$ include ../includes/screen.sh

# or copy it to the clipboard
#$ include ../secret/copy.sh

#$ include ../includes/screen.sh

# rename a secret
sos secret rename --name "Demo Note" "$NOTE_NAME"
#$ include ../includes/signin.sh
#$ wait

#$ include ../includes/screen.sh

#$ include ../includes/end-demo.sh
