# create a new folder
sos folder new "$FOLDER_NAME"
#$ include ../includes/signin.sh
#$ regex (?i)created
#$ wait

# list folders
sos folder ls -v
#$ include ../includes/signin.sh
#$ wait

#$ include ../includes/screen.sh
