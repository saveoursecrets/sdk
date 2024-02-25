# create a new folder
#$ include ../folder/new.sh

# list folders
#$ include ../folder/list.sh

# get information about a folder
#$ include ../folder/info.sh

# add a secret to the folder
sos secret add file -f "$FOLDER_NAME" -n "$FILE_NAME" "$FILE_INPUT"
#$ include ../includes/signin.sh
#$ regex (?i)created
#$ wait

#$ include ../includes/screen.sh

# print secret identifiers
#$ include ../folder/keys.sh

# inspect folder commit hashes 
#$ include ../folder/commits.sh

# remove a folder
#$ include ../folder/remove.sh
