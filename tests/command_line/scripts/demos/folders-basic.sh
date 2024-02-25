# create a new folder
#$ include ../folder/new.sh

# list folders
#$ include ../folder/list.sh

# get information about a folder
#$ include ../folder/info.sh

# add a secret to the folder
sos secret add login -f "$FOLDER_NAME" --name "$LOGIN_NAME"
#$ include ../includes/signin.sh
#$ expect Username:
$LOGIN_SERVICE_NAME
#$ expect Website:
$LOGIN_URL
#$ expect Password:
$LOGIN_PASSWORD
#$ regex (?i)created
#$ wait

#$ include ../includes/screen.sh

# print secret identifiers
#$ include ../folder/keys.sh

# inspect folder commit hashes 
#$ include ../folder/commits.sh

# remove a folder
#$ include ../folder/remove.sh
