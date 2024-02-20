sos folder rename -f $FOLDER_NAME $NEW_FOLDER_NAME
#$ include ../includes/signin.sh
#$ wait

sos folder rename -f $NEW_FOLDER_NAME $FOLDER_NAME
#$ include ../includes/signin.sh
#$ wait
