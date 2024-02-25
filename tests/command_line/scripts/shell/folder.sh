folder new "$FOLDER_NAME"
#$ regex (?i)created
#$ wait

folder ls -v
#$ wait

folder info -v
#$ wait

folder keys -f "$FOLDER_NAME"
#$ wait

folder commits -f "$FOLDER_NAME"
#$ wait

folder rename -f "$FOLDER_NAME" "$NEW_FOLDER_NAME"
#$ wait

folder rename -f "$NEW_FOLDER_NAME" "$FOLDER_NAME"
#$ wait

folder history compact -f "$FOLDER_NAME"
#$ regex (?i)remove history
y
#$ wait

folder history check -f "$FOLDER_NAME"
#$ wait

folder history list -f "$FOLDER_NAME"
#$ wait

folder remove -f "$FOLDER_NAME"
#$ regex (?i)delete folder
y
#$ regex (?i)folder deleted
#$ wait

