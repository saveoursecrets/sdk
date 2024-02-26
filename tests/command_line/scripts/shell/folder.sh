# create a new folder
folder new "$FOLDER_NAME"
#$ regex (?i)created
#$ wait

# list folders
folder ls -v
#$ wait

# print folder information
folder info -v -f "$FOLDER_NAME"
#$ wait

# print secret keys
folder keys -f "$FOLDER_NAME"
#$ wait

# print event commit hashes
folder commits -f "$FOLDER_NAME"
#$ wait

# rename a folder
folder rename -f "$FOLDER_NAME" "$NEW_FOLDER_NAME"
#$ wait

folder rename -f "$NEW_FOLDER_NAME" "$FOLDER_NAME"
#$ wait

# compact the event log history
folder history compact -f "$FOLDER_NAME"
#$ regex (?i)remove history
y
#$ wait

# check the event log history integrity
folder history check -f "$FOLDER_NAME"
#$ wait

# list event log history
folder history list -f "$FOLDER_NAME"
#$ wait

# remove a folder
folder remove -f "$FOLDER_NAME"
#$ regex (?i)delete folder
y
#$ regex (?i)folder deleted
#$ wait

