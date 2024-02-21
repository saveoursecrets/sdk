  # secret::attach(&exe, &address, &password, ACCOUNT_NAME, None).await?;

#$ include ../secret/add-note.sh
#$ include ../secret/add-file.sh
#$ include ../secret/list.sh
#$ include ../secret/get-note.sh
#$ include ../secret/copy.sh
#$ include ../secret/info.sh
#$ include ../secret/info-json.sh

#$ include ../secret/download.sh

# TODO: update secret

#$ include ../folder/new.sh
#$ include ../secret/move.sh
#$ include ../folder/remove.sh

#$ include ../secret/tags/add.sh
#$ include ../secret/tags/list.sh
#$ include ../secret/tags/remove.sh
#$ include ../secret/tags/clear.sh

# Toggle favorite on then off again
#$ include ../secret/favorite.sh
#$ include ../secret/favorite.sh

#$ include ../secret/archive.sh
#$ include ../secret/unarchive.sh

#$ include ../secret/comment.sh
#$ include ../secret/rename.sh

#$ include ../secret/remove.sh
