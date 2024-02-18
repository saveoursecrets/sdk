# create an account

#$ include ../setup/account.sh
#$ include ../includes/screen.sh

# list accounts
#$ include ../account/list.sh

# create a backup archive
#$ include ../account/backup.sh

# now we will always need to sign in

# account info shows the folder list
#$ include ../account/info.sh

#$ include ../includes/screen.sh

# show account statistics
#$ include ../account/stats.sh
