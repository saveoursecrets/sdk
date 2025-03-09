sos account migrate export $MIGRATE_EXPORT
#$ include ../../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait

sos account migrate export --force $MIGRATE_EXPORT
#$ include ../../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait
