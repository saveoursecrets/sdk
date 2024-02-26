account migrate export --force target/demo-export.zip
#$ regex (?i)export unencrypted
y
#$ wait

account migrate import --format onepassword.csv $MIGRATE_1PASSWORD
#$ regex (?i)imported
#$ wait

account migrate import --format dashlane.zip $MIGRATE_DASHLANE
#$ regex (?i)imported
#$ wait

account migrate import --format bitwarden.csv $MIGRATE_BITWARDEN
#$ regex (?i)imported
#$ wait

account migrate import --format firefox.csv $MIGRATE_FIREFOX
#$ regex (?i)imported
#$ wait

account migrate import --format macos.csv $MIGRATE_MACOS
#$ regex (?i)imported
#$ wait

