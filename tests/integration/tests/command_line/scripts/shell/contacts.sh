account contacts export --force $CONTACTS_EXPORT
#$ regex (?i)contacts exported
#$ wait

account contacts import $ACCOUNT_CONTACTS
#$ regex (?i)contacts imported
#$ wait

