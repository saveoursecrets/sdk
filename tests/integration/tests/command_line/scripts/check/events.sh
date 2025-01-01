# verify event log integrity
sos check events $(sos env paths -f identity-events)
#$ wait
