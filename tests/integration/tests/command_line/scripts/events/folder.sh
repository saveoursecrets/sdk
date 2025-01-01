# print folder event log records
sos events folder "$(sos env paths -f identity-events)"
#$ wait
