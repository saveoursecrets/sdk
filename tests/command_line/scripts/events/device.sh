# print device event log records
sos events device "$(sos env paths -f device-events)"
#$ wait
