# print the first 5 audit log events
sos audit logs -c 5 $(sos env paths -f audit)
#$ wait

# print the last 5 audit log events
sos audit logs -r -c 5 $(sos env paths -f audit)
#$ wait

# print the events as JSON
sos audit logs -c 5 -j $(sos env paths -f audit)
#$ wait
