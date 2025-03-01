# print the first 5 audit log events
sos tool audit logs -c 5 $(sos env paths -f audit)
#$ wait

# print the last 5 audit log events
sos tool audit logs -r -c 5 $(sos env paths -f audit)
#$ wait

# print the events as JSON
sos tool audit logs -c 5 -j $(sos env paths -f audit)
#$ wait
