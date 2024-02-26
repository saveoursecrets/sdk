# print the first 5 audit log events
sos audit logs -c 5 target/accounts/local/audit.dat
#$ wait

# print the last 5 audit log events
sos audit logs -r -c 5 target/accounts/local/audit.dat
#$ wait

# print the events as JSON
sos audit logs -c 5 -j target/accounts/local/audit.dat
#$ wait
