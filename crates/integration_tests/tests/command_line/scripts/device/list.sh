# list device public keys
sos device ls
#$ include ../includes/signin.sh
#$ wait

# print trusted devices as JSON
sos device ls -v
#$ include ../includes/signin.sh
#$ wait
