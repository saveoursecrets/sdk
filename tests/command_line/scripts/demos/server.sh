# create a directory to store account data
mkdir -p target/server/accounts
#$ readline

# initialize a config file for the server
sos-server init target/demo/config.toml --path ../server/accounts
#$ readline

cat target/demo/config.toml
#$ expect path = "../server/accounts"

# start the server
sos-server start target/demo/config.toml
#$ regex (?i)tls

#$ sendcontrol ^C
