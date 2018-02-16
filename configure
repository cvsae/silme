#!/bin/bash
set -e




# source directory
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}" )"; pwd)


if [[ ! -e $HOME"/.silme" ]]; then
    echo "silme_db does not exist"
    echo "please run python main.py first"
    exit 1
fi


silme_config=$HOME"/.silme/silme.conf"
function read_config()
{
    text=$1
    echo `grep -e ^$text $silme_config |awk -F\= '{print $2}' | tail -n 1| tr -d ' '`
}
function write_config()
{
    sed -i -s "s#$1 =.*#$1 = $2#" $silme_config
}

# create config file
if [ ! -f $silme_config ]; then
    echo "Creating config file"
    cp $source_dir"/silme-sample.conf" $silme_config
fi


# read username
user=$(read_config "username")
if ! [ "$user" ]; then
    read -p "username for running daemon (default: silme) " -r
    if [ $REPLY ]; then
	user=$REPLY
    else
	user="silme"
    fi 
    write_config "username" $user
fi


password=$(read_config "password")
if ! [ "$password" ]; then
    read -p "password for running daemon: " -r
    if [ $REPLY ]; then
    password=$REPLY
    else
        exit
    
    fi 
    write_config "password" $password
fi




# create log file
logfile=$(read_config "logfile")
if ! [ -f $logfile ]; then
    touch $logfile
fi





# finish
echo "Configuration written to $silme_config."