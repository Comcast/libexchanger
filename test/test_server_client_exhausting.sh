#!/bin/bash
count=1000
valgrind_cmd=""
port=12345
aad="Some additional data"
c="client"
s="server"
p=1234567
M="HMAC"
G="P-384"
H="SHA512"
A="127.0.0.1"
i=""
d=""
f=""
m="Client invocation number"

while getopts "A:a:c:d:f:G:H:i:M:m:n:P:p:s:vh" opt; do
  case ${opt} in
    A ) 
        A=$OPTARG
      ;;
    a ) 
        aad=$OPTARG
      ;;
    c )
        c=$OPTARG
      ;;
    d )
        d="-d$OPTARG"
      ;;
    f )
        f="-f$OPTARG"
      ;;
    G )
        G=$OPTARG
      ;;
    H )
        H=$OPTARG
      ;;
    i )
        i="-i$OPTARG"
      ;;
    M )
        M=$OPTARG
      ;;
    m )
        m=$OPTARG
      ;;
    n ) 
        count=$OPTARG
      ;;
    P )
        port=$OPTARG
      ;;
    p )
        p=$OPTARG
      ;;
    s )
        s=$OPTARG
      ;;
    v ) 
        valgrind_cmd="valgrind -v --tool=memcheck --track-origins=yes --leak-check=full --show-leak-kinds=all "
      ;;
    h ) 
        echo "Usage: $0 <options>"
        echo "        [-h] - print this Usage information"
        echo "        [-v] - enable Valgrind memcheck for server invocation for multiple client processing"
        echo "        [-p <password>] - Password"
        echo "        [-A <Server address>] - IP address to connect to"
        echo "        [-P <server port>] - UDP port number to conect to, default is 12345"
        echo "        [-s <server id>] - default is server"
        echo "        [-c <client id>] - default is client"
        echo "        [-a <additional string>] - default is Use SPAKE2+ latest version."
        echo "        [-G <EC group name>] - One of P-256, P-384, P-521, default is P-256"
        echo "        [-H <hash function name>] - SHA256 or SHA512, default is SHA256"
        echo "        [-M <MAC function name>] - HMAC or CMAC, default is HMAC"
        echo "        [-n <max number of processed clients>] - maximal number of processed clients,  default is 0 (unlimited)"
        echo "        [-i <interface name>] - name of interface to be used, by default are used all interfaces (Linux only)"
        echo "        [-d <directory>] - directory to store files and messages, default is /tmp"
        echo "        [-m <message to server>] - message (default is Client invocation number) to be appended by invocation number"
        exit 0
      ;;
  esac
done

valid=1

while [ $valid -eq 1 ]
do
    ( netstat -atulpn | grep ":$port " ) >& /dev/null
    result=$?
    if [ $result == 0 ]; then
     echo "Port $port is occupied."
        port=$(( port + 1 ))
    else
        valid=0
    echo "Port $port is free."
    fi
done

./server -p "$p" -s "$s" -c "$c" -a "$aad" -G "$G" -H "$H" -M "$M" 
retcode=$?
if [ $retcode -ne 0 ]
then
    echo "Failed to initialize server, exit code is $retcode"
    exit 1;
fi

$valgrind_cmd ./server -s "$s" -c "$c" -a "$aad" -G "$G" -H "$H" -M "$M" -P $port -n $count "$i" "$d" &


valid=1

while [ $valid -eq 1 ]
do
    ( netstat -atulpn | grep ":$port " ) >& /dev/null
    result=$?
    if [ $result == 0 ]; then
        valid=0
    else
        sleep 0.1
    fi
done

for (( counter=0; counter < $count; counter++ ))
do
    ./client -p "$p" -A "$A" -s "$s" -c "$c" -a "$aad" -G "$G" -H "$H" -M "$M" -P $port -m "$m $counter" "$f"
    retcode=$?
    if [ $retcode -ne 0 ]
    then
        echo "Failed to initialize server, exit code is $retcode"
        exit 1;
    fi
done

