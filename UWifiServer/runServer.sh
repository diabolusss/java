#!/bin/bash
JARNAME="UWifiServer"
PID=""

function get_pid {
   PID=`cat $JARNAME.pid`
}

function stop {
   get_pid
   if [ -z $PID ]; then
      echo "Server is not running."
      exit 1
   else
      echo -n "Stopping Server.."
      kill $PID
    rm $JARNAME.pid
      sleep 1
      echo ".. Done."
   fi
}

function start {
   get_pid   
   _now=$(date +"%m_%d_%Y_%HH:%MM:%SS")
   myip=$(curl ipecho.net/plain)
   echo $myip"["$_now"]" > $JARNAME.log
   if [ -z $PID ]; then
      echo  "Starting Server.." 
    java -jar $JARNAME.jar >> $JARNAME.log &
    echo $! > $JARNAME.pid
    get_pid
      echo "Done. PID=$PID"
   else
      echo "Server is already running, PID=$PID"
   fi
}

function restart {
   echo  "Server Strategy.."
   get_pid
   if [ -z $PID ]; then
      start
   else
      stop
      start
   fi
}


function status {
   get_pid
   if [ -z  $PID ]; then
      echo "Server is not running."
      exit 1
   else
      echo "Server is running, PID=$PID"
   fi
}

case "$1" in
   start)
      start
   ;;
   stop)
      stop
   ;;
   restart)
      restart
   ;;
   status)
      status
   ;;
   *)
      echo "Usage: $0 {start|stop|restart|status}"
        restart

esac
