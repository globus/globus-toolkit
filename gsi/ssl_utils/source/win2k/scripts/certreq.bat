@echo off
rem batch file to create a certificate request 
rem

ssleay req -config ssleay.conf -new -out newreq.pem -keyout newkey.pem


@echo
echo other things to be done:
echo edit the x509.bat. It can be called from the autoexec.bat
@echo 
echo Copy the 42864e48.0 to your certdir 
echo Copy the newkey.pem to youy userkey.pem
echo Mail the newreq.pem to ca@globus.org
echo When the CA returns the certificate, save it
echo as the usercert.pem 

