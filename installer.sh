############################ INSTALLATION APACHE + MODSECURITY ###########################################

apt-get update -

apt-get upgarde -y 

apt-get install apache2 -y 

ufw allow 80,443

systemctl enable apache2

apt install libapache2-mod-security2 -y 

a2enmod security2 && a2enmod proxy_http && a2enmod rewrite

systemctl restart apache2

rm -f /etc/apache2/sites-available/000-default.conf

echo "
<VirtualHost *:80>
    ServerName 10.0.15.5
    ProxyPreserveHost On
    ProxyPass / http://10.0.15.10/ 
    ProxyPassReverse / http://10.0.15.10/ 


    AllowEncodedSlashes NoDecode

    <Proxy *>
        Require all granted
    </Proxy>

    <Directory />
        Require all granted
        Options FollowSymLinks
        AllowOverride None
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    SecRuleEngine On
    SecRule ARGS:testparam "@contains test" "id:254,deny,status:403,msg:'Test Successful'"
    #SecRule "@contains cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2" "id:255,deny,status:403,msg:'APACHE CVE DETECTEDl'"
    SecRule REQUEST_URI|ARGS|REQUEST_BODY "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2" "id:504,phase:4,log,deny,msg:'APACHE CVE DETECTED'"
    SecRule REQUEST_URI|ARGS|REQUEST_BODY "..$2" "id:900,phase:4,log,deny,msg:'APACHE CVE DETECTED'"
    SecRule REQUEST_URI "@contains /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2" "id:444,deny,status:403,msg:'APACHE CVE DETECTED'"
</VirtualHost>" > /etc/apache2/sites-available/000-default.conf


mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

rm -f /etc/modsecurity/modsecurity.conf

echo "
SecRuleEngine On
SecRequestBodyAccess On


SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"


SecRule REQUEST_HEADERS:Content-Type "application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"


SecRule REQUEST_URI "@contains /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2" "id:200100,deny,status:403,msg:'APACHE CVE DETECED'"
SecRule REQUEST_URI "@contains ..$2" "id:200110,deny,status:405,msg:'APACHE CVE DETECED'"

SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

SecRequestBodyInMemoryLimit 131072


SecRequestBodyLimitAction Reject


SecRule REQBODY_ERROR "!@eq 0" \
"id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"


SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:'200003',phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"


SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"


SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000


SecRule TX:/^MSC_/ "!@streq 0" \
        "id:'200005',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"



SecResponseBodyAccess On

SecResponseBodyMimeType text/plain text/html text/xml


SecResponseBodyLimit 524288


SecResponseBodyLimitAction ProcessPartial

SecTmpDir /tmp/

SecDataDir /tmp/


SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"

SecAuditLogParts ABDEFHIJZ

SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log


SecArgumentSeparator &


SecCookieFormat 0


SecUnicodeMapFile unicode.mapping 20127


SecStatusEngine On" > /etc/modsecurity/modsecurity.conf


systemctl restart apache2


####################### Install the OWASP Core Rule Set (CRS) ####################

cd /tmp

wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz

tar xvf v3.3.0.tar.gz

sudo mkdir /etc/apache2/modsecurity-crs/

mv coreruleset-3.3.0/ /etc/apache2/modsecurity-crs/


cd /etc/apache2/modsecurity-crs/coreruleset-3.3.0/


mv crs-setup.conf.example crs-setup.conf

rm -f /etc/apache2/mods-enabled/security2.conf

echo "<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier
        IncludeOptional /etc/modsecurity/*.conf
        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/*.load
        IncludeOptional /etc/apache2/modsecurity-crs/coreruleset-3.3.0/crs-setup.conf
        IncludeOptional /etc/apache2/modsecurity-crs/coreruleset-3.3.0/rules/*.conf
</IfModule>" > /etc/apache2/mods-enabled/security2.conf


systemctl restart apache2
