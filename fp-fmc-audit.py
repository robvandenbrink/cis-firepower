#################################################################################
# Cisco Firepower Audit Script
# No version number yet
# syntax:  fmcaudit <fmc ip address> <userid> <password>
#
#################################################################################

import sys, getpass, requests, json

# collect input parameters if not supplied
if(len(sys.argv) != 3):
    fmcip = input("Enter IP Address of FMC Server: ")
    uid = input("Enter User ID for Firepower Auditor Account: ")
    pwd = getpass.getpass("Enter FMC Account Password: ")
else:
    fmcip = argv[1]
    uid = argv[2]
    pwd = argv[3]

# input validation for a valid IP address goes here
# rem test credentials here, if they fail go back and collect them again

baseuri = "https://"+fmcip

##################################
# Get API key, Domain UUID
##################################
apireq = "/api/fmc_platform/v1/auth/generatetoken"
apiheaders =  {'Accept': 'application/json'}
r = requests.post(baseuri+apireq, auth=(uid,pwd), headers=apiheaders, verify = False )

accesstoken = r.headers['X-auth-access-token']
refreshtoken = r.headers['X-auth-refresh-token']
domainuuid = r.headers['DOMAIN_UUID']

# erase cleartext credentials
uid = "xxxxxxxxxxxxxx"
pwd = "xxxxxxxxxxxxxx"

##################################
# Collect info for use in the audit
##################################

##################################
# FMC Server Info
##################################

apireq = "/api/fmc_platform/v1/info/serverversion"
apiheaders =  {'Accept': 'application/json', 'X-auth-access-token': accesstoken}
r = requests.get(baseuri+apireq, headers=apiheaders, verify = False )
retvals = json.loads(r.text)
fmcinfo = []
fmcinfo = { 'fmcversion': retvals['items'][0]['serverVersion'],
            'vdbversion': retvals['items'][0]['vdbVersion'],
            'geoversion': retvals['items'][0]['geoVersion'] }

##################################
# Managed Devices Info
##################################

apireq = "/api/fmc_config/v1/domain/"+domainuuid+"/devices/devicerecords?expanded=true"
apiheaders =  {'Accept': 'application/json', 'X-auth-access-token': accesstoken}
r = requests.get(baseuri+apireq, headers=apiheaders, verify = False )
retvals = json.loads(r.text)['items']

devlist = []
for x in range(len(retvals)):
   tempval = {'id': retvals[x]['id'],
   'name': retvals[x]['name'],
   'ip': retvals[x]['hostName'],
   'model': retvals[x]['model'],
   'modelId': retvals[x]['modelId'],
   'ModelNumber': retvals[x]['modelNumber'],
   'ModelType': retvals[x]['modelType'],
   'healthStatus': retvals[x]['healthStatus'],
   'sw_version': retvals[x]['sw_version'],
   'license': retvals[x]['license_caps'],
   'access_policy':retvals[x]['accessPolicy']['name'],
   'health_policy':retvals[x]['healthPolicy']['name']}
   devlist.append(tempval)








