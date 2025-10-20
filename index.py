"""
1. Endpoint discovery
    - Can be done using the spider or OPENAPI SPECS
2. Vulnerability Scanning
    - Passive Scanning <-- If SAFE mode
    - Active Scanning <-- If ATTACK mode
3. Access Security Testing
    - Brute Force Login
    - Session Management
    - API Key Management
    - OAuth Token Management
4. Payload Injection
    - SQL Injection
    - XSS
    - CSRF
    - etc.
"""


#!/usr/bin/env python
import time
from pprint import pprint
from zapv2 import ZAPv2


# The URL of the application to be tested
target = 'http://host.docker.internal:8888'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = 'changeMe'

# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apiKey)


# ---------------------------------------------Spidering--------------------------------------------
print('Spidering target {}'.format(target))
# The scan returns a scan id to support concurrent scanning
scanID = zap.spider.scan(target)
while int(zap.spider.status(scanID)) < 100:
    # Poll the status until it completes
    print('Spider progress %: {}'.format(zap.spider.status(scanID)))
    time.sleep(1)

print('Spider completed')

#---------------------------------------------Disable Scanners PASSIVE AND ACTIVE---------------------------------------------

zap.ascan.disable_all_scanners(apikey=apiKey)
zap.pscan.disable_all_scanners(apikey=apiKey)
print('Disabled all active and passive scanners.')

# ---------------------------------------------Active Scanning----------------------------------------------
api_scanners = [40034]  # Example IDs 40018, 40019, 40020, 40021, 40022, 40023, 40024, 40027
for sid in api_scanners:
    zap.ascan.enable_scanners(sid, apikey=apiKey)
print('Enabled selected active scanners: {}'.format(api_scanners))
zap.core.delete_all_alerts()
scanID = zap.ascan.scan(target)
while int(zap.ascan.status(scanID)) < 100:
    # Poll the status until it completes
    print('Active Scan progress %: {}'.format(zap.ascan.status(scanID)))
    time.sleep(2)

alerts = zap.core.alerts()
print(len(alerts), "alerts found")
for a in alerts:
    print(a['pluginId'], a['alert'], a['risk'], a['url'])

# zap.core.delete_all_alerts()
# print(zap.core.alerts())

# # ---------------------------------------------XSS----------------------------------------------

# ---------------------------------------------SQLi----------------------------------------------
# api_scanners = [40018, 40019, 40020, 40021, 40022, 40023, 40024, 40027]  # Example IDs
# for sid in api_scanners:
#     zap.ascan.enable_scanners(sid, apikey=apiKey)
# zap.ascan.disable_all_scanners()
# scanners = zap.ascan.scanners()
# print('Enabled scanners after disabling all:')
# for s in scanners:
#     if s['enabled'] == 'true':
#         print(s['id'], s['name'])
# print([s for s in scanners if s['enabled'] == 'true'])


