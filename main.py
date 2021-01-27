# Import of needed libraries
import tools.URLAnalyser as URLA
import tools.FILEAnalyser as FILEA
import requests
import time
import sys


# Elements used to reach the API
APIKey = 'put_your_api_token_here'

urlPostForURL = 'https://www.virustotal.com/vtapi/v2/url/scan'
urlGetForURL = 'https://www.virustotal.com/vtapi/v2/url/report'
urlPostForFILE = 'https://www.virustotal.com/vtapi/v2/file/scan'
urlGetForFILE = 'https://www.virustotal.com/vtapi/v2/file/report'

# % of risk allowed until the URL is considered as dangerous
SecurityPrecision = 5

# URL to analyse
AnalyseURL = 'https://www.google.com/' # If given in the script
# AnalyseURL = str(sys.arg[1]) # If given from the runtime

# File to analyse
# If given in the script
file = "link/toward/your/file"
# If given from the runtime
# file = str(sys.arg[1])
print("Analysing a URL : ")
URLA.URLAnalyser(APIKey, AnalyseURL, urlPostForURL, urlGetForURL, SecurityPrecision)
print("Analysing a File : ")
FILEA.FILEAnalyser(APIKey, file, urlPostForFILE, urlGetForFILE, SecurityPrecision)
