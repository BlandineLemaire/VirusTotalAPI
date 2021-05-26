import ModuleScript.URLAnalyser as URLA
import ModuleScript.URLExtractor as URLE
import json
import sys

# Reading params given in Param.editable files
# Opening the json file
with open('../Param.editable') as json_file:
  editableParam = json.load(json_file)
APIKey = editableParam["APIKey"]
urlPostForFILE = editableParam["urlPostForFILE"]
urlGetForFILE = editableParam["urlGetForFILE"]
SecurityPrecision = int(editableParam["SecurityPrecision"])
mail = sys.argv[1]

# Analyse of URLs as long as there are URLs in the list
# Extraction the urls of the email
urlList = URLE.extractURL(mail)
# Request URLanalyse
for urlToAnalyse in urlList:
    print("URL to be analysed : "+urlToAnalyse)
    continuing = URLA.URLAnalyser(APIKey, urlToAnalyse, urlPostForURL, urlGetForURL, SecurityPrecision)
    if continuing == 1:
      return 1
# If everything is going fine the programme return an OK flag
return 0
# Note:
#   The file analyse is critical. If one file is seen as malicious the email is considered dangerous
#   0 = not suspcious file where found during analyse and according to the SecurityPrecision given
#   1 = A suspcious file has been found during analyse and according to the SecurityPrecision given
