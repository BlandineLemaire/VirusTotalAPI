import ModuleScript.fileanalyser as FILEA
import json
import sys
import os
# Reading params given in Param.editable files
# Opening the json file
with open('../Param.editable') as json_file:
  editableParam = json.load(json_file)
APIKey = editableParam["APIKey"]
urlPostForFILE = editableParam["urlPostForFILE"]
urlGetForFILE = editableParam["urlGetForFILE"]
SecurityPrecision = int(editableParam["SecurityPrecision"])
directory = sys.argv[1]

# Analyse of attached files as long as there are files in the directory
for filename in os.listdir(directory):
    print("Analysing a File : ")
    # Generation of file path
    file = directory+filename
    print(file)

    continuing = FILEA.FILEAnalyser(APIKey, file, urlPostForFILE, urlGetForFILE, SecurityPrecision)
    # If one file is seen as unsafe the programmes stop and return a warning flag
    if continuing == 1:
      return 1
# If everything is going fine the programme return an OK flag
return 0
# Note:
#   The file analyse is critical. If one file is seen as malicious the email is considered dangerous
#   0 = not suspcious file where found during analyse and according to the SecurityPrecision given
#   1 = A suspcious file has been found during analyse and according to the SecurityPrecision given
