# Import of needed libraries
import requests
import time
import sys

def FILEAnalyser(APIKey, file, urlPost, urlGet,SecurityPrecision):
    # Opening the file
    fileToAnalyse = {'file': (file, open(file, 'rb'))}
    # Section used to send the 'file' we want to scan to VirusTotal Service
    paramsPost = {'apikey': APIKey}
    responsePost = requests.post(urlPost, files=fileToAnalyse, params=paramsPost)

    # save of the response under JSON format:
    APIresponsePost = responsePost.json()

    # If the POST is successful
    if APIresponsePost["response_code"] == 1 :
        # Print the status // Can be removed in prod
        print(APIresponsePost["verbose_msg"])
        # Print the scan ID // Can be removed in prod
        print(APIresponsePost["sha256"])
        # Save the scan ID in a var called ressourceID
        ressourceID = APIresponsePost["sha256"]
        # Waiting for VirusTotal to make the scan
        # In prod, it can be replaced by :
        #   time.sleep(10)
        print("Waiting for 60 sec ...")
        for i in range(60):
            print(".",end = '')
            time.sleep(1)
        print("\nLoading the answer ...")
        # Section used to request the result of URL analysed by VirusTotal Service
        params = {'apikey': APIKey, 'resource': ressourceID}
        responseGet = requests.get(urlGet, params=params)
        # save of the response under JSON format :
        APIresponseGet = responseGet.json()
        if APIresponseGet["response_code"] == 1 :
            # Print the status // Can be removed in prod
            print(APIresponseGet["verbose_msg"])
            # Calcultate the % of risk of the link
            risk = APIresponseGet["positives"] / APIresponseGet["total"]
            # Display this value // Can be removed in prod
            print("URL Risk is : "+str(format(risk, ".3f"))+" %")
            # Check if the file is safe or not (the precision can be changed in the top of the script)
            if risk < SecurityPrecision :
                # For demo it print some text but it can be edited to return a value
                print("The file is safe")
                return 0
            else:
                # For demo it print some text but it can be edited to return a value
                print("The file isn't safe")
                return 1
        # If the GET failed
        else:
            # For demo it print some text but it can be edited to return a value
            print(APIresponseGet["verbose_msg"])
    # If the POST failed
    else:
        # Print the status // Can be removed in prod
        # For demo it print some text but it can be edited to return a value
        print(APIresponsePost["verbose_msg"])
