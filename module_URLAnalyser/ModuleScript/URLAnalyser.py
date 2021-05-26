# Import of needed libraries
import requests
import time
import sys

def URLAnalyser(APIKey, AnalyseURL, urlPost, urlGet,SecurityPrecision):
    # Section used to send the URL we want to scan to VirusTotal Service
    paramsPost = {'apikey': APIKey, 'url': AnalyseURL} # Setting up all the elements needed in the request
    responsePost = requests.post(urlPost, data=paramsPost)  # Save the reply of the post request

    # save of the response under JSON format:
    APIresponsePost = responsePost.json() # Saving the response as a JSON

    # If the POST is successful
    if APIresponsePost["response_code"] == 1 :
        # Print the status // Can be removed in prod
        print(APIresponsePost["verbose_msg"])
        # Print the scan ID // Can be removed in prod
        print(APIresponsePost["scan_id"])
        # Save the scan ID in a var called ressourceID
        ressourceID = APIresponsePost["scan_id"]
        # Waiting for VirusTotal to make the scan
        # In prod, it can be replaced by :
        #   time.sleep(10)
        print("Waiting for 20 sec ...")
        for i in range(20):
            print(".",end = '')
            time.sleep(1)
        print("\nLoading the answer ...")
        # Section used to request the result of URL analysed by VirusTotal Service
        paramsGet = {'apikey': APIKey, 'resource': ressourceID}
        responseGet = requests.get(urlGet, params=paramsGet)
        # save of the response under JSON format :
        APIresponseGet = responseGet.json()
        if APIresponseGet["response_code"] == 1 :
            # Print the status // Can be removed in prod
            print(APIresponseGet["verbose_msg"])
            # Calcultate the % of risk of the link
            risk = APIresponseGet["positives"] / APIresponseGet["total"]
            # Display this value // Can be removed in prod
            print("URL Risk is : "+str(format(risk, ".3f"))+" %")
            # Check if the URL is safe or not (the precision can be changed in the top of the script)
            if risk < SecurityPrecision :
                # For demo it print some text but it can be edited to return a value
                print("The url is safe")
            else:
                # For demo it print some text but it can be edited to return a value
                print("The url isn't safe")
        # If the GET failed
        else:
            # Print the status // Can be removed in prod
            print(APIresponseGet["verbose_msg"])
    # If the POST failed
    else:
        # Print the status // Can be removed in prod
        print(APIresponsePost["verbose_msg"])
