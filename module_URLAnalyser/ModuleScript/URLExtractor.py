def extractURL(email):
    wordsInLine = []
    tempWord = []
    urlList = []
    file = open(email)                                              # Open up the file containing the email
    for line in file:                                               # Make a list of all the words from the mail
        wordsInLine = line.split(' ')                               # split each words using space
        for word in wordsInLine:                                    # look after each words
            tempWord = word.split("://")                              # see if the word containe '://' devide it in two parts
                                                                    # Check if the first part is http(s)
            if len(tempWord) == 2:                                  # Make sure that the person isn't just talking of http(s)
                if tempWord[0] == "http" or tempWord[0] == "https":
                    urlList.append(word)                            # Add the url to the list
    file.close()                                                    # Close the email
    return urlList                                                  # Return the list of urls found