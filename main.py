import os
print("Select Option")
print("1 ) Web Scrapping")
print("2 ) Web Vulnerability Scanning")
option = int(input("Enter The Number For Operation To Perform :"))
if(option == 1):
    os.system("python Group_2/WebScraping.py")
elif(option == 2):
    os.system("python Group_3/tv.py ")
else:
    print("Enter Proper Input (1 or 2)")