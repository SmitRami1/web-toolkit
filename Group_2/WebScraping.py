import requests
import re
from bs4 import BeautifulSoup
from itertools import cycle
import traceback

url = input("Please enter your website here (format should be 'http:// or https:// ):- \n")
reqs = requests.get(url)
print('link found: ', reqs)
soup = BeautifulSoup(reqs.text, 'html.parser')

email_find = []
tel_find = []
regex = r"^(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$"
pattern = re.compile(r"(\+\d{1,3}\s?)?((\(\d{3}\)\s?)|(\d{3})(\s|-?))(\d{3}(\s|-?))(\d{4})(\s?(([E|e]xt[:|.|]?)|x|X)(\s?\d+))?", re.IGNORECASE)
anchors = soup.find_all('a')
urls = []
for i in anchors:
    link_get = i.get('href')
    links = str(link_get)
    if links.startswith('/'):
        links = url+links
        urls.append(links)
    elif links.startswith('') and links not in ['https','http']:
        links = url+'/'+links
        urls.append(links)
    else:
        urls.append(links)

directory = []
# capture words from website and turn it into passwords

for link in urls:
    r = requests.get(link)
    # print("status OK")
    htmltext = r.text
    tel_finds = pattern.findall(htmltext)
    for tels in tel_finds:
        tel_find.append("".join(tels))
    emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", htmltext)
    email_find.append(emails)

email_list = list(filter(None, email_find))
tel_list = list(filter(None, tel_find))

final_email = []
final_phone = []

for new_email in email_list:
    if new_email not in final_email:
        final_email.append(new_email)

for new_phone in tel_list:
    if new_phone not in final_phone:
        final_phone.append(new_phone)

# print("links found: ",urls)
print("Emails found: ",final_email)
print("numbers found: ",final_phone)

# valid telephone numbers
