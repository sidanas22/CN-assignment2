import dns
import dns.resolver
from socket import *
import tldextract
import sys


# extracted = tldextract.extract('www.bbc.com')

# hello = "{}.{}".format(extracted.domain, extracted.suffix)

# url = str(input("Enter URL:"))

if len(sys.argv) == 1:
    url = "google.com"

elif len(sys.argv) > 1:
    url = sys.argv[1]

if url[0].isdigit():
    ip = gethostbyaddr(url)

    url, ip = ip, url
else:

    url = str.encode(url)  # Byte converstion of string url

    ip = gethostbyname(url)

    # print("\n", ip)
print("website:", url, "IP:", ip)

print("-- DNS INFORMATION --")
url = url.decode()

dnstypes = ["A", "NS", "MX", "CNAME"]
# dnstypes = ["CNAME"]
my_dict={}
my_dict['yolo']={}
my_dict['add']={}
for i in dnstypes:
    try:
        print(i+":")
        answer = dns.resolver.resolve(url, i)
        my_dict['add'][i]=[]

        for val in answer:
            print(i+' Record : ', val.to_text().split(' '))
            my_dict['add'][i].append(val.to_text())
    except dns.resolver.NoAnswer:
        print("No "+i)
        my_dict['add'][i]=False
        print(type(my_dict['add'][i]))
    except dns.resolver.NXDOMAIN:
        print("No such domain")
        my_dict['add'][i]=False
        print(type(my_dict['add'][i]))
    except KeyboardInterrupt:
        print("\nGoodbye!")
        exit()

print(my_dict)

for count in my_dict['add']:
    if type(my_dict['add'][count]) == bool:
        print(count)

# import csv

# # with open('protagonist.csv', 'w', newline='') as file:
# #     writer = csv.writer(file)
# #     writer.writerow(["Domain", "IP"])

# hello = {0: {}}
# flag = False
# domain = "com"
# i = 0

# with open("protagonist.csv", 'r') as file:
#     csv_file = csv.DictReader(file)

#     for row in csv_file:
#         hello[i] = row
#         # print(hello)
#         i += 1
#         if row['Domain'] == domain:
#             # yolo = row['IP']
#             print("Found the TLD DNS Server: ",
#                   row['IP'], " for ", row['Domain'])
#             flag = True
#             break

# if flag == False:
#     stri = "1.1.1."
#     stri = stri + str(i)
#     hello[i] = {'Domain': domain, 'IP': stri}
#     i += 1

#     with open('protagonist.csv', 'w', newline='') as file:
#         fieldnames = ['Domain', 'IP']

#         writer = csv.DictWriter(file, fieldnames=fieldnames)

#         writer.writeheader()
#         for j in range(0, i):
#             writer.writerow(hello[j])


# import tldextract
# extracted = tldextract.extract('www.google.com')

# hello = "{}".format(extracted.suffix)

# print (hello)


# import sys

# some_packet = dict()
# some_packet['id'] = 1234
# some_packet['flags'] = {}
# some_packet['flags']['reply'] = False
# some_packet['flags']['auth_dns'] = False
# some_packet['flags']['recursive'] = False
# some_packet['flags']['recursion_aval'] = False
# some_packet['num'] = {}
# some_packet['num']['q'] = 1
# some_packet['num']['ans'] = 0
# some_packet['num']['auth'] = 0
# some_packet['num']['add'] = 0
# some_packet['question'] = {}
# some_packet['question'][0]={}
# some_packet['question'][0]['name'] = "asdkjshdkjhaskdhkasjd"
# some_packet['question'][0]['type'] = "dss"
# some_packet['answer'] = {}
# some_packet['authority'] = {}
# some_packet['additional']={}
# some_packet['answer'][0]={}
# some_packet['answer'][0]['name']="dasdsadsssssssssssssssssssss"
# some_packet['answer'][0]['value']="dasdsadsssssssssssssssssssss"
# some_packet['answer'][0]['type']= "dasdsadsssssssssssssssssssss"
# some_packet['answer'][0]['ttl']=5
# some_packet['num']['ans'] = 2

# print(sys.getsizeof(some_packet))
