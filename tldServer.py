from socket import *
import sys
import json
import csv
import dns
import dns.resolver
import tldextract


class tld:
    def __init__(self):

        self.serverPort = 9999
        self.authServerPort = 13000
        self.serverSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverSocket.bind(('', self.serverPort))


    def record_finder(self, link,type):
        
        rr=[]
        url = link
        if type == 'NS':
            extracted = tldextract.extract(link)
            hello = "{}.{}".format(extracted.domain, extracted.suffix)
            url = hello

        # url = str(input("Enter URL:"))
         
        if url[0].isdigit():
            ip = gethostbyaddr(url)

            url, ip = ip, url
        else:

            
            url = str.encode(url)  # Byte converstion of string url
            
            try:
                ip = gethostbyname(url)
            except Exception as e:
                print("Inside Record Finder gethostbyname: The address you entered is invalid!")
                rr.append("Error")
            # print("\n", ip)
        # print("website:", url, "IP:", ip)

        # print("-- DNS INFORMATION --")
        url = url.decode()

        # dnstypes = ["A", "AAAA", "NS", "MX", "PTR", "SOA", "CNAME", "TXT"]
        dnstypes = ["NS"]

        
        try:
            answer = dns.resolver.resolve(url, type)
            k=0
            for val in answer:
                rr.append(val.to_text())
            return rr
        except dns.resolver.NoAnswer:
            print("Inside Record Finder: No",type," Record")
            rr.append("Error")
            return rr
        except dns.resolver.NXDOMAIN:
            print("Inside Record Finder: No such domain Exists")
            rr.append("Error")
            return rr
        except dns.resolver.NoNameservers:
            print("Inside Record Finder Yo: No such domain Exists")
            rr.append("Error")
            return rr
           

        



    def func(self):

        while True:
            print('\nTLD server is ready to receive\n')

            message, clientAddress = self.serverSocket.recvfrom(2048)
            packet = message.decode()
            packet = json.loads(packet)


            url = packet['question']['0']['name']

            if packet['flags']['recursive'] == False:
                
                packet['flags']['reply'] = True
                packet['flags']['recursion_aval'] = True
                packet['answer']['0']={}
                packet['answer']['0']['name']=url
                packet['answer']['0']['value']=self.authServerPort
                packet['answer']['0']['type']='A'
                packet['num']['ans'] = 1

                rr = self.record_finder(url,"NS")
                if rr and rr[0]!="Error":
                    print("Packet['answer']['1'] being filled...")
                    packet['answer']['1']={}
                    packet['answer']['1']['name']=url
                    packet['answer']['1']['value']=rr[0]
                    packet['answer']['1']['type']='NS'
                    packet['answer']['1']['ttl']=5
                    packet['num']['ans'] = 2

                    rr2 = self.record_finder(packet['answer']['1']['value'],'A')
                    if rr2 and rr2[0]!="Error":
                        print("Packet['answer']['2'] being filled...")
                        packet['answer']['2']={}
                        packet['answer']['2']['name']= packet['answer']['1']['value']
                        packet['answer']['2']['value']=rr2[0]
                        packet['answer']['2']['type']='A'
                        packet['answer']['2']['ttl']=5
                        packet['num']['ans'] = 3

                    print("1. TLDDNS --> LocalDNS :", packet['answer']['1'] )
                    print("2. TLDDNS --> LocalDNS :", packet['answer']['2'] )
                
                else:
                    print("ALERT! You entered a wrong web address! Error being conveyed TLD --> localDNS")





                # print("1. RootDNS --> LocalDNS :", packet['answer'][1] )
                # print("2. RootDNS --> LocalDNS :", packet['answer'][2] )

                # print("For ",url,"TLD is redirecting the LocalDNS to Authoritative DNS on localhost, port:",self.authServerPort)                           
                modifiedMessage = json.dumps(packet)
                print("The size of transfer -> localDNS: ",sys.getsizeof(modifiedMessage.encode()))
                print("Packet being transferred: \n",packet)
                self.serverSocket.sendto(modifiedMessage.encode(), clientAddress)
            
            elif packet['flags']['recursive'] == True:
                print("For ",url," TLD is quering the Authoritative DNS Server on localhost, port:",self.authServerPort)
                
                
                clientSocket = socket(AF_INET, SOCK_DGRAM)
                clientSocket.sendto((json.dumps(packet)).encode(), ('localhost', self.authServerPort))
                
                reply, serverAddress = clientSocket.recvfrom(2048)
                
                






if __name__ == "__main__":
    server = tld()
    server.func()
