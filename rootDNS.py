from socket import *
import sys
import json
import csv
import dns
import dns.resolver
import tldextract


class root:
    def __init__(self):

        self.serverPort = 8888
        self.tldServerPort = 9999
        self.serverSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverSocket.bind(('', self.serverPort))
        

    def func2(self,domain):
        hello = {0: {}}
        flag = False
        ret_val =None
        
        i = 0

        with open("protagonist.csv", 'r') as file:
            csv_file = csv.DictReader(file)

            for row in csv_file:
                hello[i] = row
                # print(hello)
                i += 1
                if row['Domain'] == domain:
                    # yolo = row['IP']
                    # print("Found the TLD DNS Server: ",
                    #     row['IP'], " for ", row['Domain'])
                    ret_val = row['IP']
                    flag = True
                    break

        if flag == False:
            stri = "1.1.1."
            stri = stri + str(i)
            ret_val = stri
            hello[i] = {'Domain': domain, 'IP': stri}
            i += 1

            with open('protagonist.csv', 'w', newline='') as file:
                fieldnames = ['Domain', 'IP']

                writer = csv.DictWriter(file, fieldnames=fieldnames)

                writer.writeheader()
                for j in range(0, i):
                    writer.writerow(hello[j])
        
        return ret_val







    def record_finder(self, link,type):
        
        rr=[]
        extracted = tldextract.extract(link)
        hello = "{}.{}".format(extracted.domain, extracted.suffix)

        # url = str(input("Enter URL:"))
        url = hello
        if url[0].isdigit():
            ip = gethostbyaddr(url)

            url, ip = ip, url
        else:

            
            url = str.encode(url)  # Byte converstion of string url
            
            ip = gethostbyname(url)

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
            print("No",type," Record")
            rr[0]="Error"
            return rr
        except dns.resolver.NXDOMAIN:
            print("No such domain Exists")
            rr[0]="Error"
            return rr

    def func(self):

        while True:
            print('\nRootDNS server is ready to receive\n')
            message, clientAddress = self.serverSocket.recvfrom(2048)
            packet = message.decode()
            packet = json.loads(packet)
            print("The DNS packet received: ")
            print(packet)


            url = packet['question']['0']['name']

            if packet['flags']['recursive'] == False:
                
                packet['flags']['reply'] = True
                packet['flags']['recursion_aval'] = True
                packet['answer']['0']={}
                packet['answer']['0']['name']=url
                packet['answer']['0']['value']=self.tldServerPort
                packet['answer']['0']['type']='A'
                packet['num']['ans'] = 1

                extracted = tldextract.extract(url)
                d = "{}".format(extracted.suffix)
                
                packet['answer']['1']={}
                packet['answer']['1']['name']="localhost"
                packet['answer']['1']['value']=self.func2(d)
                packet['answer']['1']['type']='A'
                packet['answer']['1']['ttl']=5
                packet['num']['ans'] = 2

                

                print("For ",d,"RootDNS is redirecting the localDNS to TLD Server: ", self.func2(d))

                modifiedMessage = json.dumps(packet)
                print("The size of transfer -> localDNS: ",sys.getsizeof(modifiedMessage.encode()))
                self.serverSocket.sendto(modifiedMessage.encode(), clientAddress)
            
            elif packet['flags']['recursive'] == True:
                print("For the domain of .",temp," Root DNS is quering the TLD Server on localhost, port:",self.tldServerPort)
                
                
                clientSocket = socket(AF_INET, SOCK_DGRAM)
                clientSocket.sendto((json.dumps(packet)).encode(), ('localhost', self.tldServerPort))
                
                reply, serverAddress = clientSocket.recvfrom(2048)
                

                






if __name__ == "__main__":
    server = root()
    server.func()
