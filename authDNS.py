from socket import *
import sys
import json
import dns
import dns.resolver
import tldextract



class auth:
    def __init__(self):

        self.serverPort = 13000
        self.serverSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverSocket.bind(('', self.serverPort))

    
    def record_finder(self, link,typ):
        
        rr=[]
        # extracted = tldextract.extract(link)
        # hello = "{}.{}".format(extracted.domain, extracted.suffix)

        # url = str(input("Enter URL:"))
        url = link
        if url[0].isdigit():
            ip = gethostbyaddr(url)

            url, ip = ip, url
        else:

            
            url = str.encode(url)  # Byte converstion of string url
            
            try:
                ip = gethostbyname(url)
            except:
                rr.append('Error')
            # print("\n", ip)
        # print("website:", url, "IP:", ip)

        # print("-- DNS INFORMATION --")
        url = url.decode()

        # dnstypes = ["A", "AAAA", "NS", "MX", "PTR", "SOA", "CNAME", "TXT"]
        # dnstypes = ["NS"]

        
        try:
            answer = dns.resolver.resolve(url, typ)
            k=0
            for val in answer:
                rr.append(val.to_text())
            return rr
        except dns.resolver.NoAnswer:
            print("No",typ," Record Exists")
            rr.append("Error")
            return rr
        except dns.resolver.NXDOMAIN:
            print("No such domain Exists")
            rr.append("Error")
            return rr       
        except Exception as t:
            print("No such domain Exists. More: ", str(t))
            rr.append("Error")
            return rr



    def func(self):

        while True:
            print('\nAuthoritative DNS server is ready to receive\n')

            message, clientAddress = self.serverSocket.recvfrom(2048)
            packet = message.decode()
            packet = json.loads(packet)


            url = packet['question']['0']['name']

            if packet['flags']['recursive'] == False:
                
                packet['flags']['reply'] = True
                packet['flags']['recursion_aval'] = True
                packet['flags']['auth_dns'] = True
                packet['answer']['0']={}

                if packet['question']['0']['type']!= 'ALL':
                    rr = self.record_finder(url, packet['question']['0']['type'])

                    if rr and rr[0]!="Error":
                        packet['answer']['0']={}
                        packet['answer']['0']['name']=url
                        packet['answer']['0']['value']=rr[0]
                        packet['answer']['0']['type']= packet['question']['0']['type']
                        packet['answer']['0']['ttl']=5
                        packet['num']['ans'] = 1

                        if(packet['question']['0']['type']=='MX'):
                            rr2 = self.record_finder(packet['answer']['0']['value'].split(' ')[1],'A')
                            if rr2 and rr2[0]!="Error":
                                packet['additional']['0']={}
                                packet['additional']['0']['name']= packet['answer']['0']['value']
                                packet['additional']['0']['value']=rr2[0]
                                packet['additional']['0']['type']='A'
                                packet['additional']['0']['ttl']=5
                                packet['num']['add'] = 1 

                    else:
                        print("ALERT! You entered a wrong web address! Error being conveyed from Auth --> localDNS")
                        packet['valid']=False

                
                if packet['question']['0']['type'] == 'ALL':
                    
                    
                    if url[0].isdigit():
                        ip = gethostbyaddr(url)

                        url, ip = ip, url
                    else:

                        url = str.encode(url)  # Byte converstion of string url

                        try:
                            ip = gethostbyname(url)
                        except Exception as f:
                            print("When type: All, and address is wrong")
                            packet['valid']=False
                            
                        # print("\n", ip)
                    # print("website:", url, "IP:", ip)

                    # print("-- DNS INFORMATION --")
                    url = url.decode()

                    dnstypes = ["A", "NS", "MX", "CNAME"]

                    # packet['additional'][1]=[]

                    for i in dnstypes:
                        try:
                            
                            answer = dns.resolver.resolve(url, i)
                            packet['additional'][i]=[]

                            for val in answer:
                                
                                packet['additional'][i].append(val.to_text())
                        except dns.resolver.NoAnswer:
                            
                            packet['additional'][i]=False
                            # packet['valid']=False
                            # print(type(my_dict['add'][i]))
                        except dns.resolver.NXDOMAIN:
                            # print("No such domain")
                            packet['additional'][i]=False
                            packet['valid']=False
                            # print(type(my_dict['add'][i]))
                        except Exception as t:
                            print("when type= all , this error exists")
                            packet['valid']=False
                        

                print("Authoritative DNS is sending to the LocalDNS :\n", packet)                           
                
                modifiedMessage = json.dumps(packet)
                print("The size of transfer -> localDNS: ",sys.getsizeof(modifiedMessage.encode()))
                self.serverSocket.sendto(modifiedMessage.encode(), clientAddress)

            
            elif packet['flags']['recursive'] == True:
                print("For ",url," TLD is quering the Authoritative DNS Server on localhost, port:",self.authServerPort)
                
                
                clientSocket = socket(AF_INET, SOCK_DGRAM)
                clientSocket.sendto((json.dumps(packet)).encode(), ('localhost', self.authServerPort))
                
                reply, serverAddress = clientSocket.recvfrom(2048)
                
                






if __name__ == "__main__":
    server = auth()
    server.func()
