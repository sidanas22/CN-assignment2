from socket import *
import sys
import json


class localdns:
    def __init__(self):

        self.serverPort = 12000
        self.rootServerPort = 8888
        self.serverSocket = socket(AF_INET, SOCK_DGRAM)
        self.serverSocket.bind(('', self.serverPort))

        print('\nLocalDNS server is built\n')

    def make_dns_packet(self, url, typ):
        some_packet = dict()
        some_packet['id'] = 1234
        some_packet['flags'] = {}
        some_packet['flags']['reply'] = False
        some_packet['flags']['auth_dns'] = False
        some_packet['flags']['recursive'] = False
        some_packet['flags']['recursion_aval'] = False
        some_packet['num'] = {}
        some_packet['num']['q'] = 1
        some_packet['num']['ans'] = 0
        some_packet['num']['auth'] = 0
        some_packet['num']['add'] = 0
        some_packet['question'] = {}
        some_packet['question']['0'] = {}
        some_packet['question']['0']['name'] = url
        some_packet['question']['0']['type'] = 'NS'
        some_packet['answer'] = {}
        some_packet['authority'] = {}
        some_packet['additional'] = {}
        some_packet['valid'] = True
        return some_packet

    def start(self):

        print('\nLocalDNS server is ready to serve\n')

        while True:
            message, clientAddress = self.serverSocket.recvfrom(2048)
            message = json.loads(message.decode())
            print("Arguments from app.py: ", message)
            url = message[1]
            mode = message[2]
            typ = message[3]

            if mode == 'i':
                self.iterative(url, typ, clientAddress)

    def iterative(self, url, typ, clientAddress):

        contains_digit = url[0].isdigit()

        if contains_digit == False:
            dns_packet_query = self.make_dns_packet(url, typ)
            data_to_root = json.dumps(dns_packet_query)

            print("The size of transfer: ", sys.getsizeof(data_to_root.encode()))

            socket_to_root = socket(AF_INET, SOCK_DGRAM)
            print("LocalDNS Querying Root Server")
            socket_to_root.sendto(data_to_root.encode(),
                                  ('localhost', self.rootServerPort))

            reply_from_root, serverAddress = socket_to_root.recvfrom(2048)
            reply = reply_from_root.decode()
            dns_packet_reply = json.loads(reply)
            final_dns_pkt = None
            socket_to_root.close()

            while dns_packet_query['id'] == dns_packet_reply['id'] and dns_packet_reply['flags']['reply'] == True and dns_packet_reply['flags']['auth_dns'] == False and dns_packet_reply['flags']['recursive'] == False:

                if dns_packet_reply['num']['ans'] == 3:
                    print("Now querying the Authoritative DNS Server: ",
                          dns_packet_reply['answer']['2']['name'], "(", dns_packet_reply['answer']['2']['value'], ")")
                    value_of_port = dns_packet_reply['answer']['0']['value']
                    dns_packet_query['question']['0']['type'] = typ
                    print("Packet going to Auth: ", dns_packet_query)
                    data_to_root = json.dumps(dns_packet_query)

                elif dns_packet_reply['num']['ans'] == 2:
                    print("Now querying the TLD Server: ",
                          dns_packet_reply['answer']['1']['value'])
                    value_of_port = dns_packet_reply['answer']['0']['value']

                if dns_packet_reply['num']['ans'] == 1:
                    print("The address you entered is invalid!")
                    # temp = dns_packet_reply
                    dns_packet_reply['valid'] = False
                    final_dns_pkt = dns_packet_reply
                    break

                sock = socket(AF_INET, SOCK_DGRAM)
                sock.sendto(data_to_root.encode(),
                            ('localhost', value_of_port))

                reply_from_tld, serverAddress = sock.recvfrom(2048)
                dns_packet_reply = json.loads(reply_from_tld.decode())
                final_dns_pkt = dns_packet_reply
                sock.close()

            print("LocalDNS sending to app: ", final_dns_pkt)
            data_to_app = json.dumps(final_dns_pkt)
            self.serverSocket.sendto(data_to_app.encode(), clientAddress)


    # def recursiv ():
    #     server





if __name__ == "__main__":
    server = localdns()
    server.start()
