from socket import *
import sys
import json

def display_packet(packet):
    print('\n')
    print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print('XX ',packet['id'],'\t\tXX\tReply:',packet['flags']['reply'],'| Auth:',packet['flags']['auth_dns'],' |Recursive: ',packet['flags']['recursive'],' |Recursion Available:', packet['flags']['recursion_aval'],'\tXX')
    print('XX\t\t\tXX                                                                                           XX')
    print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print('XX ', 'Questions #:',packet['num']['q'],'\tXX Answers #:',packet['num']['ans'],'\t\t\t\t\t\t\t\tXX')
    print('XX\t\t\tXX                                                                                                XX')
    print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print('XX ', 'Auth Info #:',packet['num']['auth'],'\tXX Additional Info: #:',packet['num']['add'],'\t\t\t\t\t\t\tXX')
    print('XX\t\t\tXX                                                                                                XX')
    print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print('XX ', 'QUESTION :\tName:',packet['question']['0']['name'],'\tType:',packet['question']['0']['type'],'\t\t\t\t\t\t\tXX')
    print('XX                                                                                                      XX')
    print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')



if len(sys.argv) < 4:
    print('Usage : "python3 app.py google.com i A" , where A is the type of RR and i stands for iterative DNS...')
    sys.exit(2)

serverName = 'localhost'
serverPort = 12000


clientSocket = socket(AF_INET, SOCK_DGRAM)
message = sys.argv
message = json.dumps(message)

clientSocket.sendto(message.encode(), (serverName, serverPort))
reply, serverAddress = clientSocket.recvfrom(2048)
my_dict = json.loads(reply.decode())

print(my_dict)

if my_dict['valid'] == False:
    print("The address you entered is invalid or the ",
          sys.argv[3], " Record(s) for your query is not available!\nPlease try again!\n")

else:

    if sys.argv[3] == 'ALL':
        print("-- DNS INFORMATION --")
        for count in my_dict['additional']:

            if count != '0' and type(my_dict['additional'][count]) != bool:
                print(count, ":", my_dict['additional'][count])
            elif count != '0' and type(my_dict['additional'][count]) == bool:
                print(count, ": Not Found")


    else:
        print("-- DNS INFORMATION --")
        print(sys.argv[3], "Record: ", my_dict['answer']['0']['value'])

display_packet(my_dict)


clientSocket.close()
