
import argparse
import struct
import socket 


LEN_RESPONSE_ERROR = 4

# each 'h' means 2 bytes
# each 'i' means 4 bytes
ID_NETWORK_MODE_FORMAT = '>12s'
TYPE_NETWORK_MODE_FORMAT = '>h'
N_NETWORK_MODE_FORMAT = '>h'
NONCE_NETWORK_MODE_FORMAT = '>i'
TOKEN_FORMAT = '64s'
GROUP_TOKEN_FORMAT = '64s'
SAS_FORMAT = '12si64s'
STATUS_FORMAT = 'b'

TYPE_INDIVIDUAL_TOKEN_REQUEST = 1

TYPE_INDIVIDUAL_TOKEN_RESPONSE = 2
LEN_INDIVIDUAL_TOKEN_RESPONSE = 82
INDIVIDUAL_TOKEN_RESPONSE_FORMAT = '>h12si64s'

TYPE_INDIVIDUAL_TOKEN_VALIDATION = 3
LEN_INDIVIDUAL_TOKEN_VALIDATION = 83
INDIVIDUAL_TOKEN_VALIDATION_RESPONSE_FORMAT = '>h12si64sb'

TYPE_INDIVIDUAL_TOKEN_STATUS = 4

TYPE_GROUP_TOKEN_REQUEST = 5
LEN_BYTES_TYPE = 2
LEN_BYTES_TOKEN = LEN_BYTES_GROUP_TOKEN = 64
LEN_BYTES_SAS = 80
INDIVIDUAL_GROUP_TOKEN_RESPONSE_FORMAT = '>h12si64sb'

TYPE_GROUP_TOKEN_RESPONSE = 6

TYPE_GROUP_TOKEN_VALIDATION = 7

TYPE_GROUP_TOKEN_STATUS = 8

LEN_BYTES_STATUS = 1

LEN_BYTES_N = 2

def return_input_parameters():
    parser = argparse.ArgumentParser(description='Inform the parameters to the program')

    parser.add_argument('host', type=str, help='The server host address')
    parser.add_argument('port', type=int, help='The server address port')

    parser.add_argument('command', choices=['itr', 'itv', 'gtr', 'gtv'], help='The command option to run the code')

    # Parse the arguments to get the command
    args, unknown = parser.parse_known_args()

    # Handle the command
    if args.command == 'itr':
        parser.add_argument('id', type=str, help='Argument 1 for itr command')
        parser.add_argument('nonce', type=int, help='Argument 2 for itr command')
    elif args.command == 'itv':
        parser.add_argument('SAS', type=str, help='Argument 1 for itv command')
    elif args.command == 'gtr':
        parser.add_argument('N', type=int, help='Number of SAS arguments for gtr command')
        parser.add_argument('SAS', nargs='+', help='List of SAS arguments for gtr command')
    elif args.command == 'gtv':
        parser.add_argument('N', type=int, help='Number of SAS arguments for gtv command')
        parser.add_argument('GAS', type=str, help='List of GAS arguments for gtv command')
    else:
        parser.error('')


    # Parse the arguments again to get all arguments
    args = parser.parse_args()

    # Handle the arguments
    if args.command == 'gtr':
        if len(args.SAS) != args.N:
            parser.error(f'Must be received {args.N} values of SAS, received {len(args.SAS)}')
    if args.command == 'gtv':
        count = 0
        for char in args.GAS:
            if char == '+':
                count += 1
        if count != args.N:
            parser.error(f'Must be received {args.N} values of SAS in GAS, received {count}')


    return args

# student id have to be 12 bytes, so the last 2 bytes are empty spaces
STUDENT_ID = '2021031726  '

def type_in_network_mode (type: int):
    type_net_mode = struct.pack(TYPE_NETWORK_MODE_FORMAT, type)
    
    return type_net_mode

def nonce_in_network_mode (nonce: int):
    nonce_net_mode = struct.pack(NONCE_NETWORK_MODE_FORMAT, nonce)
    
    return nonce_net_mode

def token_in_network_mode (token: str):
    
    token_decoded = bytes(token, encoding="ascii")

    token_net_mode = struct.pack(f'>{TOKEN_FORMAT}', token_decoded)
    
    return token_net_mode

def id_in_network_mode (student_id: str):

    student_id_adjusted = adjust_student_id_to_12_bytes(student_id)

    student_id_decoded = bytes(student_id_adjusted, encoding="ascii")
    
    student_id_net_mode = struct.pack(ID_NETWORK_MODE_FORMAT, student_id_decoded)
    
    return student_id_net_mode

def n_in_network_mode (n: int):
    n_net_mode = struct.pack(N_NETWORK_MODE_FORMAT, n)
    
    return n_net_mode

def group_token_in_network_mode (group_token: str):

    group_token_decoded = bytes(group_token, encoding="ascii")
    
    group_token_net_mode = struct.pack(GROUP_TOKEN_FORMAT, group_token_decoded)
    
    return group_token_net_mode
    

def adjust_student_id_to_12_bytes(student_id: str):

    student_id_adjusted = ''
    if len(student_id) < 12:

        student_id_adjusted = student_id.ljust(12, ' ')
    else:
        student_id_adjusted = student_id

    return student_id_adjusted



def start_server(server_address: str, server_port: int):

    # function return list, the last tuple returned has lenght = 4 if IPv6 and lenght = 2 if IPv4
    ip_info = (socket.getaddrinfo(server_address, server_port, proto=socket.IPPROTO_UDP))

    # select IPV6 info if exists
    if len(ip_info[0][-1]) == 4:
        server_ip = ip_info[0][-1][0]
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    else: #select IPV4 info
        server_ip = ip_info[0][-1][0]
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server.settimeout(20)

    loop_until_receive_response = 1
    number_of_attempts = 4

    # loop to handle timeout in conection
    while(loop_until_receive_response):
        if (number_of_attempts == 0):
            server.close()
            raise Exception('Too many attempts, conection closed')

        try:
            server.connect((server_ip, server_port))
            loop_until_receive_response = 0

        except socket.timeout:
            number_of_attempts -= 1

    return server



def individual_token_request(server:socket, student_id: str, nonce: int):


    message = type_in_network_mode(TYPE_INDIVIDUAL_TOKEN_REQUEST) + id_in_network_mode(bytes(student_id, encoding="ascii")) + nonce_in_network_mode(nonce)

    loop_until_receive_response = 1
    number_of_attempts = 4

    # loop to handle timeout in conection
    while(loop_until_receive_response):
        if (number_of_attempts == 0):
            server.close()
            raise Exception('Too many attempts, conection closed')

        try:
            server.send(message)
            
            response = server.recv(LEN_INDIVIDUAL_TOKEN_RESPONSE)
            
            loop_until_receive_response = 0

        except socket.timeout:
            number_of_attempts -= 1

    if len(response) == LEN_RESPONSE_ERROR:
        server.close()
        raise Exception (f'Error: {response}')
    
    if (len(response) != LEN_INDIVIDUAL_TOKEN_RESPONSE):
        server.close()
        raise Exception('Invalid response')
    
    response_unpacked = struct.unpack(INDIVIDUAL_TOKEN_RESPONSE_FORMAT, response)

    type_position_in_response = 0
    type = response_unpacked[type_position_in_response]
    
    if type != TYPE_INDIVIDUAL_TOKEN_RESPONSE:
        server.close()
        raise Exception('Invalid type of response')

    token_position_in_response = -1
    token = response_unpacked[token_position_in_response].decode('ascii')

    response_formated = f'{student_id}:{nonce}:{token}'

    server.close()

    return response_formated


def individual_token_validation(server: socket, SAS: str):
    
    SAS_splited = SAS.split(':')

    student_id = SAS_splited[0]
    nonce = int(SAS_splited[1])
    token = SAS_splited[2]

    message = type_in_network_mode(TYPE_INDIVIDUAL_TOKEN_VALIDATION) + id_in_network_mode(student_id) + nonce_in_network_mode(nonce) + token_in_network_mode(token)

    loop_until_receive_response = 1
    number_of_attempts = 4

    # loop to handle timeout in conection
    while(loop_until_receive_response):
        if (number_of_attempts == 0):
            server.close()
            raise Exception('Too many attempts, conection closed')

        try:
            server.send(message)
            
            response = server.recv(LEN_INDIVIDUAL_TOKEN_VALIDATION)
            
            loop_until_receive_response = 0

        except socket.timeout:
            number_of_attempts -= 1
    
    if len(response) == LEN_RESPONSE_ERROR:
        server.close()
        raise Exception (f'Error: {response}')
    
    if (len(response) != LEN_INDIVIDUAL_TOKEN_VALIDATION):
        server.close()
        raise Exception('Invalid response')
    
    response_unpacked = struct.unpack(INDIVIDUAL_TOKEN_VALIDATION_RESPONSE_FORMAT, response)

    type_position_in_response = 0
    type = response_unpacked[type_position_in_response]
    
    if type != TYPE_INDIVIDUAL_TOKEN_STATUS:
        server.close()
        raise Exception('Invalid type of response')

    status_position_in_response = -1
    status = response_unpacked[status_position_in_response]

    server.close()

    return status   

def group_token_request(server: socket, n: int, SAS: list[str]):

    message = type_in_network_mode(TYPE_GROUP_TOKEN_REQUEST) + n_in_network_mode(n)

    for individual_SAS in SAS:
        SAS_splited = individual_SAS.split(':')

        student_id = SAS_splited[0]
        nonce = int(SAS_splited[1])
        token = SAS_splited[2]

        message += id_in_network_mode(student_id) + nonce_in_network_mode(nonce) + token_in_network_mode(token)

    loop_until_receive_response = 1
    number_of_attempts = 4

    # loop to handle timeout in conection
    while(loop_until_receive_response):
        if (number_of_attempts == 0):
            server.close()
            raise Exception('Too many attempts, conection closed')

        try:
            server.send(message)
            
            total_len_response = LEN_BYTES_TYPE + LEN_BYTES_N + (LEN_BYTES_SAS * n) + LEN_BYTES_GROUP_TOKEN
            response = server.recv(total_len_response)
            
            loop_until_receive_response = 0

        except socket.timeout:
            number_of_attempts -= 1
    
    if len(response) == LEN_RESPONSE_ERROR:
        server.close()
        raise Exception (f'Error: {response}')
    
    if (len(response) != total_len_response):
        server.close()
        raise Exception('Invalid response')
    
    # format to type + n
    group_token_response_format_message = '>hh'
    for _ in range(len(SAS)):
        group_token_response_format_message += SAS_FORMAT
    
    group_token_response_format_message += TOKEN_FORMAT

    response_unpacked = struct.unpack(group_token_response_format_message, response)

    type_position_in_response = 0
    type = response_unpacked[type_position_in_response]
    
    if type != TYPE_GROUP_TOKEN_RESPONSE:
        server.close()
        raise Exception('Invalid type of response')

    token_position_in_response = -1
    token = response_unpacked[token_position_in_response].decode('ascii')

    response_formated = ''
    for individual_SAS in SAS:
        response_formated += individual_SAS + '+'
    
    response_formated += token

    server.close()

    return response_formated  

def group_token_validation(server: socket, n: int, GAS: str):
    
    message = type_in_network_mode(TYPE_GROUP_TOKEN_VALIDATION) + n_in_network_mode(n)

    # gas format = sas+sas+ ... +sas+group_token 
    GAS_splited = GAS.split('+')

    group_token = GAS_splited[-1]

    # -1 to ignore the last value = group_token
    for individual_SAS_idx in range(len(GAS_splited) -1):
        SAS_splited = GAS_splited[individual_SAS_idx].split(':')

        student_id = SAS_splited[0]
        nonce = int(SAS_splited[1])
        token = SAS_splited[2]

        message += id_in_network_mode(student_id) + nonce_in_network_mode(nonce) + token_in_network_mode(token)

    message += group_token_in_network_mode(group_token)

    loop_until_receive_response = 1
    number_of_attempts = 4

    # loop to handle timeout in conection
    while(loop_until_receive_response):
        if (number_of_attempts == 0):
            server.close()
            raise Exception('Too many attempts, conection closed')

        try:
            server.send(message)
            
            total_len_response = LEN_BYTES_TYPE + LEN_BYTES_N + (LEN_BYTES_SAS * n) + LEN_BYTES_GROUP_TOKEN + LEN_BYTES_STATUS
            response = server.recv(total_len_response)
            
            loop_until_receive_response = 0

        except socket.timeout:
            number_of_attempts -= 1
    
    if len(response) == LEN_RESPONSE_ERROR:
        server.close()
        raise Exception (f'Error: {response}')
    
    if (len(response) != total_len_response):
        print(len(response))
        print((response))
        server.close()
        raise Exception('Invalid response')    

    # format to type + n
    group_token_response_format_message = '>hh'

    for _ in range(len(GAS_splited) - 1):
        group_token_response_format_message += SAS_FORMAT
    
    group_token_response_format_message += GROUP_TOKEN_FORMAT

    print(group_token_response_format_message + STATUS_FORMAT)
    response_unpacked = struct.unpack(group_token_response_format_message + STATUS_FORMAT, response)

    type_position_in_response = 0
    type = response_unpacked[type_position_in_response]
    
    if type != TYPE_GROUP_TOKEN_STATUS:
        server.close()
        raise Exception('Invalid type of response')

    status_position_in_response = -1
    status = response_unpacked[status_position_in_response]

    server.close()

    return status       


if __name__ == "__main__":
    args = return_input_parameters()

    server = start_server(args.host, args.port)
    
    if (args.command == 'itr'):    
        response = individual_token_request(server, args.id, args.nonce)
    if (args.command == 'itv'):
        response = individual_token_validation(server, args.SAS)
    if (args.command == 'gtr'):
        response = group_token_request(server, args.N, args.SAS)
    if (args.command == 'gtv'):
        response = group_token_validation(server, args.N, args.GAS)
    
    print(response)


# mesage format
# 2 bytes type
# 12 bytes ID
# 4 bytes nonce