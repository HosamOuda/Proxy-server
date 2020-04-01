import sys
import os
import enum
import socket
import re


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(
        self,
        client_info,
        method: str,
        requested_path: str,
        requested_host: str, 
        requested_port: int,
        headers: list,
    ):
        self.method = method
        self.client_address_info = (
            client_info  # ip address and port ......client_addr = ("127.0.0.1", 9877)
        )
        self.requested_host = (
            requested_host  # l site ely ana 3yzo mn 8er l port --> url
        )
        self.requested_port = requested_port  # port of website       default 80
        self.requested_path = requested_path  # facebook/...    hya el /...
        # Headers will be represented as a list of tuples
        # for example ("Host", "www.google.com")
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ("Host", "www.google.com") note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        request_line = self.method + " " + self.requested_path + " HTTTP/1.0\r\n"
        Headers = "\r\n".join(self.headers)
        HttpStringRequest = request_line + Headers
        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return HttpStringRequest

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Path:", self.requested_path)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        print("Headers:\n", self.headers)


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """
    #Unsupported method
    #Relatie path with No host

    def __init__(self, code, message):

        self.code = code
        self.message = message

    def to_http_string(self):
        "Error"+self.code+","+self.message
        pass

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """

    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):

    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    # Intialize CTP Socket
    clientSocket = setup_CTP_sockets(proxy_port_number)
    # Rec Client Request
    clsocket, clientAddr, request = recieveClientRequest(clientSocket)

    print("client addr : ", clientAddr)
    print("Client request : ", request)
    get www.get
    get google.com
    get hhtp
    # Test Requests
    # request = ""
    # End Of testing

    serverRequest = http_request_pipeline(clientAddr, request)


    serverRequest.display()

    http_request_string = serverRequest.to_http_string()
    print("HttpStringRequest : ", http_request_string)

    http_request = serverRequest.to_byte_array(http_request_string)
    print("Encoded request", http_request)

    serverSocket = setup_PTS_socket()
    DataPacket = SendHttpRequestANDrecvData(
        serverSocket, serverRequest.requested_host, http_request
    )
    serverSocket.close()

    clsocket.sendto(DataPacket, clientAddr)
    return None


# Setting up Sockets


def setup_CTP_sockets(proxy_port_number):

    print("Starting HTTP proxy on port:", proxy_port_number)
    print("*" * 50)

    Socket = socket.socket()
    Socket.bind(("127.0.0.1", proxy_port_number))
    Socket.listen(10)
    return Socket


def setup_PTS_socket():

    print("*" * 50)
    sck = socket.socket()
    return sck


# Socket Functions
def recieveClientRequest(my_socket):
    print("*" * 50)
    print("recieveClientRequest")
    print("*" * 50)
    clientSocket, clientAddr = my_socket.accept()
    request = clientSocket.recv(1024)

    return clientSocket, clientAddr, request.decode("utf-8")


def SendHttpRequestANDrecvData(my_socket, host_name, http_request):
    print("*" * 50)
    print("SendHttpRequestANDrecvData")
    print("*" * 50)
    # print("Host name : ", host_name)
    # server_ip = socket.gethostbyname(host_name)
    # Testing The function
    server_ip = socket.gethostbyname("www.google.com")
    http_request = b"GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n"
    # End of Testing
    my_socket.connect((server_ip, 80))
    my_socket.sendto(http_request, (server_ip, 80))
    packet = my_socket.recv(4096)
    print("Packet rec : ", packet)
    return packet


def SendtoClient(my_socket, ClientAddr, Data):
    print("Clie : ", ClientAddr)
    my_socket.sendto(Data, ClientAddr)


# http request parsing functions


def http_request_pipeline(clientAddr, request):  # get user input
    """
    HTTP request processing pipeline.

    - Parses the given HTTP request
    - Validates it
    - Returns a sanitized HttpRequestInfo or HttpErrorResponse
        based on request validity.

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """

    

    # Parse HTTP request
    my_http_obj = HttpRequestInfo(None, None, None, None, None, None)

    validation_Flag, my_request_list = check_http_request_validity(my_http_obj, request)

    if validation_Flag == HttpRequestState.GOOD:
        my_http_obj = parse_http_request(clientAddr, my_request_list)
    #   else:
    #       my_Error_obj=HttpErrorResponse(type of error 404 or 501 discuss it with ashry ,validation_Flag)

    # Validate, sanitize, return Http object.
    
    #b"GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n"
    #print(method) GET
    #print(path) /
    #print(host) www.google.com
    
    return my_http_obj


def parse_http_request(clientAddr, my_request_list) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """
    print("My Request list in parse : ", my_request_list)

    # Replace this line with the correct values.
    my_instruction = my_request_list[0]

    my_command = my_instruction.split(" ")[0]

    my_url = my_instruction.split(" ")[1]
    my_headers = my_request_list[1:]
    print("my headers in Parse http request: ", my_headers)

    if my_url.startswith("/"):  # if we get get http://www.google.com/ then call sanitize to remove everything before / and put in the host & add in the validation the http check and www check and .com check (or)
        my_url, my_headers = sanitize_http_request(my_request_list, my_url)
            # dont forget class error response and the hashmap
    my_version = my_instruction.split(" ")[2]
    ret = HttpRequestInfo(
        clientAddr, my_command, path,host, 80, my_headers
    )  ## eh howa l port number

    return ret


def check_http_request_validity(http_request_info: HttpRequestInfo, my_request):
    """
    Checks if an HTTP response is valid

    returns:
    One of values in HttpRequestState
    """
    my_request_list = my_request.split("\r\n")

    print("my request list in VALIDATION", my_request_list)

    if len(my_request_list[0].split(" ")) < 3:  # a field in command
        print("Problem in 0")
        return HttpRequestState.INVALID_INPUT, my_request_list

    else:
        my_command = get_arg(4, my_request_list[0].split(" ")[0])
        my_url = get_arg(5, my_request_list[0].split(" ")[1])
        my_version = get_arg(6, my_request_list[0].split(" ")[2])
        print("version : ", my_version)
        if my_command.casefold() != "get":
            return HttpRequestState.NOT_SUPPORTED, my_request_list

        if (
            "http" in my_url == False
            or my_url.find("http") != 0
            or my_url.startswith("/")
        ):
            if len(my_request_list) < 2:  # mean no header
                return HttpRequestState.INVALID_INPUT, my_request_list
            elif (
                any("Host:".casefold() in i for i in my_request_list) == False
            ):  # means no host
                return HttpRequestState.INVALID_INPUT, my_request_list

        if my_version == "HTTP/1.1" or my_version == "HTTP/1.0":
            return HttpRequestState.GOOD, my_request_list
        else:
            return HttpRequestState.NOT_SUPPORTED, my_request_list


def sanitize_http_request(my_request_list, my_path) -> HttpRequestInfo:
    """
    Puts an HTTP request on the sanitized (standard form)

    returns:
    A modified object of the HttpRequestInfo with
    sanitized fields

    for example, expand a URL to relative path + Host header.
    """
    find = r"\r"
    replace = ""
    text = re.sub(find, replace, my_request_list[1]).rstrip()

    my_headers = re.split("; |, |\*|\n", text)
    my_host_index = my_headers.index("Host:".casefold())
    my_site = my_headers[my_host_index].split("Host:", 1)[1]

    if not my_site.startswith("www."):
        my_full_url = "www." + my_site + my_path
    else:
        my_full_url = my_site + my_path

    return my_full_url, my_headers


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re

    matches = re.findall(r"(\d{4}_){2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    # my_input = input("Enter your command: ")
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    # new_line_Counter=my_input.count('\n') #count number of /n in the input string
    # space_r_counter=my_input.count('\r')  #count number of /r in the input string

    # print("new_line_Counter",new_line_Counter)
    # print("space_r_counter",space_r_counter)

    # print("my splitted line","*",entire_command,"*",commnad_headers)

    # print("iam here","*",my_command,"*",my_url,"*",my_version)
    entry_point(18888)


if __name__ == "__main__":
    main()
