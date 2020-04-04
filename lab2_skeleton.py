import sys
import os
import enum
import socket
import re
import threading
import string

# HTTP Objects


class HttpRequestInfo(object):
    def __init__(
        self,
        client_info,
        method: str,
        requested_host: str,
        requested_port: int,
        requested_path: str,
        headers: list,
    ):
        self.client_address_info = client_info
        self.method = method
        self.requested_path = requested_path
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.headers = headers

    def to_http_string(self):
        my_list = []
        for H in self.headers:
            my_list.append(H[0] + ": " + H[1])
        my_list.append("")
        my_list.append("")
        self.headers.clear()
        self.headers = my_list.copy()

        Headers = "\r\n".join(self.headers)
        HttpStringRequest = (
            self.method + " " + self.requested_path + " HTTP/1.0\r\n" + Headers
        )
        return HttpStringRequest

    def to_byte_array(self, HttpStringRequest):
        return bytes(HttpStringRequest, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Path:", self.requested_path)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        print("Headers:\n", self.headers)

    def getRequestPacket(self):
        HttpRequest = self.to_http_string()
        return self.to_byte_array(HttpRequest)

    def getKey(self):
        return self.method + self.requested_host + self.requested_path

    def getType(self):
        return True

    def getHost(self):
        return self.requested_host

    def getPort(self):
        return self.requested_port


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return "HTTP/1.0 " + str(self.code) + " " + self.message + "\r\n\r\n"

    def to_byte_array(self, ErrRequest):
        return bytes(ErrRequest, "UTF-8")

    def display(self):
        print(self.to_http_string())

    def getResponsePacket(self):
        ErrResponse = self.to_http_string()
        return self.to_byte_array(ErrResponse)

    def getType(self):
        return False


# HTTP Request state


class HttpRequestState(enum.Enum):

    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


# Main Code


def entry_point(proxy_port_number):
    print("Entry Point")
    print("*" * 50)
    # Setup the Dictionary
    Requests = dict()

    # Intialize CTP Socket
    PSocket = setup_CTP_sockets(proxy_port_number)

    while True:

        # Waiting For Connections and Setting up Clients sockets
        print("Waiting For Client Request")
        print("*" * 50)
        clientSocket, clientAddr = PSocket.accept()
        # Start Thread for the connected Client and get ready to accept another
        threading.Thread(
            target=ServeClientRequest, args=(clientSocket, clientAddr, Requests)
        ).start()

    return None


def ServeClientRequest(clientSocket, clientAddr, Cache):

    # Recieve Client Request
    request = recieveClientRequest(clientSocket)
    # Get Http request object
    serverRequest = http_request_pipeline(clientAddr, request)

    if serverRequest.getType():  # Valid Request

        # Check if the packet in the cache
        Response = SearchANDSend(serverRequest.getKey(), Cache)

        if not Response:  # Packet is not in Cache

            # Get Request to remote server Packet

            http_request = serverRequest.getRequestPacket()
            # Open Socket between proxy and remote servers
            serverSocket = setup_PTS_socket()
            # Send Request and rec packet(S)
            host = serverRequest.getHost()
            port = serverRequest.getPort()
            Response = SendRequestANDrecvData(serverSocket, host, port, http_request)

            # Close remote server socket
            serverSocket.close()

            # Insert in cache
            Cache[serverRequest.getKey()] = Response

    else:  # Invalid Request
        # Get Packet Error to send it to the client
        Response = serverRequest.getResponsePacket()

    # Send Response packet to the client
    SendtoClient(clientSocket, clientAddr, Response)
    # Close client socket
    clientSocket.close()
    print("Response Sent")
    print("*" * 50)


# Cache Check-up


def SearchANDSend(Request, DictionaryRequests):

    if Request in DictionaryRequests:
        return DictionaryRequests[Request]
    return False


# Setting up Sockets


def setup_CTP_sockets(proxy_port_number):

    print("Starting HTTP proxy on port:", proxy_port_number)
    print("*" * 50)

    Socket = socket.socket()
    Socket.bind(("127.0.0.1", proxy_port_number))
    Socket.listen(15)
    return Socket


def setup_PTS_socket():

    sck = socket.socket()
    sck.settimeout(2)

    return sck


# Socket Functions


def recieveClientRequest(clientSocket):

    request = clientSocket.recv(1024)

    return request.decode("UTF-8")


def SendRequestANDrecvData(my_socket, host_name, my_port, http_request):
    my_port = int(my_port)
    # Get server IP
    server_ip = socket.gethostbyname(host_name)
    # Connect to remote server
    my_socket.connect((server_ip, my_port))
    # Send Request to remote server
    my_socket.sendto(http_request, (server_ip, my_port))
    # Wait for server Response
    # Receive Packets
    packets = []
    packet = 0
    while True:
        try:
            packet = my_socket.recv(1024)
        except:
            break
        if packet:
            packets.append(packet)
        else:
            break

    return packets


def SendtoClient(my_socket, ClientAddr, Data):
    if type(Data) == list:
        for packet in Data:
            my_socket.sendto(packet, ClientAddr)
    else:
        my_socket.sendto(Data, ClientAddr)


def message_coding_Switcher(argument):
    switcher = {
        HttpRequestState.INVALID_INPUT: 400,
        HttpRequestState.NOT_SUPPORTED: 501,
    }
    return switcher.get(argument, "Invalid message")


# Http Request Handling functions


def http_request_pipeline(clientAddr, request):
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
    http_obj = HttpRequestInfo(None, None, None, None, None, None)

    validation_Flag = check_http_request_validity(request)

    if validation_Flag == HttpRequestState.GOOD:
        http_obj = parse_http_request(clientAddr, request)
    else:
        my_error_code = message_coding_Switcher(validation_Flag)
        http_obj = HttpErrorResponse(my_error_code, validation_Flag.name)
    return http_obj


def parse_http_request(clientAddr, my_request) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """

    my_request_list = my_request.split("\r\n")

    my_instruction = my_request_list[0]
    my_headers = my_request_list[1:]
    my_command = my_instruction.split(" ")[0]
    my_url = my_instruction.split(" ")[1]

    # Absolute Request
    if my_url.startswith("/") == False:

        my_path, my_host, my_port, my_headers = sanitize_http_request(
            my_request_list, my_url
        )

    # Relative Path
    else:
        my_path = my_url
        my_port = 80
        for i, s in enumerate(my_headers):
            if "Host: " in s:
                my_host = s.split(":")[1].strip()
                my_headers[i] = "Host: " + my_host
                try:
                    my_port = s.split(":")[2]
                except:
                    pass
                break

    my_appended_list = []

    for s in my_headers:
        if s != "":
            l = s.split(":")
            my_appended_list.append([i.strip(" ") for i in l])

    ret = HttpRequestInfo(
        clientAddr, my_command, my_host, my_port, my_path, my_appended_list
    )
    return ret


def check_http_request_validity(my_request):
    """
    Checks if an HTTP response is valid

    returns:
    One of values in HttpRequestState
    """
    my_request_list = my_request.split("\r\n")
    filter_object = filter(lambda x: x != "", my_request_list)
    my_request_list = list(filter_object)
    command_Regx = re.compile("[a-z]{3,4} [\a-z]{1,} [\a-z]{3,}")

    if (
        len(my_request_list[0].split(" ")) < 3
        or command_Regx.match(my_request_list[0].lower()) == False
    ):  #  field missing
        return HttpRequestState.INVALID_INPUT

    else:
        if (
            not my_request_list[0].split(" ")[0].strip()
            or not my_request_list[0].split(" ")[1].strip()
            or not my_request_list[0].split(" ")[2].strip()
        ):
            return HttpRequestState.INVALID_INPUT
        else:
            my_command = get_arg(4, my_request_list[0].split(" ")[0]).strip()  # get
            my_url = get_arg(5, my_request_list[0].split(" ")[1]).strip()  # http:////
            my_version = get_arg(6, my_request_list[0].split(" ")[2]).strip()

            # Validaite Headers
            print("Command", my_command)
            Flag = 0
            print
            for s in my_request_list[1:]:

                try:
                    Hls = s.split(":")
                    if len(Hls[0]) > 3 and len(Hls[1]) > 3:
                        Flag = 1
                except:
                    return HttpRequestState.INVALID_INPUT
                if Flag != 1:
                    return HttpRequestState.INVALID_INPUT

            if my_url.startswith("/"):
                my_host_index = -1
                for i, s in enumerate(my_request_list):
                    if "Host: " in s:
                        my_host_index = i
                        break

                if my_host_index == -1:
                    return HttpRequestState.INVALID_INPUT

            if my_version.lower() not in ["http/1.1", "http/1.0"] == True:

                return HttpRequestState.NOT_SUPPORTED

            if my_command.lower() != "get":
                if (
                    my_command.lower() == "head"
                    or my_command.lower() == "post"
                    or my_command.lower() == "put"
                ):

                    return HttpRequestState.NOT_SUPPORTED
                else:

                    return HttpRequestState.INVALID_INPUT
            return HttpRequestState.GOOD


def sanitize_http_request(my_request_list, my_url) -> HttpRequestInfo:

    my_headers = my_request_list[1:]  # all my headers

    my_port = 80

    # Site URL
    my_site = my_url[: (my_url.index(".com") + 4)]
    # Port + Path
    AfterSite = my_url.split(".com".casefold())[1]
    # check If port exists in Url

    try:
        # Extract port and path
        AfterSite = AfterSite.split(":".casefold())[1]
        try:
            my_port = AfterSite.split("/".casefold())[0]
            my_path = "/" + AfterSite.split("/".casefold())[1]
        except:
            my_port = AfterSite
            my_path = "/"
    except:
        # Extract Path only
        try:
            my_path = "/" + AfterSite.split("/".casefold())[1]
        except:
            my_path = "/"

    my_host_index = -1

    for i, s in enumerate(my_headers):
        if "Host" in s:
            my_host_index = i
            break

    # End of texting
    if my_host_index != -1:
        # Get Port Number from Host header if it exists
        try:
            my_port = my_headers[my_host_index].split(":")[2]
        except:
            pass

        if my_site.startswith("http://".casefold()):
            my_site = my_site.partition("http://")[2].strip()

            if my_site.startswith("www.".casefold()):
                my_host = my_site

            else:
                my_host = "www." + my_site

        elif my_site.startswith("www.".casefold()):
            my_host = my_site

        else:
            my_host = "www." + my_site

        my_headers[my_host_index] = "Host: " + my_host

    else:

        if my_site.startswith("http://".casefold()):
            my_site = my_site.partition("http://")[2].strip()

            if my_site.startswith("www.".casefold()):

                my_host = my_site

            else:
                my_host = "www." + my_site

        elif my_site.startswith("www.".casefold()):

            my_host = my_site

        else:
            my_host = "www." + my_site

        my_headers.insert(0, "Host: " + my_host)

    return my_path, my_host, my_port, my_headers


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
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
