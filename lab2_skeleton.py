# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket


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
        requested_host: str,
        requested_port: int,
        requested_path: str,
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

        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return None

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
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


def entry_point(proxy_port_number, my_input):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    my_proxy_socket = setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    source_Addr = "127.0.0.1 69"
    http_request_pipeline(source_Addr, my_input)
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    print("*" * 50)
    sck_client_to_proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the port
    server_address = ("127.0.0.1", proxy_port_number)
    print("starting up on {} port {}".format(*server_address))
    # Set timeout
    sck_client_to_proxy.settimeout(0.1)
    ###########################################################################################
    """sck_proxy_to_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the port
    server_address = ('localhost', proxy_port_number)
    print('starting up on {} port {}'.format(*server_address))
    sck.bind(server_address)
    sck.settimeout(0.1)
    print("*" * 50)
    """
    return sck_client_to_proxy


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def http_request_pipeline(source_addr, http_raw_data):  # get user input
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
    parsed = parse_http_request(source_addr, http_raw_data)

    # Validate, sanitize, return Http object.
    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)
    return None


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """
    print("*" * 50)
    print("[parse_http_request] Implement me!")
    print("*" * 50)
    # Replace this line with the correct values.
    http_raw_data = http_raw_data.replace(r"\r", " ")

    my_input_list = http_raw_data.split(r"\n")
    print("here is my list ", my_input_list)
    my_command = get_arg(4, my_input_list[0].split(" ")[0])
    my_url = get_arg(5, my_input_list[0].split(" ")[1])
    my_version = get_arg(6, my_input_list[0].split(" ")[2])

    ret = HttpRequestInfo(my_command, source_addr, my_url, None, None, None)

    return ret


def check_http_request_validity(
    http_request_info: HttpRequestInfo, my_command, my_url, http_raw_data, my_version
) -> HttpRequestState:
    """
    Checks if an HTTP response is valid

    returns:
    One of values in HttpRequestState
    """
    flag = 0

    if my_command.casefold() != "get":
        flag = 1
        return HttpRequestState.NOT_SUPPORTED

    import re

    my_protocol = re.findall(r"^\w+", my_url)
    if my_protocol.casefold() != "www":
        if not http_raw_data:
            return HttpRequestState.INVALID_INPUT

    if my_version.casefold() != "HTTP/1.0":
        return HttpRequestState.NOT_SUPPORTED

    # return HttpRequestState.GOOD (for example)
    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:
    """
    Puts an HTTP request on the sanitized (standard form)

    returns:
    A modified object of the HttpRequestInfo with
    sanitized fields

    for example, expand a URL to relative path + Host header.
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    ret = HttpRequestInfo(None, None, None, None, None, None)
    return ret


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
    my_input = input("Enter your command: ")
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
    entry_point(proxy_port_number, my_input)


if __name__ == "__main__":
    main()
