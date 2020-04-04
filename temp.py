import enum
import re 
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


def check_http_request_validity( my_request):
    """
    Checks if an HTTP response is valid

    returns:
    One of values in HttpRequestState
    """
    find = r'\r'
    replace = ''
    text = re.sub(find, replace, my_request).rstrip()
    print(text)
    s = " "
    my_request_list=re.split('; |, |\*|\n',text)

    if len(my_request_list[0].split(' '))<3: #a field in command
        return HttpRequestState.INVALID_INPUT
    else:

        my_command =  my_request_list[0].split(" ")[0]
        my_url = my_request_list[0].split(" ")[1]
        my_version =  my_request_list[0].split(" ")[2]

    

    if my_command.casefold() != "get":
        return HttpRequestState.NOT_SUPPORTED

    
    if "http" in my_url== False or my_url.find("http")!=0 :
        if len(my_request_list)<2: #mean no header
            return HttpRequestState.INVALID_INPUT


    # return HttpRequestState.GOOD (for example)
    return HttpRequestState.GOOD
my_string="GET / HTTP/1.0\r\nHost: google.edu\r\n\r\n"
print (my_string.split("Host:",1)[1] )