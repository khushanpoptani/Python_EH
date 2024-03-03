import  requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse


def request(url):
    try:
        return requests.get(url)
    except requests.exceptions.ConnectionError:
            pass

#"http://192.168.42.130/mutillidae/index.php?page=dns-lookup.php" "http://192.168.42.130/dvwa/login.php"

target_url =  "http://192.168.42.130/mutillidae/index.php?page=dns-lookup.php"
response = request(target_url)

parse_html = BeautifulSoup(response.content.decode(), features="lxml")
forms_list = parse_html.find_all("form")


for forms in forms_list:
    action = forms.get("action")
    post_url = urlparse.urljoin(target_url, action)
    method = forms.get("method")

    post_data = {}


    input_list = forms.findAll("input")
    for input in input_list:
        input_name = input.get("name")
        input_type = input.get("type")
        input_value = input.get("value")

        if input_type == "text":
            input_value = "Khushan"

        elif input_type == "password":
            input_value = "Poptani"

        post_data[input_name] = input_value


    result = requests.post(post_url, data=post_data)
    print(result.content.decode())