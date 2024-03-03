import requests


target_url = "http://192.168.42.130/dvwa/login.php"

data_dict = {"username" : "admin", "password" : "password", "Login" : "sumbit"}
#name field in html code of web page and there values I want to enter (Login is a button so its value and field is already in the web page source)

response = requests.post(target_url, data=data_dict)

print(response.content.decode(errors="error"))