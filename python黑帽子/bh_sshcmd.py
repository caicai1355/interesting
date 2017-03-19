# -*- coding:utf-8 -*-

import threading
import paramiko
import subprocess

def ssh_conmmand(ip,user,passwd,command):
	client = paramiko.SSHClient()

	#这里是表示也支持用秘钥认证来代替密码验证
	#client.load_host_keys('????')

	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(ip,username=user,password=passwd)
	ssh_session = client.get_transport().open_session()
	if ssh_session.active:
		ssh_session.exec_command(command)
		print ssh_session.recv(1024)
	return

ssh_conmmand("192.168.137.130","root","123456","dir")
#ssh_conmmand("192.168.160.12","administrator","123","dir")
#ssh_conmmand("192.168.162.115","root","123456","dir")