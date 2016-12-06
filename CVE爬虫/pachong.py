# -*- coding: utf-8 -*- 
#!/usr/bin/env python

from socket import *
import sys
import re

reload(sys)
sys.setdefaultencoding('gbk')

a= "请输入cve号(xxxx-xxxx):".decode('UTF-8')
if(len(sys.argv) < 2):
	cveid = raw_input(a)
else:
	cveid = sys.argv[1]


a = socket(AF_INET,SOCK_STREAM)

a.connect( ('202.112.50.72',80) )

# 2005-2761
a.send("GET http://202.112.50.72:80/CVE-" + cveid + ".html HTTP/1.1 \r\nAccept-Language:zh-CN,zh;q=0.8\r\nHOST:cve.scap.org.cn\r\n\r\n")
# a.send("GET http://202.112.50.72:80 HTTP/1.1 \r\n"+
# 	"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"+
# 	"Accept-Encoding:gzip, deflate, sdch"+
# 	"Accept-Language:zh-CN,zh;q=0.8"+
# 	"Connection:keep-alive"+
# 	"Host:cve.scap.org.cn"+
# 	"Upgrade-Insecure-Requests:1"+
# 	"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36")

pattern = re.compile("<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>[^<]*</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*([^<]*)<")
notfound = re.compile("404 Not Found")

res = a.recv(66666)
#print(res)
if notfound.search(res):
	print("信息不存在".decode('UTF-8'))
	exit(0)

res2=pattern.search(res)
if res2 == None:
	print("暂无CNNVE信息".decode('UTF-8'))
	exit(0)

print("get message : \n\n" + res2.group(2).decode('UTF-8'))

a.close()

print("\nclient end")
# #!/usr/bin/env python

# from socket import *

# a = socket(AF_INET,SOCK_STREAM)

# a.bind( ('master',5556) )

# a.connect( ('master',5555) )

# print("get message : " + a.recv(1024))

# a.close()

# print("client end")