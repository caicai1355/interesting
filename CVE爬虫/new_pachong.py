# -*- coding: utf-8 -*- 
#!/usr/bin/env python

from socket import *
import sys
import re
import urllib2

def download(url,user_agent = "wswp",num_retries=2):
	print "Downloading:",url
	headers = {"User-agent" : user_agent}
	request = urllib2.Request(url,headers = headers)
	try:
		html = urllib2.urlopen(request).read()
	except urllib2.URLError as e:
		print "Download error:" , e.reason
		html = None
		if num_retries > 0:
			if hasattr(e,"code") and 500 <= e.code < 600:
				return download(url,user_agent,num_retries-1)
	return html

reload(sys)
sys.setdefaultencoding('gbk')

a = "请输入cve号(xxxx-xxxx):".decode('UTF-8')
if(len(sys.argv) < 2):
	cveid = raw_input(a)
else:
	cveid = sys.argv[1]


# a = socket(AF_INET,SOCK_STREAM)

# a.connect( ('202.112.50.72',80) )

# a.send("GET http://202.112.50.72:80/CVE-" + cveid + ".html HTTP/1.1 \r\nAccept-Language:zh-CN,zh;q=0.8\r\nHOST:cve.scap.org.cn\r\n\r\n")

#CVE-2005-2761
url = "http://cve.scap.org.cn/" + cveid + ".html"
#url = "http://httpstat.us/500"
msg = download(url)
if not msg:
	exit(0)

pattern = re.compile("<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>[^<]*</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*([^<]*)<")
notfound = re.compile("404 Not Found")

#res = a.recv(66666)
#print(res)
if notfound.search(msg):
	print("信息不存在".decode('UTF-8'))
	exit(0)

res2=pattern.search(msg)
if res2 == None:
	print("暂无CNNVE信息".decode('UTF-8'))
	exit(0)

print("\n" + res2.group(2).decode('UTF-8'))

#a.close()