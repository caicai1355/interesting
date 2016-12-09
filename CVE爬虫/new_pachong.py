# -*- coding: utf-8 -*- 
#!/usr/bin/env python

from socket import *
import sys
import re
import urllib2
import MySQLdb

reload(sys)
sys.setdefaultencoding('utf8')
cur = None
conn = None


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

def crawl_sitemap(url):
	sitemap = download(url)
	links = re.findall("<loc>(.*?)</loc>",sitemap)
	for link in links:
		html = download(link)













def connect():
	dbName = 'test'
	userName = 'root'
	passwd = '123456'
	try:
		#conn = MySQLdb.connect(db='test',user='root',passwd='123456',charset='utf8')
		conn = MySQLdb.connect(db=dbName,user=userName,passwd=passwd,charset='utf8')
		return conn.cursor(),conn
	except:
		print 'mysql connect error!'
		exit(0)


def cve_analyse(content):
	patSTR1 = "<title>.*?(CVE-\d{4}-\d{4})"
	patSTR2 = "\[原文\]</span>(.*?)</p>"
	patSTR3 = "\[CNNVD\]</span><strong>(.*?)</strong>"
	patSTR4 = "<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>(.*?)</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*(<br/>)*(.*?)</div>"
	patSTR5 = ">(CNNVD-\d+-\d+)</"

	pattern1 = re.compile(patSTR1)
	pattern2 = re.compile(patSTR2,re.S)
	pattern3 = re.compile(patSTR3,re.S)
	pattern4 = re.compile(patSTR4,re.S)
	pattern5 = re.compile(patSTR5)
	#pattern6 = re.compile("<td width=.*?>CVSS分值:</td>\s*?<td width=.*?>(.*?)</td>")

	#CVE号
	cveNum = pattern1.search(content)
	print "CVE号：".decode('UTF-8')
	if cveNum == None:
		print("   暂无CVE号".decode('UTF-8'))
		return;
	else:
		print("   " + cveNum.group(1).decode('UTF-8'))

	#英文标题
	cveENTitle = pattern2.search(content)
	print "CVE英文标题：".decode('UTF-8')
	if cveENTitle == None:
		print("   暂无CVE英文标题".decode('UTF-8'))
	else:
		print("   " + cveENTitle.group(1).decode('UTF-8'))

	#中文标题
	cveCNTitle = pattern3.search(content)
	print "CNNVE中文标题：".decode('UTF-8')
	if cveCNTitle == None:
		print("   暂无CNNVE中文标题".decode('UTF-8'))
	else:
		print("   " + cveCNTitle.group(1).decode('UTF-8'))

	#中文描述
	cnnveMsg = pattern4.search(content)
	print "CNNVE信息：".decode('UTF-8')
	if cnnveMsg == None:
		print("   暂无CNNVE信息".decode('UTF-8'))
	else:
		print("   " + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>','').replace('<p>','\n').replace('</p>','').replace('\'','\\\'').replace('\"','\\\"').decode('UTF-8'))

	#CNNVD号
	cnnvdNum = pattern5.search(content)
	print "CNNVD号：".decode('UTF-8')
	if cnnveMsg == None:
		print("   暂无CNNVD号".decode('UTF-8'))
	else:
		print("   " + cnnvdNum.group(1).decode('UTF-8'))

	#CVSS分值

	print

	try:
		query = ''
		query += "insert into cveall values("
		query += (cveNum != None) and ("'" + cveNum.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveENTitle != None) and ("'" + cveENTitle.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveCNTitle != None) and ("'" + cveCNTitle.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnveMsg != None) and ("'" + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>','').replace('<p>','\n').replace('</p>','').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnvdNum != None) and ("'" + cnnvdNum.group(1).replace('\'','\\\'').replace('\"','\\\"') + "'") or "NULL"
		query += ")"
		#print ("'" + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>','').replace('<p>','\n').replace('</p>','').replace('\'','\\\'').replace('\"','\\\"') + "',")
		cur.execute(query)
		conn.commit()
		print "insert " + cveNum.group(1).decode('UTF-8') + " success!"
	except Exception,e:
		print "insert " + cveNum.group(1).decode('UTF-8') + " error!"
		print e

	print
	print "================================="
	print


#==============扫web=============================================


def crawl_sitemap_web(url,analyse):
	sitemap = download(url)
	if sitemap:
		links = re.findall("<loc>(.*?)</loc>",sitemap)
		if links:
			for link in links:
				if url_filter(link):
					html = crawl_sitemap_web(link,analyse)
				else:
					print "pass the url : " + link

def url_filter(url):
	patternUrl = re.compile("http://cve.scap.org.cn/(CVE-\d{4}-\d{4}).html")
	try:
		cur.execute("select cveid from cve order by cveid desc limit 1")
		ret = cur.fetchall()
		cveId = patternUrl.search(url)
		if cveId:
			if cveId.group(1) > ret[0][0]:
				return True
			else:
				return False
		else:
			return True
	except:
		return False		
		analyse(sitemap)

def cve_get_from_web():
	global cur,conn
	cur,conn = connect()
	crawl_sitemap_web("http://www.scap.org.cn/sitemap.xml",cve_analyse)



#======================扫文档=======================================


def cve_filter(url):
	patternUrl = re.compile("http://cve.scap.org.cn/(CVE-\d{4}-\d{4}).html")
	try:
		cveId = patternUrl.search(url)
		ret = cur.execute("select cveid from cveall where cveid = '" + cveId.group(1) + "'")
		#print "select cveid from cveall where cveid = '" + cveId.group(1) + "'"
		if ret == 0:
			return True
		else:
			return False
	except:
		return False	

def cve_get_from_local():
	global cur,conn
	cur,conn = connect()
	file = open("C:\Users\caizhiyuan\Desktop\cveall.txt")
	count = len(file.readlines())
	file.seek(0)
	for i in range(count):
		cve = file.readline()
		url = "http://cve.scap.org.cn/" + cve[:13] + ".html"
		try:
			if cve_filter(url):
				sitemap = download(url)
				cve_analyse(sitemap)
			else:
				#print "pass the url : " + url
				pass
		except:
			print "error!"
			exit(0)



#==============================================================
if __name__ == '__main__':

	cve_get_from_local()





# reload(sys)
# sys.setdefaultencoding('gbk')

# a = "请输入cve号(xxxx-xxxx):".decode('UTF-8')
# if(len(sys.argv) < 2):
# 	cveid = raw_input(a)
# else:
# 	cveid = sys.argv[1]

# #CVE-2005-2761
# url = "http://cve.scap.org.cn/" + cveid + ".html"
# #url = "http://httpstat.us/500"
# msg = download(url)
# if not msg:
# 	exit(0)

# pattern = re.compile("<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>[^<]*</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*([^<]*)<")
# notfound = re.compile("404 Not Found")

# if notfound.search(msg):
# 	print("信息不存在".decode('UTF-8'))
# 	exit(0)

# res2=pattern.search(msg)
# if res2 == None:
# 	print("暂无CNNVE信息".decode('UTF-8'))
# 	exit(0)

# print("\n" + res2.group(2).decode('UTF-8'))