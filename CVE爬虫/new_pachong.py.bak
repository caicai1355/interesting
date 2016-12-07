# -*- coding: utf-8 -*- 
#!/usr/bin/env python

from socket import *
import sys
import re
import urllib2
import MySQLdb

reload(sys)
sys.setdefaultencoding('GBK')
cur = None
conn = None

def connect():
	dbName = 'test'
	userName = 'root'
	passwd = '123456'
	try:
		conn = MySQLdb.connect(db=dbName,user=userName,passwd=passwd,charset='GBK')
		return conn.cursor(),conn
	except:
		print 'mysql connect error!'
		exit(0)

def cve_analyse(url):
	pattern1 = re.compile("<title>.*?(CVE-\d{4}-\d{4})")
	pattern2 = re.compile("\[原文\]</span>(.*?)</p>")
	pattern3 = re.compile("\[CNNVD\]</span><strong>(.*?)</strong>")
	pattern4 = re.compile("<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>(.*?)</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*(<br/>)*(.*?)</p>")
	pattern5 = re.compile(">(CNNVD-\d+-\d+)</")
	#pattern6 = re.compile("<td width=.*?>CVSS分值:</td>\s*?<td width=.*?>(.*?)</td>")

	#CVE号
	cveNum = pattern1.search(url)
	print "CVE号："
	if cveNum == None:
		print("   暂无CVE号")
	else:
		print("   " + cveNum.group(1))

	#英文标题
	cveENTitle = pattern2.search(url)
	print "CVE英文标题："
	if cveENTitle == None:
		print("   暂无CVE英文标题")
	else:
		print("   " + cveENTitle.group(1))

	#中文标题
	cveCNTitle = pattern3.search(url)
	print "CNNVE中文标题："
	if cveCNTitle == None:
		print("   暂无CNNVE中文标题")
	else:
		print("   " + cveCNTitle.group(1))

	#中文描述
	cnnveMsg = pattern4.search(url)
	print "CNNVE信息："
	if cnnveMsg == None:
		print("   暂无CNNVE信息")
	else:
		print("   " + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>',''))

	#CNNVD号
	cnnvdNum = pattern5.search(url)
	print "CNNVD号："
	if cnnveMsg == None:
		print("   CNNVD号")
	else:
		print("   " + cnnvdNum.group(1))

	#CVSS分值

	print
	print "================================="
	print

	if True:
		query = ''
		query += "insert into cvemsg values("
		query += (cveNum != None) and ("'" + cveNum.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveENTitle != None) and ("'" + cveENTitle.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveCNTitle != None) and ("'" + cveCNTitle.group(1).replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnveMsg != None) and ("'" + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>','').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnvdNum != None) and ("'" + cnnvdNum.group(1).replace('\'','\\\'').replace('\"','\\\"') + "'") or "NULL"
		query += ")"
		print query.decode("utf-8")
		#query = query.decode("gbk").encode("utf-8")
		cur.execute(query)
		conn.commit()
	if True:
		print "insert " + cveNum.group(1) + " error!"

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

def crawl_allsitemap(url,analyse):
	sitemap = download(url)
	if sitemap:
		links = re.findall("<loc>(.*?)</loc>",sitemap)
		if links:
			for link in links:
				html = crawl_allsitemap(link,analyse)
		analyse(sitemap)

cur,conn = connect()
crawl_allsitemap("http://www.scap.org.cn/sitemap.xml",cve_analyse)

# reload(sys)
# sys.setdefaultencoding('gbk')

# a = "请输入cve号(xxxx-xxxx):"
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
# 	print("信息不存在")
# 	exit(0)

# res2=pattern.search(msg)
# if res2 == None:
# 	print("暂无CNNVE信息")
# 	exit(0)

# print("\n" + res2.group(2))