# -*- coding: utf-8 -*- 
#!/usr/bin/env python

from socket import *
import sys
import re
import urllib2
import MySQLdb
import bs4

reload(sys)
sys.setdefaultencoding('utf8')
cur = None
conn = None
file = None


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
	strTemp = ''
	patSTR1 = "<title>.*?(CVE-\d{4}-\d{4})"
	patSTR2 = "\[原文\]</span>(.*?)</p>"
	patSTR3 = "\[CNNVD\]</span><strong>(.*?)</strong>"
	patSTR4 = "<hr size=\"0\" />\s*<p><span class=[\"']tip_text[\"'] title=\"[^\"]*\">\[CNNVD\]</span><strong>(.*?)</strong>\(<a href=\"[^\"]*\"\s*target=\"[^\"]*\">[^<]*</a>\)</p><p>(&nbsp;)*((<br/>)*.*?)</div>"
	patSTR5 = ">(CNNVD-\d+-\d+)</"
	patSTR6 = "<td\s*width=\"\d*%\">CVSS分值:?</td>\s*<td\s*width=\"\d*%\">\s*(\d*\.?\d*)\s*</td>"
	patSTR7 = "<td>机密性影响:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR8 = "<td>完整性影响:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR9 = "<td>可用性影响:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR10 = "<td>攻击复杂度:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR11 = "<td>攻击向量:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR12 = "<td>身份认证:?</td>\s*<td>([a-zA-Z]*)\s*</td>"
	patSTR13 = "CPE \(受影响的平台与产品\)\s*</h2>\s*<\s*table[^>]*>.*?<\s*/\s*table[^>]*>"
	patSTR13_1 = "<td[^>]*62%[^>]*>(.*?)</td>"
	patSTR14 = "CWE \(弱点类目\).*?<a\s*href=[^>]*>(CWE-\d+?)\s*</a>"
	patSTR15 = "<label>漏洞类型:</label>(.*?)</td>"
	patSTR16 = "<td><label>发布日期:</label>(.*?)</td>"
	patSTR17 = "<td><label>更新日期:</label>(.*?)</td>"
	patSTR18 = "<td><label>攻击路径:</label>(.*?)</td>"
	patSTR19 = "<label>BugtraqID:</label>\s*<a\s*href=[^>]*>(\d+)</a></td>"
	#patSTR20 = "公告与补丁</h2>\s*<table[^>]*>\s*<tr>\s*<td>\s*(.*?)\s*</td>\s*</tr>"
	patSTR20 = "公告与补丁</h2>\s*<table[^>]*>\s*<tr>\s*<td>\s*.*?\s*</td>\s*</tr>"
	patSTR21 = "<a\s*href\s*=\s*[\'\"\`][^\'\"\`]*?[\'\"\`]\s*[^>]*?>"

	pattern1 = re.compile(patSTR1)
	pattern2 = re.compile(patSTR2,re.S)
	pattern3 = re.compile(patSTR3,re.S)
	pattern4 = re.compile(patSTR4,re.S)
	pattern5 = re.compile(patSTR5)
	#pattern6 = re.compile("<td width=.*?>CVSS分值:</td>\s*?<td width=.*?>(.*?)</td>")
	pattern6 = re.compile(patSTR6,re.S)
	pattern7 = re.compile(patSTR7,re.S)
	pattern8 = re.compile(patSTR8,re.S)
	pattern9 = re.compile(patSTR9,re.S)
	pattern10 = re.compile(patSTR10,re.S)
	pattern11 = re.compile(patSTR11,re.S)
	pattern12 = re.compile(patSTR12,re.S)
	pattern13 = re.compile(patSTR13,re.S)
	pattern13_1 = re.compile(patSTR13_1,re.S)
	pattern14 = re.compile(patSTR14,re.S)
	pattern15 = re.compile(patSTR15,re.S)
	pattern16 = re.compile(patSTR16,re.S)
	pattern17 = re.compile(patSTR17,re.S)
	pattern18 = re.compile(patSTR18,re.S)
	pattern19 = re.compile(patSTR19,re.S)
	pattern20 = re.compile(patSTR20,re.S)
	pattern21 = re.compile(patSTR21,re.S)

	file.write('=========================================================' + '\n')

	#CVE号
	cveNum = pattern1.search(content)
	strTemp =  "CVE号："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cveNum == None:
		strTemp = "   暂无CVE号"
		file.write(strTemp + '\n')
		print strTemp.decode('UTF-8').encode('GB18030')
		return;
	else:
		strTemp = "   " + cveNum.group(1)
		file.write(strTemp + '\n')
		print strTemp.decode('UTF-8').encode('GB18030')

	#英文标题
	cveENTitle = pattern2.search(content)
	strTemp =  "CVE英文标题："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cveENTitle == None:
		strTemp = "   暂无CVE英文标题"
	else:
		strTemp = "   " + cveENTitle.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#中文标题
	cveCNTitle = pattern3.search(content)
	strTemp = "CNNVE中文标题："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cveCNTitle == None:
		strTemp = "   暂无CNNVE中文标题"
	else:
		strTemp = "   " + cveCNTitle.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#中文描述
	cnnveMsg = pattern4.search(content)
	strTemp = "CNNVE信息："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cnnveMsg == None:
		strTemp = "   暂无CNNVE信息"
	else:
		strTemp = "   " + cnnveMsg.group(3).replace('&nbsp;','')

		#reportAndHotfixStr = reportAndHotfix.group().replace('&nbsp;','')
		soup = bs4.BeautifulSoup(strTemp)
		cnnveMsg = ''.join([i.lstrip().rstrip('\n') +'\n' for i in soup.strings if i != '' and i != '\n']).lstrip('\n').rstrip('\n')
		strTemp = "   " + cnnveMsg

	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#CNNVD号
	cnnvdNum = pattern5.search(content)
	strTemp = "CNNVD号："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cnnvdNum == None:
		strTemp = "   暂无CNNVD号"
	else:
		strTemp = "   " + cnnvdNum.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#CVSS分值
	cvssScore = pattern6.search(content)
	strTemp = "CVSS分值："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if cvssScore == None:
		strTemp = "   暂无CVSS分值"
	else:
		strTemp = "   " + cvssScore.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#机密性影响：
	secrecyEff  = pattern7.search(content)
	strTemp = "机密性影响："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if secrecyEff == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + secrecyEff.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	#完整性影响
	completeEff  = pattern8.search(content)
	strTemp = "完整性影响："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if completeEff == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + completeEff.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#可用性影响
	enableEff  = pattern9.search(content)
	strTemp = "可用性影响："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if enableEff == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + enableEff.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#攻击复杂度
	attackComplex  = pattern10.search(content)
	strTemp = "攻击复杂度："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if attackComplex == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + attackComplex.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#攻击向量
	attackVec  = pattern11.search(content)
	strTemp = "攻击向量："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if attackVec == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + attackVec.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#身份认证
	identityCred  = pattern12.search(content)
	strTemp = "身份认证："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if identityCred == None:
		strTemp = "   暂无机密性影响"
	else:
		strTemp = "   " + identityCred.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#CPE (受影响的平台与产品))
	CPE1  = pattern13.search(content)
	strTemp = "CPE (受影响的平台与产品)："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if CPE1 == None:
		strTemp = "   暂无 CPE (受影响的平台与产品)"
	else:
		CPE2  = pattern13_1.findall(CPE1.group())
		if CPE2 == '':
			strTemp = "   暂无 CPE (受影响的平台与产品)"
		else:
			CPE = ''
			for i in CPE2:
				if i != '':
					CPE += i + '\n'
			if(len(CPE) != 0 and CPE[-1] == '\n'):
				CPE = CPE[:-1]
			strTemp = "   " + CPE
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#CWE (弱点类目)
	CWE  = pattern14.search(content)
	strTemp = "CWE (弱点类目)："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if CWE == None:
		strTemp = "   暂无 CWE (弱点类目)"
	else:
		strTemp = "   " + CWE.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#漏洞类型
	vulType  = pattern15.search(content)
	strTemp = "漏洞类型："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if vulType == None:
		strTemp = "   暂无漏洞类型"
	else:
		strTemp = "   " + vulType.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#cnnvd发布日期
	releaseDate  = pattern16.search(content)
	strTemp = "cnnvd发布日期："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if releaseDate == None:
		strTemp = "   暂无cnnvd发布日期"
	else:
		strTemp = "   " + releaseDate.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#cnnvd更新日期
	updateDate  = pattern17.search(content)
	strTemp = "cnnvd更新日期："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if updateDate == None:
		strTemp = "   暂无cnnvd更新日期"
	else:
		strTemp = "   " + updateDate.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#攻击路径
	atkUrl  = pattern18.search(content)
	strTemp = "攻击路径："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if atkUrl == None:
		strTemp = "   暂无攻击路径"
	else:
		strTemp = "   " + atkUrl.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	
	#BugtraqID
	BugtraqID  = pattern19.search(content)
	strTemp = "BugtraqID："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if BugtraqID == None:
		strTemp = "   暂无BugtraqID"
	else:
		strTemp = "   " + BugtraqID.group(1)
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	reportAndHotfix  = pattern20.search(content)
	reportAndHotfixStr = ''
	strTemp = "公告与补丁："
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')
	if reportAndHotfix == None:
		strTemp = "   暂无公告与补丁"
	else:
		reportAndHotfixStr = reportAndHotfix.group().replace('&nbsp;','')
		soup = bs4.BeautifulSoup(reportAndHotfixStr)
		reportAndHotfixStr = ''.join([i.lstrip().rstrip('\n') +'\n' for i in soup.td.strings if i != '' and i != '\n']).lstrip('\n').rstrip('\n')
		strTemp = "   " + reportAndHotfixStr
	file.write(strTemp + '\n')
	print strTemp.decode('UTF-8').encode('GB18030')

	file.write('=========================================================' + '\n')

	#try:
	if True:
		query = ''
		query += "insert into newcve values("
		query += (cveNum != None) and ("'" + cveNum.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveENTitle != None) and ("'" + cveENTitle.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cveCNTitle != None) and ("'" + cveCNTitle.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnveMsg != None) and ("'" + cnnveMsg.replace('&nbsp;','').replace('<br/>','').replace('<p>','\n').replace('</p>','').replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (cnnvdNum != None) and ("'" + cnnvdNum.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"

		query += (cvssScore != None) and ("'" + cvssScore.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (secrecyEff != None) and ("'" + secrecyEff.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (completeEff != None) and ("'" + completeEff.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (enableEff != None) and ("'" + enableEff.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (attackComplex != None) and ("'" + attackComplex.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (attackVec != None) and ("'" + attackVec.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (identityCred != None) and ("'" + identityCred.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (CPE != '') and ("'" + CPE.replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (CWE != None) and ("'" + CWE.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (vulType != None) and ("'" + vulType.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (releaseDate != None) and ("'" + releaseDate.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (updateDate != None) and ("'" + updateDate.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (atkUrl != None) and ("'" + atkUrl.group(1).replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "',") or "NULL,"
		query += (BugtraqID != None) and (BugtraqID.group(1) + ",") or "NULL,"
		query += (reportAndHotfixStr != '') and ("'" + reportAndHotfixStr.replace('\\','\\\\').replace('\'','\\\'').replace('\"','\\\"') + "'") or "NULL"

		query += ")"
		#print ("'" + cnnveMsg.group(4).replace('&nbsp;','').replace('<br/>','').replace('<p>','\n').replace('</p>','').replace('\'','\\\'').replace('\"','\\\"') + "',")
		#print query.decode('UTF-8').encode('GB18030')
		cur.execute(query)
		conn.commit()
		print "insert " + cveNum.group(1).decode('UTF-8').encode('GB18030') + " success!"
	# except Exception,e:
	# 	print "insert " + cveNum.group(1).decode('UTF-8').encode('GB18030') + " error!"
	# 	print e
	# 	exit(0)

	print
	print "================================="
	print


#==============扫web=============================================


def crawl_sitemap_web(url,analyse):
	sitemap = download(url)
	if sitemap:
		analyse(sitemap)
		links = re.findall("<loc>(.*?)</loc>",sitemap)
		if links:
			for link in links:
				if url_filter(link):
					html = crawl_sitemap_web(link,analyse)
				else:
					print "pass the url : " + link

def url_filter(url):
	patternUrl = re.compile("http://cve.scap.org.cn/(CVE-\d{4}-\d{4,5}).html")
	try:
		cveId = patternUrl.search(url)
		if cveId:
			cur.execute("select cveid from newcve where cveid = '" + cveId.group(1) +"'")
			ret = cur.fetchall()
			if ret == ():	
				return True
			else:
				return False
		else:
			return True
	except:
		return False	

def cve_get_from_web():
	global cur,conn
	cur,conn = connect()
	crawl_sitemap_web("http://www.scap.org.cn/sitemap.xml",cve_analyse)



#======================扫文档=======================================


def cve_filter(url):
	patternUrl = re.compile("http://cve.scap.org.cn/(CVE-\d{4}-\d{4}).html")
	try:
		cveId = patternUrl.search(url)
		ret = cur.execute("select cveid from newcve where cveid = '" + cveId.group(1) + "'")
		#print "select cveid from newcve where cveid = '" + cveId.group(1) + "'"
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
	file = open('cve.log','w+')
	cve_get_from_web()





# reload(sys)
# sys.setdefaultencoding('gbk')

# a = "请输入cve号(xxxx-xxxx):".decode('UTF-8').encode('GB18030')
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
# 	print("信息不存在".decode('UTF-8').encode('GB18030')
# 	exit(0)

# res2=pattern.search(msg)
# if res2 == None:
# 	print("暂无CNNVE信息".decode('UTF-8').encode('GB18030')
# 	exit(0)

# print("\n" + res2.group(2).decode('UTF-8').encode('GB18030')