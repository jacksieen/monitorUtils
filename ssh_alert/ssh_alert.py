#!/usr/bin/python
# -*- coding:utf-8 -*-
from send_mail import *
from IPy import IP
import string, time, re, os, sys
from datetime import *
import MySQLdb
from settings import *

mail_content = []
wlist = []

msg = 'Apr 28 20:30:18 Athena sshd[31041]: Accepted publickey for root from 222.1.218.3 port 41085 ssh2: RSA 8c:25:06:52:56:3b:73'
class alert:
    def __init__(self, line=msg):
        self.rawmsg = line
        self.ltime = datetime.utcnow()
        self.username = ''
        self.hostname = ''
        self.fromIP = ''
        self.acc = 0
        self.__parse()
        self.alertmsg = ALERT_TEMPLATE % (self.username, self.hostname, self.fromIP, self.ltime.strftime("%Y/%m/%d-%X"))
    
    def __parse(self):
        patt = re.compile(r'\s+')
        log = patt.split(self.rawmsg, 6)
        if log[5] != "Accepted":
            self.acc = 1
        self.hostname = log[3]
        info = log[6]
        self.username = log[6].split(' ')[2]
        ip_expr = r'\d+(.)\d+(.)\d+(.)\d+'
        pattern = re.compile(ip_expr)
        try:
            self.fromIP = pattern.search(log[6]).group()
        except:
            return

def save(list):
    values = []
    getWlist()
    for i in list:
        values.append((i.ltime, i.username, i.hostname, i.fromIP, i.rawmsg))
        if i.acc == 0:
            continue
        elif i.fromIP in wlist:
            continue
        else:
            mail_content.append(i.alertmsg)
    conn = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD)
    conn.select_db(DB_NAME)
    sql = """insert into Log_hostlogin (LoginTime, Username, HostName_id, FromIP, content) values (%s, %s, %s, %s, %s )"""
    cursor = conn.cursor()
    cursor.executemany(sql, values)

def getLogbuf(loglist):
    f = open(LOG_FILE, 'r')
    for line in f:
        loglist.append(line)
    f.close()
    return

def getWlist():
    f = open(WHITE_LIST, 'r')
    for lines in f:
        l = lines.rstrip()
        if l == '':
            continue
        tempip = IP(l)
        for x in tempip:
            wlist.append(x.strNormal())

if __name__ == '__main__':
    logs = []
    list = []
    mail_content = []
    getLogbuf(logs)
    if logs == []:
        exit()
    for l in logs:
        list.append(alert(l))
    save(list)
    if mail_content != []:
        send_mail(mail_to=[ADMIN_EMAIL,], mail_subject=SMTP_SUBJECT, mail_content='\n'.join(mail_content))
    f = open(LOG_FILE, 'w')
    f.write('')
    f.close()

