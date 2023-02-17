import os
import random
import uuid
import smtplib
from email.mime.text import MIMEText
import yaml

def cRandPwd():
    z = ''
    for x in range(random.randrange(10, 20)):
        z += random.choice([
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
            'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '@', '#',
            '$', '%', '^', '&', '*'
        ])
    return z

def CreateUUID():
    return uuid.uuid4().hex

def sendEmail(to, content, title):
  msg = MIMEText(content, 'html')
  msg['Subject'] = title
  port = 587
  email = os.environ['email']
  password = os.environ['password']

  with smtplib.SMTP('smtp-mail.outlook.com', port) as server:
      server.starttls()
      server.login(email, password)
      server.sendmail(email, to, msg.as_string())

def GetSettings():
  with open('settings.yaml', 'r') as file:
    return yaml.safe_load(file)

'''
def ELOCALC(p0: Player, p1: Player, win=0.5):
  "0.5: Draw | 1: p0Win | 0: p1Win"
  diff = (p1.elo-p0.elo)/400
  expected_score = 1/(1+(10**diff))
  p0e = 30*(1-win-expected_score)
  p1e = 30*(win-expected_score)
  p0.elo += p0e
  p1.elo += p1e
'''