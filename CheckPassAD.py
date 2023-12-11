from ldap3 import Connection, Server, Tls, ALL_ATTRIBUTES
from datetime import timedelta, datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd
import time

while True:
    server = Server('domain server', use_ssl=True, get_info=ALL_ATTRIBUTES)
    conn = Connection(server, user='username', password='pass')

    floader_ad = ['Users', 'Shared', 'Prod']#List of scan folders
    email_recipient = ['user1@mail.com', 'user2@mail.com']#Mailboxes to whom we send the notification
   
    credentials_uid = {}#Keys with meanings. To get email and password expiration date

    for scan_directory in floader_ad:
        if conn.bind():
            conn.search('ou={},ou=Users,ou=Ru,dc=domain,dc=net'.format(scan_directory), '(&(objectClass=user))', attributes=['sAMAccountName','name','mail','pwdMustChange','userAccountControl', 'pwdLastSet', 'passwordExpirationTime','msDS-UserPasswordExpiryTimeComputed'])
            response = conn.response

            for entry in response:
                sAMAccountName = entry['attributes']['sAMAccountName']
                user_account_control = entry['attributes']['userAccountControl']
                pwdLastSet = entry['attributes']['pwdLastSet']
                pwd_must_change = entry['attributes']['pwdMustChange']
                pwdExpiryTime = entry['attributes']['msDS-UserPasswordExpiryTimeComputed']
                email = entry['attributes']['mail']
                name = entry['attributes']['name']
                is_disabled = bool(int(user_account_control[0]) & 2)#Receiving a response about the checkbox "Requires password change at next login" checked
                if is_disabled:
                    pass
                elif pwd_must_change:
                    pass
                else:
                    try:
                        #Convection to date
                        try:
                            pwdExpiryTime = int(pwdExpiryTime[0])/10000000 - 11644473600
                            target_date = datetime.fromtimestamp(pwdExpiryTime)
                            pwdLastSet = int(pwdLastSet[0])/10000000 - 11644473600
                            pwdLastSet = datetime.fromtimestamp(pwdLastSet).strftime("%d.%m.%Y %H:%M:%S")
                            pwdExpiryTime = datetime.fromtimestamp(pwdExpiryTime).strftime("%d.%m.%Y %H:%M:%S")
                        except:
                            pwdLastSet = int(pwdLastSet[0])/10000000 - 11644473600
                            pwdLastSet = datetime.fromtimestamp(pwdLastSet)
                            pwdExpiryTime = pwdLastSet + timedelta(3*365/12)
                            target_date = pwdExpiryTime
                            pwdLastSet = pwdLastSet.strftime("%d.%m.%Y %H:%M:%S")
                            pwdExpiryTime = pwdExpiryTime.strftime("%d.%m.%Y %H:%M:%S")
                        
                        current_date = datetime.now()    
                        print(f'Пользователь: {sAMAccountName[0]}')
                        print(f'Email: {email[0]}')
                        print(f'Name: {name[0]}')
                        print(f'Дата последнего изменения пароля: {pwdLastSet}')
                        print(f'Дата истечения срока действия пароля: {pwdExpiryTime}')
                        #Key generation
                        if target_date < current_date or current_date - target_date == timedelta(days=3):
                                pass
                                key = f'{sAMAccountName[0]}'
                                if email[0] == '' or email[0] == None:
                                    pass
                                else:
                                    credentials_uid[email[0]] = pwdExpiryTime
                    except:
                        pass
            conn.unbind()
        else:
            print('Не удалось подключиться к серверу Active Directory.')
    credentials_uid = str(credentials_uid).replace('{', ' ')
    credentials_uid = str(credentials_uid).replace('}', '')
    credentials_uid = str(credentials_uid).replace("'", '')
    credentials_uid = str(credentials_uid).replace(',', '\n')
    if credentials_uid != [] or credentials_uid != {} or credentials_uid != None or credentials_uid != '':
        
        for send_mail in email_recipient:
            sender_email = "support@mail.com"
            sender_password = "password"

            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = send_mail
            message["Subject"] = "Истечение действия пароля"
                        
            body = "Вам направлено уведомление, об истечении срока действия пароля служебных учетных записей:\n\n{}".format(credentials_uid)
            message.attach(MIMEText(body, "plain"))
            with smtplib.SMTP("smtp.server.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, send_mail, message.as_string())
    time.sleep(60*60*24)