import boto3
import datetime
import sys
import json

class IamAccess(object):
    
    def __init__(self):
        self.client = boto3.client('iam')

    def get_all_users(self):
        """
            Getting all IAM alse if is trucated
        """
        list_user = []
        response = self.client.list_users()
        for user in response.get('Users'):
            list_user.append(user)
        if response.get('IsTruncated'):
            response = self.client.list_users(Marker=response.get('Marker'))
            #list_user.append(response)
            for user in response.get('Users'):
                list_user.append(user)
        return list_user

    def get_users_activity(self, users, dias):
        dict_inactive_users = {}
        for usuario in users:
            response = self.client.list_access_keys(UserName=usuario.get('UserName'))
            if len(response.get('AccessKeyMetadata')) > 0:
                for access in response.get('AccessKeyMetadata'):
                    access_age = self.client.get_access_key_last_used(AccessKeyId=access.get('AccessKeyId'))                    
                    

                    access_key_usage = access_age.get('AccessKeyLastUsed').get('LastUsedDate')
                    password_last_usage = usuario.get('PasswordLastUsed')

                    #Valida se ja foi utilizada e faz calculo da diferenca do utlimo uso para a data atual
                    if (access_key_usage):
                        access_key_usage = access_age.get('AccessKeyLastUsed').get('LastUsedDate').date()
                        access_key_last_usage = (datetime.datetime.now().date() - access_key_usage).days
                    else:
                        access_key_usage = dias

                    if (password_last_usage):
                        password_last_usage = usuario.get('PasswordLastUsed').date()
                        password_last_usage = (datetime.datetime.now().date() - password_last_usage).days
                    else:
                        password_last_usage = dias                    

                    if (int(access_key_last_usage) >= dias and int(password_last_usage) >= dias):
                        dict_inactive_users[usuario.get('UserName')] = {'ultimo_acesso':access_key_last_usage}
        
            else:
                password_last_usage = usuario.get('PasswordLastUsed')
                if (password_last_usage):
                        password_last_usage = usuario.get('PasswordLastUsed').date()
                        password_last_usage = (datetime.datetime.now().date() - password_last_usage).days
                else:
                    password_last_usage = dias 
                
                if (int(password_last_usage) >= dias):
                    dict_inactive_users[usuario.get('UserName')] = {'ultimo_acesso':password_last_usage}
                #print()
        return dict_inactive_users

days_to_check = sys.argv[1]

iam = IamAccess()
users = iam.get_all_users()
print(json.dumps(iam.get_users_activity(users, int(days_to_check))))
