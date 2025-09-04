#Initialisation / Pre-Setups
import mysql.connector,hashlib,secrets,base64
from cryptography.fernet import Fernet
id=mysql.connector.connect(host="localhost",user="root",passwd="root")

#Check for existing databases
idc=id.cursor()
idc.execute("Show databases")
rec=idc.fetchall()
for i in rec: 
    if i[0] == "mpd":
        break
else:      #if database does not exist
    idc.execute("Create database MPD")             #Creating required databases
    idc.execute("Use MPD")
    idc.execute("Create table MasterPassword(Username varchar(64) Primary key,Salt varchar(32) Not Null,Password varchar(64) Not Null)")
    idc.execute("Create table Keystore(Username varchar(64) Primary key,Keystore varchar(256) Not Null)")
    try:
        idc.execute("Create database Userbase")
        id.commit()
    except mysql.connector.Error:  #Sql Query Error Handling
        idc.execute("Drop database Userbase")
        idc.execute("Create database Userbase")
        id.commit()
for i in rec: 
    if i[0] == "userbase":
        break
else:
    idc.execute("Create database Userbase")
    id.commit()
id.close()

#SQL Connection objects    
Md=mysql.connector.connect(host="localhost",user="root",passwd="root",database="MPD")
Mc=Md.cursor()
Ud=mysql.connector.connect(host="localhost",user="root",passwd="root",database="Userbase")
Uc=Ud.cursor()

#Registration
def Reg():
    while True:
        try:
            U=input("Enter Username: ")
            P=input("Enter Password: ")
            PC=input("Confirm Password: ")
            if P == PC: #Password Match-up confirmation
                S=secrets.token_bytes(16) #Generating random bytes for salt generation
                HexS=S.hex()
                HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32).hex()  #Password Hashing
                Mc.execute("insert into MasterPassword values('{0}','{1}','{2}')".format(U,HexS,HashP)) #Inserting Hashed Password to database
                Uc.execute("Create table `{}`(S_no int(50) Primary Key,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)".format(U)) #Creating User-table
                S=secrets.token_bytes(16) 
                key=base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32)).hex() #Key Generation
                Mc.execute("insert into Keystore values('{}','{}')".format(U,key)) #Insering Keys to databse
                print("| Registration Success |")
                print("Records inserted succesfuly\n \t| Login |")
                Md.commit()
                break
            else:
                print("| Password confirm mismatch | \n\t Try Again")
                continue
        except mysql.connector.Error: 
            print("! Registration Unsuccessful !\n ! Username Already Exists !")
            continue

#User Login/Main Loop
def Login():
    while True:
        U=input("Enter Username: ")
        P=input("Enter Password: ")
        Mc.execute("Select * from MasterPassword where username = '{}'".format(U))
        rec=Mc.fetchone()
        if rec != None:
            S=rec[1]
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),bytes.fromhex(S),10000,32) #Hashing inputed Password
            if secrets.compare_digest(HashP,bytes.fromhex(rec[2])): #Comapring both passwords 
                print("  | Succesful Login |\n")
                Mc.execute("Select Keystore from Keystore where Username = '{}'".format(U)) #Fetching Key from database
                key=Mc.fetchone()[0]
                F=Fernet(bytes.fromhex(key)) #Encryption Object
                while True:
                    try:
                        Uc.execute("Select * from `{}` order by S_no".format(U))
                        rec=Uc.fetchall()
                        print("|----------------------------------------------------------------------------------|")
                        if rec == []:
                            print("\t\t\t| No Passwords Stored Yet |")
                            Sn=1
                        else:
                            print("|S_no |\t\t Domain |\t\t Username |\t\t Password |")
                            for x in rec:
                                print("",x[0],"\t\t",F.decrypt(bytes.fromhex(x[1])).decode(),"\t\t",F.decrypt(bytes.fromhex(x[2])).decode(),"\t",F.decrypt(bytes.fromhex(x[3])).decode())  #Decrypting / Displaying Records
                                Sn=x[0]+1
                        print("|----------------------------------------------------------------------------------|")
                        print("\n| Pick a choice |\n1: Add record\n2: Delete record\n3: Change record\n4: Additional Settings\n5: Logout\n6: Quit")
                        ch=int(input("Enter your choice: "))
                        if ch == 1:
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()      #Encrypting and storing Information
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Uc.execute("insert into `{0}` values({1},'{2}','{3}','{4}')".format(U,Sn,Domain,Usi,Pai))
                            print("Successfuly inserted record\n")
                            Ud.commit()
                        elif ch == 2:
                            n=int(input("Input the Sn. of the record you wish to delete: "))      #Deleting records
                            Uc.execute("Delete from `{0}` where S_no = {1}".format(U,n))
                            print("Record succesfuly deleted\n")
                            Ud.commit()
                        elif ch == 3:
                            Sn=int(input("Input the Sn. of the record you wish to change: "))     #Altering Records
                            print("Please re-enter the following information\n")
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Uc.execute("update `{0}` set Domain ='{1}',Username='{2}',Password='{3}' where S_no = {4}".format(U,Domain,Usi,Pai,Sn))
                            print("Successfuly changed record\n")
                            Ud.commit()
                        elif ch == 4:
                            print("| Adittional Settings |")
                            print("1: Change Master Password\n2: Delete Account\n3: Go Back")
                            s=int(input("Enter your choice: "))
                            if s == 1:
                                while True:
                                    P=input("Enter New Password: ")
                                    PC=input("Confirm Password: ")
                                    if P == PC:
                                        S=secrets.token_bytes(16)
                                        HexS=S.hex()
                                        HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32).hex()
                                        Mc.execute("Update MasterPassword Set Salt = '{0}',Password = '{1}' where Username = '{2}'".format(HexS,HashP,U))
                                        Md.commit()
                                        print("| Successfuly Altered Password |\n \tLogging Out")
                                        break                                  
                                    else:
                                        print("| Password confirm mismatch | \n\t Try Again")
                                        continue
                                break
                            elif s == 2:
                                Uc.execute("Drop table `{0}`".format(U))
                                Mc.execute("Delete from Masterpassword where username ='{0}'".format(U))
                                Mc.execute("Delete from keystore where username = '{0}'".format(U))
                                Ud.commit()
                                Md.commit()
                                print("| Account Deleted Successfuly |\n \tLogging Out")
                                break
                            elif s == 3:
                                pass
                            else:
                                print(" | Invalid Input | \n     Try Again")
                                
                        elif ch == 5:
                            print(" | Successfuly Logged out |")
                            break
                        elif ch == 6:
                            print(" | Quitting |")
                            return True
                        else:
                            print(" | Invalid Input | \n     Try Again")
                    except ValueError: # Input Error Handling
                        print(" | Invalid Input | \n ! Enter Numbers !")
                        continue
                break
            else:
                print("Wrong Password")
                continue
        else:
            print("Wrong Username")
            continue

 # Program Loop
while True:
    try:
        Ch=int(input("Login  [0]  Register  [1]  Quit  [2]\n\tPick your choice: "))
        if Ch == 0:
            Q=Login()
            if Q == True:
                break
        elif Ch == 1:
            Reg()
            Q=Login()
            if Q == True:
                break
        elif Ch == 2:
            print(" | Quitting |")
            break
        else:
            print(" | Invalid Input | \n     Try Again")
    except ValueError:
        print(" | Invalid Input | \n ! Enter Numbers !")
        continue
#Deinitialisation    
Md.close()
Ud.close()
