import mysql.connector,hashlib,secrets,base64
from cryptography.fernet import Fernet
id=mysql.connector.connect(host="localhost",user="root",passwd="root")
idc=id.cursor()
idc.execute("Show databases")
rec=idc.fetchall()
for i in rec:
    if i[0] == "mpd":
        break
else:
    idc.execute("Create database MPD")
    idc.execute("Use MPD")
    idc.execute("Create table MasterPassword(Username varchar(64) Primary key,Salt varchar(32) Not Null,Password varchar(64) Not Null)")
    idc.execute("Create table Keystore(Username varchar(64) Primary key,Keystore varchar(256) Not Null)")
    idc.execute("Create database Userbase")
    idc.execute("Use Userbase")
    id.commit()
    id.close()
Md=mysql.connector.connect(host="localhost",user="root",passwd="root",database="MPD")
Mc=Md.cursor()
Ud=mysql.connector.connect(host="localhost",user="root",passwd="root",database="Userbase")
Uc=Ud.cursor()

def tabinp(u,s,p):
    Mc.execute("insert into MasterPassword values('{0}','{1}','{2}')".format(u,s,p))
    print("Records inserted Successfuly \n No: of records =",Mc.rowcount)
    Md.commit()

def tabpri(dbcur,tbname):
    dbcur.execute("Select * from {}".format(tbname))
    rec=dbcur.fetchall()
    rc=dbcur.rowcount
    if rc != 0:
        print(rec)
        print("No: of records =",rc)
    else:
        print("No records found")

#Registration
def Reg():
    while True:
        U=input("Enter Username: ")
        P=input("Enter Password: ")
        PC=input("Confirm Password: ")
        if P == PC:
            print("Success")
            S=secrets.token_bytes(16)
            HexS=S.hex()
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32).hex()
            tabinp(U,HexS,HashP)
            Uc.execute("Create table {}(S_no int(50) Primary Key,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)".format(U))
            S=secrets.token_bytes(16)
            key=base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32)).hex()
            Mc.execute("insert into Keystore values('{}','{}')".format(U,key))
            break
        else:
            print("| Password confirm mismatch | \n\t Try Again")
            continue

#User Login
def Login():
    while True:
        U=input("Enter Username: ")
        P=input("Enter Password: ")
        Mc.execute("Select * from MasterPassword where username = '{}'".format(U))
        rec=Mc.fetchone()
        if rec != None:
            S=rec[1]
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),bytes.fromhex(S),10000,32)
            if secrets.compare_digest(HashP,bytes.fromhex(rec[2])):
                print("Succesful Login\n")
                Mc.execute("Select Keystore from Keystore where Username = '{}'".format(U))
                key=Mc.fetchone()[0]
                F=Fernet(bytes.fromhex(key))
                while True:
                    Uc.execute("Select * from {} order by S_no".format(U))
                    rec=Uc.fetchall()
                    if rec == []:
                        print("| No Passwords Stored Yet |")
                        Sn=1
                    else:
                        print("S_no \t Domain \t Username \t Password")
                        for x in rec:
                            print(x[0],"\t",F.decrypt(bytes.fromhex(x[1])).decode(),"\t\t",F.decrypt(bytes.fromhex(x[2])).decode(),"\t\t",F.decrypt(bytes.fromhex(x[3])).decode())
                            Sn=x[0]+1
                    print("\n Pick a choice \n1: Add record\n2: Delete record\n3: Change record\n4 Autofill function\n5: Quit\n[2,3,4 WIP do not select]")
                    ch=int(input("Enter your choice: "))
                    if ch == 1:
                        Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                        Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()
                        Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                        Uc.execute("insert into {0} values({1},'{2}','{3}','{4}')".format(U,Sn,Domain,Usi,Pai))
                        print("Successfuly inserted record\n")
                        Ud.commit()
                    elif ch != 1 and ch != 5:
                        print(" WIP !!! ")
                    elif ch == 5:
                        break
                break
            else:
                print("Wrong Password")
                continue
        else:
            print("Wrong Username")
            continue

Ch=int(input("Login or Register[0/1]: "))
if Ch == 0:
    Login()
else:
    Reg()
    Login()

Md.close()
Ud.close()