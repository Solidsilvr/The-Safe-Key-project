import mysql.connector,hashlib,secrets
db=mysql.connector.connect(host="localhost",user="root",passwd="root",database="Prototest")
sc=db.cursor()

def tabinp(u,s,p):
    sc.execute("insert into Protopassword values('{0}','{1}','{2}')".format(u,s,p))
    print("Records inserted Successfuly \n No: of records =",sc.rowcount)

def tabpri():
    sc.execute("Select * from ProtoPassword")
    rec=sc.fetchall()
    rc=sc.rowcount
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
            break
        else:
            print("| Password confirm mismatch | \n\t Try Again")
            continue

#User Login
def Login():
    while True:
        U=input("Enter Username: ")
        P=input("Enter Password: ")
        sc.execute("Select * from ProtoPassword where username = '{}'".format(U))
        rec=sc.fetchone()
        if rec != None:
            S=rec[1]
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),bytes.fromhex(S),10000,32)
            if secrets.compare_digest(HashP,bytes.fromhex(rec[2])):
                print("Succesful Login")
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

db.commit()
db.close()