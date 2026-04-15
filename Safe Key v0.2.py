#Initialisation / Pre-Setups
import sqlite3,hashlib,secrets,base64,pickle,os
from cryptography.fernet import Fernet
from prettytable import PrettyTable

#File/Database integrity verification and Database intialisation
if not os.path.exists("Psuedo.db"):    
    print("dbFile Does not Exist\nCheck for possible alteration to Psuedo.db")
    In=input("Create a new Database\n| YES  or Quit |\n\t")
    if In in ("YES","yes","Yes","Y","y"):
        if os.path.exists("Hex.dat"):
            os.remove("Hex.dat")
        if os.path.exists("Pepper.dat"):
            os.remove("Pepper.dat")
        Db=sqlite3.connect("Psuedo.db")
        Dc=Db.cursor()
        Dc.execute("Create table Seneor (Password Varchar(256) Primary key)")
        Dc.execute("Create table seneorita (S_no integer Primary Key Autoincrement,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)")
        Db.commit()
    elif In in ("QUIT","quit","q","Q"):
        quit() 
    else:
        print(" | Invalid Input | \n     Try Again")
else:
    print("|DbFile Found|proceedig to digest Hash")
    f1=open("Psuedo.db","rb")
    NewHex1=hashlib.file_digest(f1,"sha256").hexdigest()
    NewHex=NewHex1.encode()
    f1.close()
    if not os.path.exists("Hex.dat"):
        print("HexFile Does not Exist\nCheck for possible alteration to Hex.dat")
        In=input("Create a new Database\n| YES  or Quit |\n\t")
        if In in ("YES","yes","Yes","Y","y"):
            os.remove("Psuedo.db")
            if os.path.exists("Pepper.dat"):
                os.remove("Pepper.dat")
            Db=sqlite3.connect("Psuedo.db")
            Dc=Db.cursor()
            Dc.execute("Create table Seneor (Password Varchar(256) Primary key)")
            Dc.execute("Create table Seneorita (S_no integer Primary Key Autoincrement,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)")
            Db.commit()
        elif In in ("QUIT","quit","q","Q"):
            quit() 
        else:
            print(" | Invalid Input | \n     Try Again")
    else:
        print("|HexFile Found|proceedig to compare Hash")
        f2=open("Hex.dat","rb")
        X=pickle.load(f2).encode()
        f2.close()
        if secrets.compare_digest(X,NewHex):
            print("| Hash verification Success |")
            if not os.path.exists("Pepper.dat"):
                print("| SaltHashFile Not Found |\n |Recent Account Reset| /possible alteration to Pepper.dat")
                In=input("Create a new Database\n| YES  or Quit |\n\t")
                if In in ("YES","yes","Yes","Y","y"):
                    os.remove("Psuedo.db")
                    os.remove("Hex.dat")
                    Db=sqlite3.connect("Psuedo.db")
                    Dc=Db.cursor()
                    Dc.execute("Create table Seneor (Password Varchar(256) Primary key)")
                    Dc.execute("Create table Seneorita (S_no integer Primary Key Autoincrement,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)")
                    Db.commit()
                elif In in ("QUIT","quit","q","Q"):
                    quit() 
                else:
                    print(" | Invalid Input | \n     Try Again")
            else:
                Db=sqlite3.connect("Psuedo.db")
                Dc=Db.cursor()
        else:
            print("| Hash Verification Failed |\nDatabase Compromised")
            In=input("Create a new Database\n| YES  or Quit |\n\t")
            if In in ("YES","yes","Yes","Y","y"):
                os.remove("Psuedo.db")
                os.remove("Hex.dat")
                if os.path.exists("Pepper.dat"):
                    os.remove("Pepper.dat")
                Db=sqlite3.connect("Psuedo.db")
                Dc=Db.cursor()
                Dc.execute("Create table Seneor (Password Varchar(256) Primary key)")
                Dc.execute("Create table Seneorita (S_no integer Primary Key Autoincrement,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)")
                Db.commit()
            elif In in ("QUIT","quit","q","Q"):
                quit() 
            else:
                print(" | Invalid Input | \n     Try Again")

#Registration
def Reg():
    while True:
        P=input("Enter Password: ")
        PC=input("Confirm Password: ")
        if P == PC: #Password Match-up confirmation
            S=secrets.token_bytes(16) #Generating random bytes for salt generation
            HexS=S.hex()
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32)  #Password Hashing
            HexHashP=HashP.hex()
            f3=open("Pepper.dat","wb")
            pickle.dump(HexS,f3)
            f3.close()
            Dc.execute("insert into Seneor values(?)",(HexHashP,)) #Inserting Hashed Password to database
            print("| Registration Success |")
            print("Records inserted succesfuly\n \t| Login |")
            Db.commit()
            break
        else:
            print("| Password confirm mismatch | \n\t Try Again")
            continue
    
#User Login/Main Loop
def Login():
    while True:
        P=input("Enter Password: ")
        PC=input("Confirm Password: ")
        if P == PC: #Password Match-up confirmation
            Dc.execute("Select Password from Seneor")
            Px=Dc.fetchone()[0]
            f3=open("Pepper.dat","rb")
            S=pickle.load(f3)
            f3.close()
            HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),bytes.fromhex(S),10000,32) #Hashing inputed Password
            if secrets.compare_digest(HashP.hex(),Px): #Comapring both passwords 
                print("  | Succesful Login |\n")
                key=base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',P.encode(),bytes.fromhex(S),10000,32)) #Key Generation
                F=Fernet(key) #Encryption Object
                while True:
                    try:
                        Dc.execute("Select * from seneorita order by S_no")
                        rec=Dc.fetchall()
                        print("|------------------------------------------------------------------------------|\n")
                        if rec == []:
                            print("\t\t\t| No Passwords Stored Yet |")
                            Sn=1
                        else:
                            table=PrettyTable()
                            table.field_names=["S_no","Domain","Username","Password"]
                            for x in rec:
                                table.add_row([x[0],F.decrypt(bytes.fromhex(x[1])).decode(),F.decrypt(bytes.fromhex(x[2])).decode(),F.decrypt(bytes.fromhex(x[3])).decode()])  #Decrypting / Displaying Records
                                Sn=x[0]+1
                            print(table)
                        print("\n|------------------------------------------------------------------------------|")
                        print("\n| Pick a choice |\n1: Add record\n2: Delete record\n3: Change record\n4: Search record\n5: Additional Settings\n6: Logout\n7: Quit")
                        ch=int(input("Enter your choice: "))
                        if ch == 1:
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()      #Encrypting and storing Information
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Dc.execute("insert into seneorita values(?,?,?,?)",(Sn,Domain,Usi,Pai))
                            print("Successfuly inserted record\n")
                            Db.commit()
                        elif ch == 2:
                            n=int(input("Input the Sn. of the record you wish to delete: "))      #Deleting records
                            Dc.execute("Delete from seneorita where S_no = ?",(n,))
                            print("Record succesfuly deleted\n")
                            Db.commit()
                        elif ch == 3:
                            Sn=int(input("Input the Sn. of the record you wish to change: "))     #Altering Records
                            print("Please re-enter the following information\n")
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Dc.execute("update Seneorita set Domain =?,Username=?,Password=? where S_no = ?",(Domain,Usi,Pai,Sn))
                            print("Successfuly changed record\n")
                            Db.commit()
                        elif ch == 4:
                            print("| Search Record |")
                            print("1: Search by Domain\n2: Search by Username\n3: Go Back")
                            s=int(input("Enter your choice: "))
                            if s == 1:
                                shx=input("Enter the Domain to search: ")
                                table2=table.get_string(row_filter=lambda row: row[1]==shx)
                                print("|------------------------------------------------------------------------------|\n")
                                if len(table2) == 159:
                                    print("\t\t\t| No Such Records found |")
                                else:
                                    print(table2)
                                print("\n|------------------------------------------------------------------------------|\n")
                                input("Continue: ")
                            elif s == 2:
                                shx=input("Enter the Username to search: ")
                                table2=table.get_string(row_filter=lambda row: row[2]==shx)
                                print("|------------------------------------------------------------------------------|\n")
                                if len(table2) == 159:
                                    print("\t\t\t| No Such Records found |")
                                else:
                                    print(table2)
                                print("\n|------------------------------------------------------------------------------|\n")
                                input("Continue: ")
                            elif s == 3:
                                pass
                            else:
                                print(" | Invalid Input | \n     Try Again")   
                        elif ch == 5:
                            print("| Adittional Settings |")
                            print("1: Change Master Password\n2: Delete Account\n3: Go Back")
                            s=int(input("Enter your choice: "))
                            if s == 1:
                                while True:
                                    P=input("Enter New Password: ")
                                    PC=input("Confirm Password: ")
                                    if P == PC:
                                        S=secrets.token_bytes(16) #Generating random bytes for salt generation
                                        HexS=S.hex()
                                        HashP=hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32)  #Password Hashing
                                        HexHashP=HashP.hex()
                                        f3=open("Pepper.dat","wb")
                                        pickle.dump(HexS,f3)
                                        f3.close()
                                        Dc.execute("Delete from Seneor")
                                        Dc.execute("insert into Seneor values(?)",(HexHashP,)) #Inserting Hashed Password to database
                                        Db.commit()
                                        print("| Successfuly Altered Password |\n \tLogging Out")
                                        Dc.execute("Select * from seneorita order by S_no")
                                        rec=Dc.fetchall()
                                        LX=[]
                                        LN=[]
                                        if rec != []:
                                            for x in rec:
                                                LX.append([x[0],F.decrypt(bytes.fromhex(x[1])),F.decrypt(bytes.fromhex(x[2])),F.decrypt(bytes.fromhex(x[3]))])  #Decrypting Records
                                            key=base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',P.encode(),S,10000,32)) #Key Generation
                                            F=Fernet(key) #Encryption Object
                                            for x in LX:
                                                LN.append([x[0],F.encrypt(x[1]).hex(),F.encrypt(x[2]).hex(),F.encrypt(x[3]).hex()])
                                            Dc.execute("Delete from Seneorita")
                                            for x in LN:
                                                Dc.execute("insert into seneorita values(?,?,?,?)",(x[0],x[1],x[2],x[3]))
                                            Db.commit()
                                        break                                  
                                    else:
                                        print("| Password confirm mismatch | \n\t Try Again")
                                        continue
                                break
                            elif s == 2:
                                Dc.execute("Drop table seneorita")
                                Dc.execute("Drop table Seneor")
                                os.remove("Pepper.dat")
                                Db.commit()
                                print("| Account Deleted Successfuly |\n \t| Quitting |")
                                return True
                            elif s == 3:
                                pass
                            else:
                                print(" | Invalid Input | \n     Try Again")
                                
                        elif ch == 6:
                            print(" | Successfuly Logged out |")
                            break
                        elif ch == 7:
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
            print("| Password confirm mismatch | \n\t Try Again")
            continue

 # Program Loop
while True:
    if os.path.exists("Pepper.dat"):
        if Login():
            break
        else:
            continue
    else:
        Reg()
        if Login():
            break
        else:
            continue
#Deinitialisation
Dc.close()    
Db.close()
f2=open("Hex.dat","wb")
f4=open("Psuedo.db","rb")
Hexhash=hashlib.file_digest(f4,"sha256").hexdigest()
pickle.dump(Hexhash,f2)
f4.close()
f2.close()
quit()
