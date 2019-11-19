from PIL import Image, ImageTk
from msilib.schema import ListBox
import time
from tkinter import *
from tinyec import registry
import secrets
import os
import cmath
import mysql.connector
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="Alekya@736",
    database="mydatabase1",
auth_plugin="mysql_native_password"
)

mycursor = mydb.cursor()
curve=registry.get_curve('secp192r1');

p=curve.g
#server extracting r1 from zn*
r1=secrets.randbelow(curve.field.n)
#print(f"r1: {r1}")
R1=r1*p
#tag extracting r2 from zn* and calculating R2
r2=secrets.randbelow(curve.field.n)
R2=r2*p
#handling GUI of the server
main=Tk()
main.geometry("500x500")
main.title("My Server")
img=ImageTk.PhotoImage(file="logo2.jpg")
photoL=Label(main,image=img)
photoL.pack(pady=5)
frame=Frame(main)
sc=Scrollbar(frame)
msgs=Listbox(frame,width=100,height=10,yscrollcommand=sc.set)
sc.pack(side=RIGHT,fill=Y)
msgs.pack(side=LEFT,fill=X,pady=10)
frame.pack()
# creating the text field...
textF=Entry(main,font=("Verdana",20))
textF.pack(fill=X,pady=10)
textF1=Entry(main,font=("Verdana",20))
textF1.pack(fill=X,pady=10)
# tag sends {R2,IDS} to the server..
def search_tag():
     query = textF.get()
     query1=textF1.get()
     label = str(query)
     password=str(query1)
     if  label=='':
         print("User label can't be blank")
         exit()
     if password=='':
         print("Password shouldn't be blank")
         exit()
     sql1=f"select IDS,count(*) from tag_table where IDS={password};"
     mycursor.execute(sql1)
     myresult1=mycursor.fetchall()
     for x in myresult1:
         if x[1]==0:
             print("Invalid tag pseudonym or already used pseudonymn")
             time.sleep(3)
             exit()
     sql=f"select IDS,count(*) from tag_table where tag_label={label};"
     mycursor.execute(sql)
     myresult=mycursor.fetchall()
     #print("TAG NOT REGISTERED....")
     for x in myresult:
         if x[1]==0:
             print("TAG NOT REGISTERED....")
             msgs.insert(END,"TAG NOT REGISTERED....")
             exit()

         IDS=x[0]
         print("Tag found")
         msgs.insert(END,"Tag found")
     #server first computation
     sql1=f"select * from tag_table where tag_label={label};"
     mycursor.execute(sql1)
     myresult=mycursor.fetchall()
     sql2=f"select * from server_table;"
     mycursor.execute(sql2)
     myresult1=mycursor.fetchall()
     for x in myresult1:
         xs=x[0]

     xt=curve.g
     Ps=curve.g
     for x in myresult:
         K=x[2]
         Ps.x=x[5]
         Ps.y=x[6]
         xt.x=x[3]
         xt.x=int(xt.x)
         xt.y=x[4]
         xt.y=int(xt.y)
     TKs1=r1*int(K)*R2
     TKs2=int(xs)*int(K)*R2
     Auths=curve.g
     Auths.x=TKs1.x ^ TKs2.x ^ xt.x
     Auths.y=TKs1.y ^ TKs2.y ^ xt.y
     print(Auths)
     # server sends {Auths to tag}
     #tag computation
     TKt1=r2*int(K)*R1
     TKt2=r2*int(K)*Ps
     # label1 ------ xt'

     label1 = p
     label1.x = TKt1.x ^ TKt2.x ^ Auths.x
     label1.y = TKt1.y ^ TKt2.y ^ Auths.y
     if label1.x==xt.x and label1.y==xt.y:
         print("xt' matched with xt value of given Identifier")
   #here label1 refer to the xt'... By
    # x(RHS)=TKt1.x ^ TKt2.x ^ Auths.x matches with the xt values of given tag values
    #y(RHS)= TKt1.y ^ TKt2.y ^ Auths.y matches with the xt values of given tag values
     if label1.x == xt.x and label1.y == xt.y:
         print("Server Authentication success")
         msgs.insert(END,"Server Authentication success")
         #after server authentication, matched tag computes Autht
         Autht=curve.g
         Autht.x=label1.x ^ 2* TKt1.x ^2* TKt2.x
         Autht.y=label1.y ^ 2* TKt1.y ^ 2* TKt2.y
         #server final computation
         rhs=curve.g
         rhs.x=xt.x ^ 2* TKs1.x ^ 2* TKs2.x
         rhs.y = xt.y ^ 2 * TKs1.y ^ 2 * TKs2.y
         if rhs==Autht:
             print("Tag is authenticated")

             # updating the values to prevent desynchronous attack...
             sql = f"select IDS,K from tag_table where tag_label={label};"
             mycursor.execute(sql)
             myresult = mycursor.fetchall()
             for x in myresult:
                 IDS_OLD = x[0]
                 K_OLD = x[1]
             IDS_NEW = TKt1.x ^ int(IDS_OLD) ^ int(K_OLD)
             K_NEW = TKt2.x ^ 2 * int(K_OLD)
             msgs.insert(END, "Before Updating")
             msgs.insert(END, f"K_OLD:{K_OLD}  ")
             msgs.insert(END, f"IDS:{IDS_OLD} ")
             msgs.insert(END, "After Updating")
             msgs.insert(END, f"K_NEW:{K_NEW} ")
             msgs.insert(END, f"IDS:{IDS_NEW}")
             sql5=f"update tag_table set IDS={int(IDS_NEW)}  where tag_label={label}"
             mycursor.execute(sql5)
             mydb.commit()
             sql6 = f"update tag_table set K={int(K_NEW)}  where tag_label={label}"
             mycursor.execute(sql6)
             #myresult=mycursor.fetchall()
             #and K={int(K_NEW)}
             mydb.commit()
             print("Updated Values got inserted")
         else:
             print("Tag Authentication failed")

     else:
         print("Session Termination: Server not authenticated")
         msgs.insert(END,"Session Termination: Server not authenticated")

btn=Button(main,text="SEARCH_FOR_TAG",font=("Verdana,20"),command=search_tag)
btn.pack()
def enter_function(event):
    btn.invoke()
main.bind('<Return>',enter_function)
main.mainloop()