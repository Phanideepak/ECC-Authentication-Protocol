from tinyec import registry
import secrets
from flask import Flask, render_template
import mysql.connector
#from django.shortcuts import render
curve = registry.get_curve('secp192r1')
curve1=registry.get_curve('secp192r1')

print(curve.field.n)
#generating private key for server
xs = secrets.randbelow(curve.field.n)
tag_identifier=secrets.randbelow((curve.field.n))
P=curve.g
P1=curve1.g
print(P.x)
print(P.y)
print(f"server_key={xs}    ")
#generating public key of server...
Ps = xs * curve.g
print("private key:", xs)
print("public key:", Ps)
K=secrets.randbelow(curve.field.n)
IDS=secrets.randbelow(curve.field.n)
#xt=curve.g
xt=tag_identifier*P1

print(xt.x)
print(xt.y)
# data base handler snippet.....
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="Alekya@736",
    database="mydatabase1",
auth_plugin="mysql_native_password"
)

mycursor = mydb.cursor()
sql=f"insert into tag_table (IDS,K,xtx,xty,Psx,Psy) values({IDS},{K},{xt.x},{xt.y},{Ps.x},{Ps.y});"
#sql1="select * from tag_table;"
mycursor.execute(sql)
mydb.commit()
print("1 record inserted")


#sql="select * from tag_table;"
#mycursor.execute(sql);
#result=mycursor.fetchall()
#render_template('tag.html',result)


