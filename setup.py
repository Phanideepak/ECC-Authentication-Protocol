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
print(f"x-cordinate: of Point p {P.x}")
print(f"y-cordinate: of point P: {P.y}")
print(f"server_key={xs}    ")
#generating public key of server...
Ps = xs * curve.g
print("private key:", xs)
print("public key:", Ps)
K=secrets.randbelow(curve.field.n)
print(f"Shared Key between server and tag(created): {K}")

IDS=secrets.randbelow(curve.field.n)
print(f"Unique Psuedonym: {IDS}")
#xt=curve.g
xt=tag_identifier*P1

print(f"x cordinate of identifier of a tag: {xt.x}")
print(f"y cordinate of identifier of a tag: {xt.y}")
# data base handler snippet.....
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="Alekya@736",
    database="mydatabase1",
auth_plugin="mysql_native_password"
)

mycursor = mydb.cursor()
sql=f"insert into server_tag (IDS,K,xtx,xty) values({IDS},{K},{xt.x},{xt.y});"
#sql1="select * from tag_table;"
mycursor.execute(sql)
mydb.commit()
sql1=f"insert into tag_memory (IDS,K,Psx,Psy) values({IDS},{K},{Ps.x},{Ps.y});"
mycursor.execute(sql1)
mydb.commit()
print("1 record inserted")





