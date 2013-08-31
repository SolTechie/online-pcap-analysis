import json
import csv
import os
import time

def genAtlas(items):
    counter=0
    vexs=set()
    arcs={}
    for item in items:
        ip1=item[2]
        ip2=item[4]
        val=float(item[7])/1024.0
        if ip1 not in vexs:
            counter=counter+1
            vexs.add(ip1)
        if ip2 not in vexs:
            counter=counter+1
            vexs.add(ip2)
        if ip1<ip2:
            arc=(ip1,ip2)
        else:
            arc=(ip2,ip1)
        if arc not in arcs:
            arcs[arc]=val
        else:
            arcs[arc]=arcs[arc]+val
    data={}
    data["vertexs"]={}
    data["numVexs"]=counter
    data["arcs"]=[]
    for vex in vexs:
        data["vertexs"][vex]={"traffic":0}
    for arc in arcs:
        data["arcs"].append({"s":arc[0],"t":arc[1],"flow":arcs[arc]})
        data["vertexs"][arc[0]]["traffic"]=data["vertexs"][arc[0]]["traffic"]+arcs[arc]
        data["vertexs"][arc[1]]["traffic"]=data["vertexs"][arc[1]]["traffic"]+arcs[arc]
    f=open("/home/pingan/mytask/json/atlas.json","w")
    json.dump(data,f)
    f.close()

def process(file):
    items=[]
    f=open(file,"r")
    rows = csv.reader(f)
    for row in rows:
        items.append(row)
    f.close()
    return items

def loadCSV(request):
    fields=["No.","Time","Source","S-Port","Destination","D-Port","Protocol","Length","Direction"]     
    rawParsedFileName=""
    if request.method=="POST":
        upFile=request.FILES["fileName"]
        upTime=time.time()
        upAddr=request.META["REMOTE_ADDR"]
        upPath="/home/pingan/mytask/upload/"
        upName="__tm__"+str(upTime)+"__ad__"+str(upAddr)+"__nm__"+str(upFile.name)
        f=open(upPath+upName,"wb")
        for chunk in upFile.chunks():
            f.write(chunk)
            f.flush()
        f.close()
        os.system("/home/pingan/mytask/CAnalysis/analysis"+" "+upPath+upName+" "+"/home/pingan/mytask/CAnalysis/"+upName+".csv"+" "+" /home/pingan/mytask/json/")
        rawParsedFileName=upName+".csv"
        os.system("cat /home/pingan/mytask/CAnalysis/"+upName+".csv | grep http >"+" /home/pingan/mytask/CAnalysis/"+upName+".csv.http")
        #os.system("cat /home/pingan/mytask/CAnalysis/"+upName+".csv | grep tcp >"+" /home/pingan/mytask/CAnalysis/"+upName+".csv.tcp")
        itemsHttp=process("/home/pingan/mytask/CAnalysis/"+upName+".csv.http")
        #itemsTcp=process("/home/pingan/mytask/CAnalysis/"+upName+".csv.tcp")
        #items=process("/home/pingan/mytask/CAnalysis/"+upName+".csv")
    else:
        rawParsedFileName="__example__.csv"
        itemsHttp=process("/home/pingan/mytask/CAnalysis/__example__.csv.http")
        #itemsTcp=process("/home/pingan/mytask/CAnalysis/__example__.csv.tcp")
        #items=process("/home/pingan/mytask/CAnalysis/__example__.csv")
    genAtlas(itemsHttp)
    return fields,itemsHttp,rawParsedFileName
