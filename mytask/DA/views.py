# Create your views here.
from django.http import HttpResponse  
from django.shortcuts import render_to_response, RequestContext


import work

def index(request):  
    return render_to_response("index.html",{},context_instance=RequestContext(request))

def analysis(request):
    fields,itemsHttp,parsedFileName=work.loadCSV(request)
    notPost=True
    if request.method=="POST":
        notPost=False
    return render_to_response("analysis.html",{"notPost":notPost,"parsedFileName":"http://121.199.35.74/"+str(parsedFileName),"fields":fields,"items":itemsHttp},context_instance=RequestContext(request))


    
    

