function atlasShow(){
    $("#netGraph").click(function(){

	modalShow();

        $(".myModalBody").append("<canvas class='myCanvas' width='"+parseInt(parseInt($("body").width())*0.58)+"' height='"+parseInt(parseInt($("body").height())*0.58)+"' style='width:"+parseInt(parseInt($("body").width())*0.58)+"px; height:"+parseInt(parseInt($("body").height())*0.58)+"px;'></canvas>");
        var ctx=document.getElementsByClassName("myCanvas")[0].getContext("2d");
        ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);

    
	$.getJSON("http://121.199.35.74/atlas.json",function (res){
	    
	    layoutG(ctx,res);
	    
	    drawT(ctx,res);

	});
    });
}

function drawT(ctx,data){
    ctx.shadowBlur=0;
    var ind=0;
    for ( var vex in data["vertexs"]){
	ctx.fillStyle=data["vertexs"][vex]["color"];
        ctx.beginPath();
        ctx.arc(20,ind*15+30,5,0,Math.PI*2,true);
        ctx.closePath();
        ctx.fill();
	ctx.fillText(vex,35,ind*15+30);
	ind=ind+1;
    }
    var ind=0;
    for (var arc in data["arcs"]){
        ctx.strokeStyle=data["arcs"][arc]["color"];
        ctx.lineWidth=parseInt(data["arcs"][arc]["width"]);
        ctx.lineCap="round";
        ctx.beginPath();
	ctx.moveTo(120,ind*15+30);
        ctx.lineTo(140,ind*15+30);                                                                                                                                                                                                            ctx.stroke();
        ctx.closePath();
        ctx.fillStyle="#000000";
        ctx.fillText(Math.round(data["arcs"][arc]["flow"]*100)/100+"kB",145,ind*15+30);
	ind=ind+1;
    }
    ctx.fillStyle="#000000";
    ctx.font="10px Arial";
    ctx.fillText("图例",20,15);
}

function drawV(ctx,data,baseBlock){
    ctx.shadowBlur=20;
    ctx.shadowColor="black";
    for (var vex in data["vertexs"]){
	var xx=data["vertexs"][vex]["x"];
	var yy=data["vertexs"][vex]["y"];
	var rr=data["vertexs"][vex]["radius"];
	ctx.fillStyle=data["vertexs"][vex]["color"];
	ctx.beginPath();
	ctx.arc(xx,yy,rr,0,Math.PI*2,true);
	ctx.closePath();
	ctx.fill();
    }
}

function layoutG(ctx,data){
    var nBlock=Math.ceil(Math.sqrt(parseInt(data["numVexs"])));
    var baseBlock=Math.min(ctx.canvas.height,ctx.canvas.width)/nBlock;
    var baseX=(Math.max(ctx.canvas.height,ctx.canvas.width)-Math.min(ctx.canvas.height,ctx.canvas.width))/7*4+baseBlock/2;
    var baseY=baseBlock/2;
    var vexInd=[];
    for(var i=0;i<nBlock*nBlock;i++){
	vexInd[i]=i;
    }
    for(var i=0;i<nBlock*nBlock;i++){
	var swp1=Math.round(Math.random()*(nBlock*nBlock-1));
	var swp2=Math.round(Math.random()*(nBlock*nBlock-1));
	var tmp=vexInd[swp1];
	vexInd[swp1]=vexInd[swp2];
	vexInd[swp2]=tmp;
    }
    var maxFlow=0.0;
    var minFlow=10000.0;
    for (var vex in data["vertexs"]){
	if(maxFlow < parseFloat(data["vertexs"][vex]["traffic"])){
	    maxFlow=parseFloat(data["vertexs"][vex]["traffic"]);
	}
	if(minFlow > parseFloat(data["vertexs"][vex]["traffic"])){
	    minFlow=parseFloat(data["vertexs"][vex]["traffic"]);
	}
	data["vertexs"][vex]["color"]="rgb("+Math.round(Math.random()*255)+","+Math.round(Math.random()*255)+","+Math.round(Math.random()*255)+")";
    }
    counter=0;
    for (var vex in data["vertexs"]){
	data["vertexs"][vex]["ind"]=vexInd[counter];
	data["vertexs"][vex]["radius"]=((parseFloat(data["vertexs"][vex]["traffic"])-minFlow)/(maxFlow-minFlow)*0.7+0.3)*baseBlock*0.3;
	data["vertexs"][vex]["x"]=baseX+data["vertexs"][vex]["ind"]%nBlock*baseBlock-(baseBlock*0.4-data["vertexs"][vex]["radius"])+(baseBlock*0.8-data["vertexs"][vex]["radius"]*2)*Math.random();
	data["vertexs"][vex]["y"]=baseY+Math.floor(data["vertexs"][vex]["ind"]/nBlock)*baseBlock-(baseBlock*0.4-data["vertexs"][vex]["radius"])+(baseBlock*0.8-data["vertexs"][vex]["radius"]*2)*Math.random();
	counter=counter+1;
    }
    maxFlow=0.0;
    minFlow=10000.0;
    for(var arc in data["arcs"]){
	if(maxFlow < parseFloat(data["arcs"][arc]["flow"])){
            maxFlow=parseFloat(data["arcs"][arc]["flow"]);
        }
        if(minFlow > parseFloat(data["arcs"][arc]["flow"])){
            minFlow=parseFloat(data["arcs"][arc]["flow"]);
        }
        data["arcs"][arc]["color"]="rgb("+Math.round(Math.random()*255)+","+Math.round(Math.random()*255)+","+Math.round(Math.random()*255)+")";
    }
    for(var arc in data["arcs"]){
	data["arcs"][arc]["width"]=((parseFloat(data["arcs"][arc]["flow"])-minFlow)/(maxFlow-minFlow)*0.7+0.3)*baseBlock*0.05;
    }
    drawA(ctx,data);
    drawV(ctx,data,baseBlock);

}


function drawA(ctx,data){
    ctx.shadowBlur=0;
    for (var arc in data["arcs"]){
	var posSX=data["vertexs"][data["arcs"][arc]["s"]]["x"];
	var posSY=data["vertexs"][data["arcs"][arc]["s"]]["y"];
	var posTX=data["vertexs"][data["arcs"][arc]["t"]]["x"];
	var posTY=data["vertexs"][data["arcs"][arc]["t"]]["y"];
	ctx.strokeStyle=data["arcs"][arc]["color"];
	ctx.lineWidth=parseInt(data["arcs"][arc]["width"]);
	ctx.lineCap="round";
	ctx.beginPath();
	ctx.moveTo(posSX,posSY);
	var cPoint=[(posSX+posTX)/2+Math.random()*(posTX-posSX)*0.3,(posSY+posTY)/2+Math.random()*(posTY-posSY)*0.3]
	ctx.quadraticCurveTo(cPoint[0],cPoint[1],posTX,posTY);
	ctx.stroke();
	ctx.closePath();
    }

    
}