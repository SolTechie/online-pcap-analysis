function trafficPie(){
    $("#ipsFlow").click(function(){
	modalShow();
	
        $(".myModalBody").append("<canvas class='myCanvas' width='"+parseInt(parseInt($("body").width())*0.58)+"' height='"+parseInt(parseInt($("body").height())*0.58)+"' style='width:"+parseInt(parseInt($("body").width())*0.58)+"px; height:"+parseInt(parseInt($("body").height())*0.58)+"px;'></canvas>");
	var ctx=document.getElementsByClassName("myCanvas")[0].getContext("2d");
	ctx.canvas.height=ctx.canvas.height*0.8;
	ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
	
	$.getJSON("http://121.199.35.74/p2p_traffic_pie.json",function(res){
	    options={
		//Boolean - Whether we should show a stroke on each segment
		segmentShowStroke : true,
		//String - The colour of each segment stroke
		segmentStrokeColor : "#fff",
		//Number - The width of each segment stroke
		segmentStrokeWidth : 2,
		//Boolean - Whether we should animate the chart
		animation : true,
		//Number - Amount of animation steps
		animationSteps : 100,
		//String - Animation easing effect
		animationEasing : "easeOutBounce",
		//Boolean - Whether we animate the rotation of the Pie
		animateRotate : true,
		//Boolean - Whether we animate scaling the Pie from the centre
		animateScale : false,
		//Function - Will fire on animation completion.
		onAnimationComplete : null
	    }
	    new Chart(ctx).Pie(res,options);
	});
	$(".myModalBody").append("<table id='innerTb' class='table table-condensed table-hover'></table>");
	$("#innerTb").prepend("<tr><td style='text-align:center;'>序号</td><td style='text-align:center;'>IP地址对</td><td style='text-align:center;'>流量byte</td><tr>");
	$.getJSON("http://121.199.35.74/p2p_traffic_list.json",function(res){
	    for(var ind in res){
		$("#innerTb").append("<tr><td style='text-align:center;'>No."+ind+"</td><td style='text-align:center;'>"+res[ind]["ipPair"]+"</td><td style='text-align:center;'>"+res[ind]["traffic"]+"</td><tr>");
	    }
	});
	$(".mask").click(function(){
	    modalClose();
	    $("#innerTb").remove();
	});
    });
}

