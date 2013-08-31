function flowCurve(){
    $("#totalFlow").click(function(){

	modalShow();

        $(".myModalBody").append("<canvas class='myCanvas' width='"+parseInt(parseInt($("body").width())*0.58)+"' height='"+parseInt(parseInt($("body").height())*0.58)+"' style='width:"+parseInt(parseInt($("body").width())*0.58)+"px; height:"+parseInt(parseInt($("body").height())*0.58)+"px;'></canvas>");
	var ctx=document.getElementsByClassName("myCanvas")[0].getContext("2d");
	ctx.canvas.height=ctx.canvas.height*0.8;
	ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
	var options = {
	    //Boolean - If we show the scale above the chart data
	    scaleOverlay : false,
	    //Boolean - If we want to override with a hard coded scale
	    scaleOverride : false,
	    //** Required if scaleOverride is true **
	    //Number - The number of steps in a hard coded scale
	    scaleSteps : null,
	    //Number - The value jump in the hard coded scale
	    scaleStepWidth : null,
	    //Number - The scale starting value
	    scaleStartValue : null,
	    //String - Colour of the scale line
	    scaleLineColor : "rgba(0,0,0,.1)",
	    //Number - Pixel width of the scale line
	    scaleLineWidth : 1,
	    //Boolean - Whether to show labels on the scale
	    scaleShowLabels : true,
	    //Interpolated JS string - can access value
	    scaleLabel : "<%=value%>",
	    //String - Scale label font declaration for the scale label
	    scaleFontFamily : "'Arial'",
	    //Number - Scale label font size in pixels
	    scaleFontSize : 12,
	    //String - Scale label font weight style
	    scaleFontStyle : "normal",
	    //String - Scale label font colour
	    scaleFontColor : "#666",
	    ///Boolean - Whether grid lines are shown across the chart
	    scaleShowGridLines : true,
	    //String - Colour of the grid lines
	    scaleGridLineColor : "rgba(0,0,0,.05)",
	    //Number - Width of the grid lines
	    scaleGridLineWidth : 1,
	    //Boolean - Whether the line is curved between points
	    bezierCurve : true,
	    //Boolean - Whether to show a dot for each point
	    pointDot : true,
	    //Number - Radius of each point dot in pixels
	    pointDotRadius : 3,
	    //Number - Pixel width of point dot stroke
	    pointDotStrokeWidth : 1,
	    //Boolean - Whether to show a stroke for datasets
	    datasetStroke : true,
	    //Number - Pixel width of dataset stroke
	    datasetStrokeWidth : 2,
	    //Boolean - Whether to fill the dataset with a colour
	    datasetFill : true,
	    //Boolean - Whether to animate the chart
	    animation : true,
	    //Number - Number of animation steps
	    animationSteps : 60,
	    //String - Animation easing effect
	    animationEasing : "easeOutQuart",
	    //Function - Fires when the animation is complete
	    onAnimationComplete : null
	};
	$.getJSON("http://121.199.35.74/traffic_per_second_line.json",function(res){
	    new Chart(ctx).Line(res,options);
	});
	
	$(".myModalBody").append("<table id='innerTb' class='table table-condensed table-hover'></table>");
	$("#innerTb").prepend("<tr><td style='text-align:center;'>序号</td><td style='text-align:center;'>时间（秒）</td><td style='text-align:center;'>流量byte</td><tr>");

	$.getJSON("http://121.199.35.74/traffic_per_second_list.json",function(res){
	    for(var ind in res){
		$("#innerTb").append("<tr><td style='text-align:center;'>No."+ind+"</td><td style='text-align:center;'>"+res[ind]["second"]+"</td><td style='text-align:center;'>"+res[ind]["traffic"]+"</td><tr>");
	    }
	});
	$(".mask").click(function(){
	    modalClose();
	    $("#innerTb").remove();
	});
    });
}
	
 