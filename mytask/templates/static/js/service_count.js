function serviceShow(){
    $("#servList").click(function(){
	modalShow();

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
	    //Boolean - If there is a stroke on each bar
	    barShowStroke : true,
	    //Number - Pixel width of the bar stroke
	    barStrokeWidth : 2,
	    //Number - Spacing between each of the X value sets
	    barValueSpacing : 5,
	    //Number - Spacing between data sets within X values
	    barDatasetSpacing : 1,
	    //Boolean - Whether to animate the chart
	    animation : true,
	    //Number - Number of animation steps
	    animationSteps : 60,
	    //String - Animation easing effect
	    animationEasing : "easeOutQuart",
	    //Function - Fires when the animation is complete
	    onAnimationComplete : null
	}

	$(".myModalBody").append("<canvas class='myCanvas' width='"+parseInt(parseInt($("body").width())*0.58)+"' height='"+parseInt(parseInt($("body").height())*0.58)+"' style='width:"+parseInt(parseInt($("body").width())*0.58)+"px; height:"+parseInt(parseInt($("body").height())*0.58)+"px;'></canvas>");
	var ctx=document.getElementsByClassName("myCanvas")[0].getContext("2d");
	ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
	$.getJSON("http://121.199.35.74/service_traffic_bar.json",function(res){
	    new Chart(ctx).Bar(res,options);
	});


	$(".myModalBody").append("<canvas class='myCanvas2' width='"+parseInt(parseInt($("body").width())*0.58)+"' height='"+parseInt(parseInt($("body").height())*0.58)+"' style='width:"+parseInt(parseInt($("body").width())*0.58)+"px; height:"+parseInt(parseInt($("body").height())*0.58)+"px;'></canvas>");
	var ctx2=document.getElementsByClassName("myCanvas2")[0].getContext("2d");
	ctx2.clearRect(0,0,ctx2.canvas.width,ctx2.canvas.height);
	$.getJSON("http://121.199.35.74/service_clients_count_bar.json",function(res){
	    new Chart(ctx2).Bar(res,options);
	});

	$(".mask").click(function(){
	    modalClose();
	    $(".myCanvas2").remove();
	});
	
    });
}