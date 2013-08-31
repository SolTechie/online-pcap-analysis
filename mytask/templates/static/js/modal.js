function modalInit(){
    var bodyW=parseInt($("body").width());
    var bodyH=parseInt($("body").height());
    $(".myModal").width(bodyW*0.6);
    $(".myModal").height(bodyH*0.8);
    $(".myModal").css("left",bodyW*0.2);
    $(".myModal").css("top",bodyH*0.1);
    $(".myModalHeader").width(bodyW*0.6);
    $(".myModalHeader").height(bodyH*0.1);
    $(".myModalBody").width(bodyW*0.6);
    $(".myModalBody").height(bodyH*0.6);
    $(".myModalFooter").width(bodyW*0.6);
    $(".myModalFooter").height(bodyH*0.1);
    
    $(".mask").click(function(){
	modalClose();
    });

}

function modalClose(){
    $(".mask").hide("slow");
    $(".myModal").hide("slow");
    $(".myCanvas").remove();
}

function modalShow(){
    $(".mask").show("slow");
    $(".myModal").show("slow");
}