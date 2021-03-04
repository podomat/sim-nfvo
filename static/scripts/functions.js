function open_updtsk_popup(flag) {
	$('#update-task-modal').show();
};

function close_updtsk_popup(flag) {
	$('#update-task-result').css('visibility','hidden');
	$('#update-task-result').html('');
	$('#update-task-modal').hide();
};


function open_mvvlm_popup(flag) {
	$('#move-volume-modal').show();
};

function close_mvvlm_popup(flag) {
	$('#output-result').css('visibility','hidden');
	$('#output-result').html('');
	$("#source-vnfci-name").prop('selectedIndex',0);
	$("#target-vnfci-name").prop('selectedIndex',0);
	$('#move-volume-modal').hide();
};

