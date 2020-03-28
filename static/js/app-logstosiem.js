

// http://stackoverflow.com/questions/33295120/how-to-generate-gif-256-colors-palette
// Select nice colors for the first ones
colorPallete = [
"#4BC0C0", "#FF6384", "#FFCE56", "#E7E9ED", "#36A2EB",
"#1CE6FF", "#FF34FF", "#FF4A46", "#008941", "#006FA6", "#A30059", "#6A3A4C", "#324E72",
"#FFDBE5", "#7A4900", "#0000A6", "#63FFAC", "#B79762", "#004D43", "#8FB0FF", "#997D87",
"#5A0007", "#809693", "#FEFFE6", "#1B4400", "#4FC601", "#3B5DFF", "#4A3B53", "#FF2F80",
"#61615A", "#BA0900", "#6B7900", "#00C2A0", "#FFAA92", "#FF90C9", "#B903AA", "#D16100",
"#DDEFFF", "#000035", "#7B4F4B", "#A1C299", "#300018", "#0AA6D8", "#013349", "#00846F",
"#372101", "#FFB500", "#C2FFED", "#A079BF", "#CC0744", "#C0B9B2", "#C2FF99", "#001E09",
"#00489C", "#6F0062", "#0CBD66", "#EEC3FF", "#456D75", "#B77B68", "#7A87A1", "#788D66",
"#885578", "#FAD09F", "#FF8A9A", "#D157A0", "#BEC459", "#456648", "#0086ED", "#886F4C",
"#34362D", "#B4A8BD", "#00A6AA", "#452C2C", "#636375", "#A3C8C9", "#FF913F", "#938A81",
"#575329", "#00FECF", "#B05B6F", "#8CD0FF", "#3B9700", "#04F757", "#C8A1A1", "#1E6E00",
"#7900D7", "#A77500", "#6367A9", "#A05837", "#6B002C", "#772600", "#D790FF", "#9B9700",
"#549E79", "#FFF69F", "#201625", "#72418F", "#BC23FF", "#99ADC0", "#3A2465", "#922329",
"#5B4534", "#FDE8DC", "#404E55", "#0089A3", "#CB7E98", "#A4E804", "#000000", "#FFFF00"
]

// Set momentjs locale
moment.locale('es')

$(function() {


	/**************************
	* Helpers
	**************************/

	// Get last executions and show in tab "Toda's Alerts"
	function getLastExecutionsToLogs() {
		
		$("#todaysAlertsContainer").empty();

		$.ajax({
			type:        "GET",
			url:         "/getLastExecutionsLogs",
			contentType: "application/json",
			dataType:    "json"
		})
	
		.done(function(d) {
			var check1 = false;
			var check2 = false;

			$.each(d.execLogs, function(idx, val){
				if (val.date_log == "0") {
					$("#todaysAlertsContainer").html('<b style="font-size:15px;color:black;">'+"0 rules executed today against log files."+'</b>'+'</br>');
				} else if (val.logfile_log != "") {
					check1 = true;
					if (val.matches_log != "Unsupported") {
						if (parseInt(val.matches_log) > 0) {
							$("#todaysAlertsContainer").append('<b style="font-size:15px;color:red;">'+val.date_log+" : "+val.alert_log+" => "+val.matches_log+" matches. Check alerts. ["+val.logfile_log+"]"+'</b>'+'</br>');
							check2 = true;
						}
					}
				} 

			});

			if (check1 && !check2) {
				$("#todaysAlertsContainer").html('<b style="font-size:15px;color:green;">'+"0 matches."+'</b>'+'</br>');
			} else if (!check1) {
				$("#todaysAlertsContainer").html('<b style="font-size:15px;color:black;">'+"0 rules executed today against log files."+'</b>'+'</br>');
			} 

		})
	
		.fail(function(d) {
			console.log("getLastExecutionsToLogs - fail!")
		});
	}


	// Get last executions and show in tab "Toda's Alerts"
	function getLastFilesUploadedLogs() {
		
		$("#filesTodayContainer").empty();

		$.ajax({
			type:        "GET",
			url:         "/getLastFilesUploadedLogs",
			contentType: "application/json",
			dataType:    "json"
		})
	
		.done(function(d) {

			$.each(d.fileLogs, function(idx, val){
				if (val.date_log == "0" && val.fileName_log == "") {
					$("#filesTodayContainer").append('<b style="font-size:15px;color:black;">'+"0 files uploaded today."+'</b>'+'</br>');
				} else {
					$("#filesTodayContainer").append('<b style="font-size:15px;color:blue;">'+val.date_log+" : "+val.fileName_log+'</b>'+'</br>');
				}
			})
		})
	
		.fail(function(d) {
			console.log("filesTodayContainer - fail!")
		});
	}

	// Loader functions
	function show_loader(){
		$("#loader").addClass("loader");
  		//event.preventDefault();
	}
	function hide_loader(){
		$("#loader").removeClass("loader");
	 	//event.preventDefault();
	}

	/******************
	* Event listeners
	******************/
	$(document).ready(function() {
		// Initial data fetching
		getLastExecutionsToLogs()
		getLastFilesUploadedLogs()

		$(function() {
			$("form input").keypress(function (e) {
				if ((e.which && e.which == 13) || (e.keyCode && e.keyCode == 13)) {
					$('button[type=submit] .default').click();
					return false;
				} else {
					return true;
				}
			});
		});



		// Upload Windows Event Logs to SIEM
		$("#winLogsUploadBtn").on("click", function(e) {

			show_loader();

		});


	});
});
