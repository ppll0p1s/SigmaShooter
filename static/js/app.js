

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

	// Chart Type Rules
	function chartTypeRules() {

		$.ajax({
			type: "GET",
			url: "/getFolderList",
			// data: data,
			// success: success
			// dataType: dataType
		})
		.done(function(d) {
			var datalabels = []
			var datarulesnumber = []

			$.each(d.rulesfolders, function(idx, val){
				datalabels.push(val.folder_name);
				datarulesnumber.push(val.rules_number);
			});	

			var colorArray = []
			for (var i = datalabels.length - 1; i >= 0; i--) {
				colorArray.push(colorPallete[i])
			};

			var ctx = $("#chartRules");

			var data = {
				labels: datalabels,
				datasets: [
				{
					data: datarulesnumber,
					backgroundColor: colorArray,
					hoverBackgroundColor: colorArray
				}
				]
			};

			var myPieChart = new Chart(ctx, {
				type: 'pie',
				data: data,
				options: {
					legend: {
						display: false,
						//position: 'bottom'
					}
				}
			});
		})

		.fail(function(d) {
			console.log(d)
			console.log("chartTypeRules fail!")
		});
	}	

	// Get total rules count
	function getTotalRulesCount() {

		$.ajax({
			type:        "GET",
			url:         "/api/rules/count",
			contentType: "application/json",
			dataType:    "json"
		})

		.done(function(d) {
			tot = d.total
			$("#rulesCounter").html("Rules: " + tot)
		})

		.fail(function(d) {
			console.log("getTotalRulesCount fail!")
		});
	}

	// Last 10 days alerts
	function chartAlertsLastDays() {

		$.ajax({
			type: "GET",
			url: "/getLastAlertsCountByDay",
			// data: data,
			// success: success
			// dataType: dataType
		})
		.done(function(d) {

			var datalabels = []
			var dataalertsnumber = []

			$.each(d.alertslastdays, function(idx, val){
				datalabels.push(val.day_alerts);
				dataalertsnumber.push(val.count_alerts);
			});	

			var ctx = $("#chartAlerts");

			var data = {
				labels: datalabels,
				datasets: [
				{
					label: "Alerts",
					data: dataalertsnumber,
					backgroundColor: "#15b9fa",
						//hoverBackgroundColor: colorArray
					}
					]
				};

				var myPieChart = new Chart(ctx, {
					type: 'bar',
					data: data,
				});
			})

		.fail(function(d) {
			console.log(d)
			console.log("chartAlertsLastDays fail!")
		});
	}	

	// Show rule path in upload single sigma rule modal
	function showRulePathUploadRule() {

		$.ajax({
			type:        "GET",
			url:         "/getRootRulePath",
			contentType: "application/json",
			dataType:    "json"
		})

		.done(function(d) {
			path = d.path
			$("#uploadRulePath").html(path);
			$("#uploadRulePath2").html(path);
		})

		.fail(function(d) {
			console.log("showRulePathUploadRule fail!")
		});
	}


	/***************
	* File Tree
	***************/
	function rulesFileTree() {

		$.ajax({
			type: "GET",
			url: "/getJsonRulesTree",
			contentType: "application/json",
			dataType:    "json"
		})

		.done(function(d) {
			$('#rulesContainer').jstree({
				"core" : {
					"data" : [
					d.rulesTree
					],
					"check_callback": function(operation, node, node_parent, node_position, more) {
	                    // operation can be 'create_node', 'rename_node', 'delete_node', 'move_node' or 'copy_node'
	                    // in case of 'rename_node' node_position is filled with the new node name

	                    if (operation === "move_node" || (operation === "move_node" && data.parent == "#")) {
	                        return node_parent.original.type === "folder"; //only allow dropping inside nodes of type 'folder'
	                    }
	                    //if(more && more.dnd && (operation === 'move_node')) {
    					//	return true;
  						//}
	                    return true;  //allow all other operations
                	}
				},
				"types" : {
					// TODO: select better icons maybe?
					"default" : {
						"icon" : "glyphicon glyphicon-flash"
					},
					"folder" : {
						"icon" : "far fa-folder"
					},
					"folder-open" : {
						"icon" : "far fa-folder-open"
					},
					"yml" : {
						"icon" : "fas fa-file-alt"
					}
				},
				"search": {
					"case_sensitive": false,
					"show_only_matches": true
				},
				"dnd": {
					"check_while_dragging": true
				},
				"plugins" : ["types", "sort", "search", "dnd", "actions"],
				// alphabetical order
				"sort" : function(a, b) {
					a1 = this.get_node(a);
					b1 = this.get_node(b);
					if (a1.icon == b1.icon){
						return (a1.text > b1.text) ? 1 : -1;
					} else {
						return (a1.icon > b1.icon) ? 1 : -1;
					}
				},
			});

			// Play action in each node (could be a folder or rule)
			$('#rulesContainer').jstree(true).add_action("all", {
				"id": "action_play",
				"class": "pull-right fa fa-play",
				"text": "",
				"after": true,
				"selector": "a",
				"event": "click",
				"callback": function(node_id, node, action_id, action_el){

					var days = $("#daysRunAllRules").val();
					var rule = {
						ruleId: node.id,
					}
					show_loader();

					$.ajax({
						type:        "POST",
						url:         "/api/runRule/"+days,
						contentType: "application/json",
						data:        JSON.stringify(rule),
						dataType:    "json",
					})


					.done(function(d) {
						$.each(d.runrule_msg, function(idx, val){
							if (val.unsupported > 0) {
								$("#alert_unsupportedRule").css("display", "");
								$("#alert_unsupportedRule").html(val.unsupported.toString() + " Unsupported rules");
								setTimeout(function(){
									$("#alert_unsupportedRule").css("display", "none"); 
								}, 5000);
							}
							if (val.matches > 0) {
								$("#alert_alertRule").css("display", "");
								$("#alert_alertRule").html(val.matches.toString() + " Matches");
								setTimeout(function(){
									$("#alert_alertRule").css("display", "none"); 
								}, 5000);
							}
							if (val.matches == 0) {
								$("#alert_nomatches").css("display", "");
								$("#alert_nomatches").html("No rule matched");
								setTimeout(function(){
									$("#alert_nomatches").css("display", "none"); 
								}, 5000);
							}
						});	
						
						hide_loader()
						chartAlertsLastDays()
						getLastExecutionsLogs()
						console.log("rulesContainer - action_play")
					})
				
					.fail(function(d) {
						hide_loader()
						$("#alert_error").css("display", "");
						$("#alert_error").html("Something went wrong. Check config.");
						setTimeout(function(){
							$("#alert_error").css("display", "none"); 
						}, 5000);
						console.log("rulesContainer - action_play- fail!")
					});
				}	
			});

			// Remove action in each node (could be a folder or rule)
			$('#rulesContainer').jstree(true).add_action("all", {
				"id": "action_trash",
				"class": "pull-right fa fa-trash",
				"text": "",
				"after": true,
				"selector": "a",
				"event": "click",
				"callback": function(node_id, node, action_id, action_el){
					if (confirm("Selected Sigma rules will be deleted. Are you sure?") == true) {
						var rule = {
							ruleId: node.id,
						}

						$.ajax({
							type:        "POST",
							url:         "/api/deleteRule",
							contentType: "application/json",
							data:        JSON.stringify(rule),
							dataType:    "json",
						})

						.done(function(d) {
							console.log("rulesContainer - action_trash")
							
							state = d.state
							if (state == "OK") {
								updateRulesFileTree();
							}
						})
					} 
				}	
			});

			// Get all nodes and add ones actions to folder nodes and others to rules nodes (yml)
			$('#rulesContainer').bind('ready.jstree', function(e, data){
				var jsonNodes = $('#rulesContainer').jstree(true).get_json("#", { flat: true });
				$.each(jsonNodes, function (i, val) {
					// Action to rules (yml)
					if ($(val).attr('type') == "yml") {
						// Edit action 
						$('#rulesContainer').jstree(true).add_action($(val).attr('id').toString(), {
							"id": "action_edit",
							"class": "pull-right fa fa-edit",
							"text": "",
							"after": true,
							"selector": "a",
							"event": "click",
							"callback": function(node_id, node, action_id, action_el){
								//console.log("callback", node_id, action_id);
								var rule = {
									ruleId: node_id,
								}

								$.ajax({
									type:        "POST",
									url:         "/infoEditRule",
									contentType: "application/json",
									data:        JSON.stringify(rule),
									dataType:    "json",
								})
							
								.done(function(d) {
									$('#editRuleModal').modal('show');
									$.each(d.infoRuleData, function(idx, val){
										document.getElementById("nameFileEdit").innerHTML = val.ruleNameInfo;
										document.getElementById("nameFileEditNew").innerHTML = val.ruleNameInfo;
										document.getElementById("ruleContentEdit").innerHTML = val.ruleContentInfo;
									});	
								})
							
								.fail(function(d) {
									console.log("rulesContainer - action_edit - fail!")
								});
							}	
						});	
					}

					// Action to folders
					if ($(val).attr('type').includes("folder")) {
						// Add new folder
						$('#rulesContainer').jstree(true).add_action($(val).attr('id').toString(), {
							"id": "action_addfolder",
							"class": "pull-right fa fa-folder-plus",
							"text": "",
							"after": true,
							"selector": "a",
							"event": "click",
							"callback": function(node_id, node, action_id, action_el){
								//console.log("callback", node_id, action_id);
								var rule = {
									ruleId: node_id,
								}

								$.ajax({
									type:        "POST",
									url:         "/addFolder",
									contentType: "application/json",
									data:        JSON.stringify(rule),
									dataType:    "json",
								})
							
								.done(function(d) {
									updateRulesFileTree()
								})
							
								.fail(function(d) {
									updateRulesFileTree()
									console.log("rulesContainer - action_addfolder - fail!")
								});
							}	
						});	
						// Add new rule
						$('#rulesContainer').jstree(true).add_action($(val).attr('id').toString(), {
							"id": "action_addrule",
							"class": "pull-right fa fa-upload",
							"text": "",
							"after": true,
							"selector": "a",
							"event": "click",
							"callback": function(node_id, node, action_id, action_el){
								//console.log("callback", node_id, action_id);
								var rule = {
									ruleId: node_id,
								}

								$.ajax({
									type:        "POST",
									url:         "/addRule",
									contentType: "application/json",
									data:        JSON.stringify(rule),
									dataType:    "json",
								})
							
								.done(function(d) {
									$.each(d.infoRuleData, function(idx, val){
										var rulepath = val.rulePath;
										$("#uploadRulePath").html(rulepath);
										$("#uploadRulePath2").html(rulepath);
									});	
									
									$('#uploadRuleModal').modal('show');

								})
							
								.fail(function(d) {
									console.log("rulesContainer - action_addrule - fail!")
								});
							}	
						});	
					}
				});

			});

		})

		.fail(function(d) {
			console.log("rulesFileTree - fail!")
		});
	}	

	// Update the current rules file tree
	function updateRulesFileTree() {

		$.ajax({
			type: "GET",
			url: "/getJsonRulesTree",
			contentType: "application/json",
			dataType:    "json"
		})

		.done(function(d) {
			$('#rulesContainer').jstree(true).settings.core.data = d.rulesTree;
			$('#rulesContainer').jstree(true).refresh();
			getTotalRulesCount();
			chartTypeRules();
		})

		.fail(function(d) {
			console.log("updateRulesFileTree - fail!")
			console.log(d)
		});
	}	

	// Get sigma rules executions logs of last days and show in tab "Executions last day"
	function getLastExecutionsLogs() {
		
		$("#execLogsContainer").empty();

		$.ajax({
			type:        "GET",
			url:         "/getLastExecutionsLogs",
			contentType: "application/json",
			dataType:    "json"
		})
	
		.done(function(d) {

			$.each(d.execLogs, function(idx, val){
				if (val.date_log == "0" && val.sigmaRule_log == "0" && val.matches_log == "0") {
					$("#execLogsContainer").append('<b style="font-size:15px;color:black;">'+"0 rules executed today."+'</b>'+'</br>');
				} else if (val.matches_log == "0") {
					$("#execLogsContainer").append('<b style="font-size:15px;color:green;">'+val.date_log+" : "+val.sigmaRule_log+" => "+val.matches_log+" matches. "+val.logfile_log+'</b>'+'</br>');
				} else if (val.matches_log == "Unsupported") {
					$("#execLogsContainer").append('<b style="font-size:15px;color:orange;">'+val.date_log+" : "+val.sigmaRule_log+" => "+val.matches_log+". Check rule. "+val.logfile_log+'</b>'+'</br>');
				} else if (parseInt(val.matches_log) >= 100) {
					$("#execLogsContainer").append('<b style="font-size:15px;color:red;">'+val.date_log+" : "+val.sigmaRule_log+" => "+val.matches_log+" matches. Check alerts, possible False Positives. "+val.logfile_log+'</b>'+'</br>');
				} else {
					$("#execLogsContainer").append('<b style="font-size:15px;color:red;">'+val.date_log+" : "+val.sigmaRule_log+" => "+val.matches_log+" matches. Check alerts. "+val.logfile_log+'</b>'+'</br>');
				}
			});	

		})
	
		.fail(function(d) {
			console.log("getLastExecutionsLogs - fail!")
		});
	}

	// Check values entered by the user (this is done in backend too)
	function checkNameFolder(val) {
		var patt = new RegExp("^[a-zA-Z0-9_ -]*$");
  		var res = patt.test(val);
  		return res
	}
	function checkNameRule(val) {
		var patt = new RegExp("^[a-zA-Z0-9_ -]*.yml$");
  		var res = patt.test(val);
  		return res
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
		chartTypeRules()
		getTotalRulesCount()
		chartAlertsLastDays()
		rulesFileTree()
		getLastExecutionsLogs()
		showRulePathUploadRule()


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

		
		// Download rules (.tar.gz)
		$("#downloadRulesBtn").on("click", function(e) {
			e.preventDefault()
			window.location.href = "/api/download";
			console.log("#downloadRulesBtn")
		});

		// Delete all sigma rules
		$("#deleteAllRulesBtn").on("click", function(e) {
			e.preventDefault()
			if (confirm("All Sigma rules will be deleted. Are you sure?") == true) {
				window.location.href = "/api/delete";
				console.log("#deleteAllRulesBtn, OK")
			} else {
				console.log("#deleteAllRulesBtn, Cancel")
			}

		});

		// Run all sigma rules
		$("#runAllRulesBtn").on("click", function(e) {
			e.preventDefault()
			console.log("#runAllRulesBtn")

			show_loader();

			var days = $("#daysRunAllRules").val();

			$.ajax({
				type:        "GET",
				url:         "/api/runAllRules/"+days,
				contentType: "application/json",
				//data:        JSON.stringify(rule),
				dataType:    "json",
			})


			.done(function(d) {
				$.each(d.runrule_msg, function(idx, val){
					if (val.unsupported > 0) {
						$("#alert_unsupportedRuleAll").css("display", "");
						$("#alert_unsupportedRuleAll").html(val.unsupported.toString() + " Unsupported rules");
						setTimeout(function(){
							$("#alert_unsupportedRuleAll").css("display", "none"); 
						}, 5000);
					}
					if (val.matches > 0) {
						$("#alert_alertRuleAll").css("display", "");
						$("#alert_alertRuleAll").html(val.matches.toString() + " Matches");
						setTimeout(function(){
							$("#alert_alertRuleAll").css("display", "none"); 
						}, 5000);
					}
					if (val.matches == 0) {
						$("#alert_nomatchesAll").css("display", "");
						$("#alert_nomatchesAll").html("No rule matched");
						setTimeout(function(){
							$("#alert_nomatchesAll").css("display", "none"); 
						}, 5000);
					}
				});	
				
				hide_loader()
				chartAlertsLastDays()
				getLastExecutionsLogs()
				console.log("runAllRulesBtn")
			})
		
			.fail(function(d) {
				hide_loader()
				$("#alert_error").html("Something went wrong. Check config.");
				setTimeout(function(){
					$("#alert_error").css("display", "none"); 
				}, 5000);
				console.log("runAllRulesBtn - fail!")
			});
		});

		// Check SIEM connectivity
		$("#checkConn").on("click", function(e) {
			e.preventDefault()
			console.log("#checkConn")

			$.ajax({
				type:        "GET",
				url:         "/api/checkConn",
				//contentType: "application/json",
				//data:        JSON.stringify(rule),
				dataType:    "json",
			})


			.done(function(d) {
				conn = d.conn
				if (conn == "OK") {
					$("#checkCo").html('<i class="checkGreen fas fa-check"></i>');
				} else {
					$("#checkCo").html('<i class="checkRed fas fa-times"></i>');
				}
			})
		
			.fail(function(d) {
				console.log("checkConn - fail!")
			});
		});

		// Test sigma rules
		$("#testAllRulesBtn").on("click", function(e) {
			show_loader();

			$.ajax({
				type:        "GET",
				url:         "/api/testRules",
				contentType: "application/json",
				dataType:    "json"
			})
		
			.done(function(d) {

				$.each(d.resultsTest, function(idx, val){
					// TODO: maybe adjust better colour assignation, maybe num_alerts = 0 > green ¿? [remember apply changes in all file]
					if (val.num_alerts == "0") {
						$("#testRulesContainer").append('<b style="font-size:15px;color:green;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
					} else if (val.num_alerts == "Unsupported") {
						$("#testRulesContainer").append('<b style="font-size:15px;color:orange;">'+val.rule_name+" => "+val.num_alerts+". Check rule, could be not supported by the SIEM."+'</b>'+'</br>');
					} else if (parseInt(val.num_alerts) >= 100) {
						$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, possible False Positives."+'</b>'+'</br>');
					} else if (parseInt(val.num_alerts) >= 10000) {
						$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, high probability of False Positive. Probably very generic rule."+'</b>'+'</br>');
					} else {
						$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
					}
					hide_loader();
				});	

			})
		
			.fail(function(d) {
				show_loader();
				console.log("testAllRulesBtn - fail!")
			});
		});

		// Test sigma rule simple file
		$("#testRuleFileBtn").on("click", function(e) {
			/*
			console.log(($('#ruleUploadForm')).length)
			console.log(($('#ruleUploadForm'))[0])
			console.log(($('#ruleUploadForm'))[0].files)
			console.log(($('#ruleUploadForm'))[0].files.length)
			console.log(($('#ruleUploadForm'))[0].files[0])
			console.log(($('#ruleUploadForm'))[0].files[0].name)
			*/

			if (($('#ruleUploadForm'))[0].files.length == 0) {
				
				alert("Please, select a file.")

			}  else {

				var file = ($('#ruleUploadForm'))[0].files[0];
				read = new FileReader();

				read.readAsBinaryString(file);

				read.onloadend = function(){

					if (read.result == "") {
						alert("The file seems to be empty. Please, send a valid file.")
					} else {
						var rule = {
							ruleName: ($('#ruleUploadForm'))[0].files[0].name,
							ruleBody: read.result,
						}

						show_loader();

						$.ajax({
							type:        "POST",
							url:         "/api/testRuleFile",
							contentType: "application/json",
							data:        JSON.stringify(rule),
							dataType:    "json",
						})
					
						.done(function(d) {
							if (d.errMsg != "") {
								alert(d.errMsg)
							} else { 
								$.each(d.resultsTest, function(idx, val){
									$('#testAllRulesModal').modal('show');

									if (val.num_alerts == "0") {
										$("#testRulesContainer").append('<b style="font-size:15px;color:green;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
									} else if (val.num_alerts == "Unsupported") {
										$("#testRulesContainer").append('<b style="font-size:15px;color:orange;">'+val.rule_name+" => "+val.num_alerts+". Check rule, could be not supported by the SIEM."+'</b>'+'</br>');
									} else if (parseInt(val.num_alerts) >= 100) {
										$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, possible False Positives."+'</b>'+'</br>');
									} else if (parseInt(val.num_alerts) >= 10000) {
										$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, high probability of False Positive. Probably very generic rule."+'</b>'+'</br>');
									} else {
										$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
									}
									hide_loader();
								});	
							}
						})
					
						.fail(function(d) {
							console.log("testRuleFileBtn - fail!")
						});
					}
				}
			}
		});


		// Reload file tree from submit and edit rules
		/*
		$("#submitUpload").on("click", function(e) {
			chartTypeRules()
			getTotalRulesCount()
			rulesFileTree()
		});
		$("#submitUploadRule").on("click", function(e) {
			chartTypeRules()
			getTotalRulesCount()
			rulesFileTree()
		});
		$("#submitUploadRuleManual").on("click", function(e) {
			chartTypeRules()
			getTotalRulesCount()
			rulesFileTree()
		});
		$("#submitEditRuleTree").on("click", function(e) {
			chartTypeRules()
			getTotalRulesCount()
			rulesFileTree()
		});
		*/


		// Test sigma rule simple manual
		$("#testRuleManualBtn").on("click", function(e) {

			var rule = {
				ruleName: $("#nameFile").val(),
				ruleBody: $("#bodyFile").val(),
			}

			// Check values entered by the user (this is done in backend too)
			if (checkNameRule(rule.ruleName)) {

				show_loader();

				$.ajax({
					type:        "POST",
					url:         "/api/testRuleManual",
					contentType: "application/json",
					data:        JSON.stringify(rule),
					dataType:    "json",
				})

			
				.done(function(d) {
					if (d.errMsg != "") {
						alert(d.errMsg)
					} else { 

					$('#testAllRulesModal').modal('show');
					
						$.each(d.resultsTest, function(idx, val){
							if (val.num_alerts == "0") {
								$("#testRulesContainer").append('<b style="font-size:15px;color:green;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
							} else if (val.num_alerts == "Unsupported") {
								$("#testRulesContainer").append('<b style="font-size:15px;color:orange;">'+val.rule_name+" => "+val.num_alerts+". Check rule, could be not supported by the SIEM."+'</b>'+'</br>');
							} else if (parseInt(val.num_alerts) >= 100) {
								$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, possible False Positives."+'</b>'+'</br>');
							} else if (parseInt(val.num_alerts) >= 10000) {
								$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches. Check rule, high probability of False Positive. Probably very generic rule."+'</b>'+'</br>');
							} else {
								$("#testRulesContainer").append('<b style="font-size:15px;color:red;">'+val.rule_name+" => "+val.num_alerts+" matches."+'</b>'+'</br>');
							}
							hide_loader();
						});	
					}
				})
			
				.fail(function(d) {
					console.log("testRuleManualBtn - fail!")
				});

			} else {
				alert("Incorrect value. Please write a correct name.")
			}

		});

		// Reset testRulesContainer when modal is closed
		$("#testAllRulesModal").on("hidden.bs.modal", function(){
		    $("#testRulesContainer").empty();
		});

		// Show "Sigma rules backup done" frontend alert when .tar.gz rules file is uploaded
		/* 
		$("#submitUpload").on("click", function(e) {
		    $("#alert_submitUpload").css("display", "");
			setTimeout(function(){
				$("#alert_submitUpload").css("display", "none"); 
			}, 5000);
		});
		*/		


		/***************
		* File Tree
		***************/

		// Toggle between folder open and folder closed 
		$("#rulesContainer").on('open_node.jstree', function (event, data) {
			data.instance.set_type(data.node,'folder-open');
		});
		$("#rulesContainer").on('close_node.jstree', function (event, data) {
			data.instance.set_type(data.node,'folder');

		});

		// Search options
		$("#search-jstree").keyup(function () {
			var searchString = $(this).val();
			$('#rulesContainer').jstree('search', searchString);
		});

		// If folder node is dblclicked -> let user to edit name and save it
		// IF rule node is dblclicked -> open modal to edit rule
		$('#rulesContainer').on("dblclick.jstree", function (e) {
			var tree = $(this).jstree();
			var node = tree.get_node(e.target);

			if (node.type.includes("folder")) {
				tree.edit(node);
				$('#rulesContainer').on('rename_node.jstree', function (e, data) {
				  	//data.text is the new name:
					console.log(data.node.id);

					// Check values entered by the user (this is done in backend too)
					//console.log(checkNameFolder(data.text));
					if (checkNameFolder(data.text)) {

						var rule = {
							ruleId: data.node.id,
							folderNewName: data.text,
						}

						$.ajax({
							type:        "POST",
							url:         "/newNodeName",
							contentType: "application/json",
							data:        JSON.stringify(rule),
							dataType:    "json",
						})

						.done(function(d) {
							console.log("dblclick.jstree - folder - newNodeName!")
							updateRulesFileTree()
						})
					
						.fail(function(d) {
							console.log("dblclick.jstree - folder - newNodeName - fail!")
							updateRulesFileTree()
						});

					} else {
						updateRulesFileTree()
						alert("Incorrect value. Please write a correct name.")
					}

				});
			}

			if (node.type == "yml") {

				var rule = {
					ruleId: node.id,
				}

				$.ajax({
					type:        "POST",
					url:         "/infoEditRule",
					contentType: "application/json",
					data:        JSON.stringify(rule),
					dataType:    "json",
				})

				.done(function(d) {
					$('#editRuleModal').modal('show');
					$.each(d.infoRuleData, function(idx, val){
						document.getElementById("nameFileEdit").innerHTML = val.ruleNameInfo;
						document.getElementById("nameFileEditNew").innerHTML = val.ruleNameInfo;
						document.getElementById("ruleContentEdit").innerHTML = val.ruleContentInfo;
					});	
				})
			
				.fail(function(d) {
					console.log("dblclick.jstree - yml - editRuleModal - fail!!")
				});

			}
		});

		// Let drag and drop nodes to user
		$("#rulesContainer").on('move_node.jstree', function (e, data) {
			/*
			console.log("dnd")
			// Node dragged
			console.log(data.node.id)
			// Node where dropped
			console.log(data.node.parent)
			*/

			var nodes = {
				nodeDrag: data.node.id,
				nodeToDrop: data.node.parent,
			}

			$.ajax({
				type:        "POST",
				url:         "/movednd",
				contentType: "application/json",
				data:        JSON.stringify(nodes),
				dataType:    "json",
			})

			.done(function(d) {
				updateRulesFileTree()
				console.log("rulesContainer - move node dnd")
			})
		
			.fail(function(d) {
				updateRulesFileTree()
				console.log("rulesContainer - move node dnd - fail!")
			});
		});

		/***************
		* End File Tree
		***************/


	});
});
