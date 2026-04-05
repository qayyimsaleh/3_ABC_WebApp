function ExecuteScript(strId)
{
  switch (strId)
  {
      case "6mMpir5GhFW":
        Script1();
        break;
      case "5UqsTS4IkSH":
        Script2();
        break;
      case "6DDSOpwSBUn":
        Script3();
        break;
		
	case "5hpJeuoSIX6":
        ScriptFinal();
        break;
  }
}

function Script1()
{
  var targetDate = new Date();



var monthArray = new Array ("January","February","March","April","May","June","July","August","September","October","November","December");

var month = targetDate.getMonth();

var theMonth = monthArray[month];

var dd = targetDate.getDate();

var yyyy = targetDate.getFullYear();

var dateString = dd + " " + theMonth + " " + yyyy;

var player = GetPlayer();
player.SetVar("SystemDate2",dateString);
}

function Script2()
{
  var styles = `@media print {
  body, * { visibility: hidden; }
  html, body { overflow: hidden; transform: translateZ(0); }
  #slide {
    transform: scale(1.3) !important;
  }
  #wrapper {
   transform: scale(1) !important;
  }
  #slide,
  #wrapper {
    width: 100% !important;
    height: 100% !important;
    overflow: visible !important;
  }
  #frame {
    overflow: visible !important;
  }
  .slide-transition-container {
    overflow: visible !important;
  }
  @page {size: A4 landscape;max-height:99%; max-width:99%}
    .slide-container, .slide-container * {
      visibility: visible !important;
      margin-top: 0px !important;
      margin-left: 0px !important;
    }
    #outline-panel {
      display: none !important;
    }
  }
}`
  var stylesheet = document.createElement('style');
  stylesheet.type = 'text/css';
  stylesheet.innerText = styles;
  document.head.appendChild(stylesheet);
  window.print();
}

function Script3()
{
  var targetDate = new Date();



var monthArray = new Array ("January","February","March","April","May","June","July","August","September","October","November","December");

var month = targetDate.getMonth();

var theMonth = monthArray[month];

var dd = targetDate.getDate();

var yyyy = targetDate.getFullYear();

var dateString = dd + " " + theMonth + " " + yyyy;

var player = GetPlayer();
player.SetVar("SystemDate2",dateString);
}


function ScriptFinal(){
	
	
	if(window.opener){
		var player = GetPlayer();
		
		/* not working, probably need to postMessage from main to child to pass the info.
		if(window.opener.studentID){
			player.SetVar("IDTextEntryXXX",window.opener.studentID);
		}
		
		if(window.opener.studentName){
			player.SetVar("NameTextEntryXX",window.opener.studentName);
		}
		*/
		
		if(window.DS)
		{
			if(window.DS.lmsManager)
			{
				if(window.DS.lmsManager.getScorings())
				{
					if(window.DS.lmsManager.getScorings().models.length > 0)
					{
						if(window.DS.lmsManager.getScorings().models[0].playerProps)
						{
							if(window.DS.lmsManager.getScorings().models[0].playerProps.attributes.Completed && window.DS.lmsManager.getScorings().models[0].playerProps.attributes.Status ==='pass')
							{
								window.opener.postMessage('ScorePercentage|' + window.DS.lmsManager.getScorings().models[0].playerProps.attributes.PercentScore,'*');
								window.opener.postMessage('ScoreStatus|' + window.DS.lmsManager.getScorings().models[0].playerProps.attributes.Status,'*');
							}
						}
					}
					
				}
			}
				
		}
			
		
	}
	
	/* not working browser not allow
	if(window.opener){
		var player = GetPlayer();
		
		if(window.opener.studentID){
			player.SetVar("IDTextEntryXXX",window.opener.studentID);
		}
		
		if(window.opener.studentName){
			player.SetVar("NameTextEntryXX",window.opener.studentName);
		}
		
		if(window.opener.studentScorePencentage){
			if(window.DS)
			{
				if(window.DS.lmsManager)
				{
					if(window.DS.lmsManager.getScorings())
					{
						if(window.DS.lmsManager.getScorings().models.length > 0)
						{
							if(window.DS.lmsManager.getScorings().models[0].playerProps)
							{
								window.opener.studentScorePencentage = window.DS.lmsManager.getScorings().models[0].playerProps.attributes.PercentScore;
							}
						}
						
					}
				}
					
			}
			
		}
	}
	*/
	
}
