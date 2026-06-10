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
	if(!window.DS||!window.DS.lmsManager) return;
	var sc=window.DS.lmsManager.getScorings();
	if(!sc||!sc.models||sc.models.length===0) return;
	var pp=sc.models[0].playerProps;
	if(!pp||!pp.attributes.Completed||pp.attributes.Status!=='pass') return;

	var score=pp.attributes.PercentScore;
	var status=pp.attributes.Status;

	if(window.parent !== window){
		window.parent.postMessage('ScorePercentage|'+score,window.location.origin);
		window.parent.postMessage('ScoreStatus|'+status,window.location.origin);
	}

	// Backup to localStorage — same origin as wrapper page, survives if parent tab was closed
	try{
		var ctx=JSON.parse(localStorage.getItem('abc_ctx')||'{}');
		localStorage.setItem('abc_pending',JSON.stringify({
			part:ctx.part||0,empID:ctx.empID||'',year:ctx.year||0,
			lang:ctx.lang||'',score:String(score),status:String(status),ts:Date.now()
		}));
	}catch(e){}
}

// Track visited slides via globalProvideData interception
(function(){
	var _orig=window.globalProvideData;
	var _seen={};
	var _count=0;
	var _TOTAL=54;
	window.globalProvideData=function(type,data){
		if(type==='slide'&&window.parent!==window){
			try{
				var slideId='';
				if(document.currentScript){
					var m=(document.currentScript.src||'').match(/\/([^\/?.]+)\.js/);
					if(m) slideId=m[1];
				}
				if(slideId){
					if(!_seen[slideId]){_seen[slideId]=true;_count++;}
					try{localStorage.setItem('abc_slide_prog_p2',JSON.stringify({id:slideId,count:_count,ts:Date.now()}));}catch(e){}
					window.parent.postMessage('SlideLoaded|'+_count+'|'+_TOTAL+'|'+slideId,window.location.origin);
				}
			}catch(e){}
		}
		if(_orig) return _orig.apply(this,arguments);
	};
})();

// Resume from last slide if URL contains ?resumeSlide=slideId
(function(){
	try{
		var m=window.location.search.match(/[?&]resumeSlide=([^&]+)/);
		if(!m||!m[1]) return;
		var slideId=decodeURIComponent(m[1]);
		if(!slideId) return;
		var tries=0;
		var t=setInterval(function(){
			try{
				var p=GetPlayer();
				if(p&&typeof p.gotoSlide==='function'){p.gotoSlide(slideId);clearInterval(t);}
			}catch(e){}
			if(++tries>40) clearInterval(t);
		},500);
	}catch(e){}
})();