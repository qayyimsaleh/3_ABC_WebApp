function ExecuteScript(strId)
{
  switch (strId)
  {
      case "5ZUQXI2b0Qq":
        Script1();
        break;
      case "6lR38EixWNn":
        Script2();
        break;
      case "5oN4o09Q3CV":
        Script3();
        break;
	case "6EjLmyfB2sU":
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

var _slideFullIdMap = {};
(function(){
	function _wrapGPD(fn) {
		return function(type, dataStr) {
			if (type === 'data' && typeof dataStr === 'string' && !Object.keys(_slideFullIdMap).length) {
				try {
					var allScenes = [], sRe = /"startingSlide":"_player\.([^.]+)\.[^"]+","sceneNumber":(\d+)/g, sMatch;
					while ((sMatch = sRe.exec(dataStr)) !== null) {
						if (parseInt(sMatch[2]) > 0) allScenes.push({id: sMatch[1], pos: sMatch.index});
					}
					for (var i = 0; i < allScenes.length; i++) {
						var scId = allScenes[i].id;
						var chunk = dataStr.substring(allScenes[i].pos, i+1 < allScenes.length ? allScenes[i+1].pos : dataStr.length);
						var hRe = /"html5url":"html5\/data\/js\/([^"]+)\.js"/g, hMatch;
						while ((hMatch = hRe.exec(chunk)) !== null) {
							var fId = hMatch[1];
							if (!_slideFullIdMap[fId]) _slideFullIdMap[fId] = scId + '.' + fId;
						}
					}
				} catch(e2) {}
			}
			return fn ? fn.apply(this, arguments) : undefined;
		};
	}
	var _stored = _wrapGPD(window.globalProvideData);
	try {
		Object.defineProperty(window, 'globalProvideData', {
			get: function() { return _stored; },
			set: function(fn) { _stored = _wrapGPD(fn); },
			configurable: true
		});
	} catch(e) { window.globalProvideData = _stored; }
})();

(function(){
	var _seen={};
	var _count=0;
	var _TOTAL=69;
	var obs=new MutationObserver(function(muts){
		for(var i=0;i<muts.length;i++){
			var nodes=muts[i].addedNodes;
			for(var j=0;j<nodes.length;j++){
				var n=nodes[j];
				if(n.nodeName==='SCRIPT'){
					var src=n.src||'';
					var m=src.match(/html5\/data\/js\/([^\/]+)\.js/);
					if(m&&/^[0-9A-Za-z]{8,15}$/.test(m[1])&&window.parent!==window){
						var slideId=m[1];
						if(!_seen[slideId]){_seen[slideId]=true;_count++;}
						var fullSlideId=_slideFullIdMap[slideId]||slideId;
						window.parent.postMessage('SlideLoaded|'+_count+'|'+_TOTAL+'|'+fullSlideId,window.location.origin);
					}
				}
			}
		}
	});
	obs.observe(document.documentElement,{childList:true,subtree:true});
})();

// Resume from last slide if URL contains ?resumeSlide=slideId
(function(){
	try{
		var m=window.location.search.match(/[?&]resumeSlide=([^&]+)/);
		if(!m||!m[1]) return;
		var slideId=decodeURIComponent(m[1]);
		if(!slideId) return;
		var done=false;
		var resumeObs=new MutationObserver(function(muts){
			if(done) return;
			for(var i=0;i<muts.length;i++){
				var nodes=muts[i].addedNodes;
				for(var j=0;j<nodes.length;j++){
					var n=nodes[j];
					var fnm=n.src?n.src.match(/html5\/data\/js\/([^\/]+)\.js/):null;
					if(n.nodeName==='SCRIPT'&&fnm&&/^[0-9A-Za-z]{8,15}$/.test(fnm[1])){
						resumeObs.disconnect();
						setTimeout(function(){
							var tries=0;
							var t=setInterval(function(){
								if(done){clearInterval(t);return;}
								try{
									var fId=(slideId.indexOf('.')===-1&&_slideFullIdMap[slideId])?_slideFullIdMap[slideId]:slideId;
									var fullId=fId.indexOf('_player.')===0?fId:'_player.'+fId;
									if(window.DS&&window.DS.pubSub&&typeof window.DS.pubSub.trigger==='function'){
										window.DS.pubSub.trigger('nextSlide:requesting',fullId);
										done=true;clearInterval(t);
									}
								}catch(e){}
								if(++tries>20){clearInterval(t);}
							},250);
						},800);
						return;
					}
				}
			}
		});
		resumeObs.observe(document.documentElement,{childList:true,subtree:true});
	}catch(e){}
})();