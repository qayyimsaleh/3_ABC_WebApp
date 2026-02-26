function ExecuteScript(strId)
{
  switch (strId)
  {
      case "6CMmJoXDUBi":
        Script1();
        break;
      case "5muvFpKnZot":
        Script2();
        break;
      case "65Lw1Q7jgWk":
        Script3();
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

