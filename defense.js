/*Defense_xss is used to defense xss quickly in the front end of web application,make the attack more difficult.
the encode() use the esapi of OWASP，and the fiter() is user-defined.*/

/*
MIT License

Copyright (c) 2018 Albortt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

var xss_vector=['<','>','\'','\"','\\\\','\\\/'];
function filter(param){
	try
	{
		for (var i=0; i<xss_vector.length; i++)
		{	
			var pat = new RegExp(xss_vector[i],"i");
			while(pat.test(param)){
				param=param.replace(pat,"");
			}
		}
	return param;
	}
	catch(err)
	{
	return param;
	}
};

var Log4js = {
  	version: "1.0",
	applicationStartDate: new Date(),
	loggers: {},
	getLogger: function(categoryName) {
		if (!(typeof categoryName == "string")) {
			categoryName = "[default]";
		}

		if (!Log4js.loggers[categoryName]) {
			Log4js.loggers[categoryName] = new Log4js.Logger(categoryName);
		}
		
		return Log4js.loggers[categoryName];
	},
	getDefaultLogger: function() {
		return Log4js.getLogger("[default]"); 
	},
  	attachEvent: function (element, name, observer) {
		if (element.addEventListener) { //DOM event model
			element.addEventListener(name, observer, false);
    	} else if (element.attachEvent) { //M$ event model
			element.attachEvent('on' + name, observer);
    	}
	}
};
Log4js.extend = function(destination, source) {
  for (property in source) {
    destination[property] = source[property];
  }
  return destination;
}
Log4js.bind = function(fn, object) {
  return function() {
        return fn.apply(object, arguments);
  };
};
Log4js.Level = function(level, levelStr) {
	this.level = level;
	this.levelStr = levelStr;
};

Log4js.Level.prototype =  {
	toLevel: function(sArg, defaultLevel) {
		if(sArg === null) {
			return defaultLevel;
		}
		
		if(typeof sArg == "string") { 
			var s = sArg.toUpperCase();
			if(s == "ALL") {return Log4js.Level.ALL;}
			if(s == "DEBUG") {return Log4js.Level.DEBUG;}
			if(s == "INFO") {return Log4js.Level.INFO;}
			if(s == "WARN") {return Log4js.Level.WARN;}
			if(s == "ERROR") {return Log4js.Level.ERROR;}
			if(s == "FATAL") {return Log4js.Level.FATAL;}
			if(s == "OFF") {return Log4js.Level.OFF;}
			if(s == "TRACE") {return Log4js.Level.TRACE;}
			return defaultLevel;
		} else if(typeof sArg == "number") {
			switch(sArg) {
				case ALL_INT: return Log4js.Level.ALL;
				case DEBUG_INT: return Log4js.Level.DEBUG;
				case INFO_INT: return Log4js.Level.INFO;
				case WARN_INT: return Log4js.Level.WARN;
				case ERROR_INT: return Log4js.Level.ERROR;
				case FATAL_INT: return Log4js.Level.FATAL;
				case OFF_INT: return Log4js.Level.OFF;
				case TRACE_INT: return Log4js.Level.TRACE;
				default: return defaultLevel;
			}
		} else {
			return defaultLevel;	
		}
	},	
	toString: function() {
		return this.levelStr;	
	},	
	valueOf: function() {
		return this.level;
	}
};
Log4js.Level.OFF_INT = Number.MAX_VALUE;
Log4js.Level.FATAL_INT = 50000;
Log4js.Level.ERROR_INT = 40000;
Log4js.Level.WARN_INT = 30000;
Log4js.Level.INFO_INT = 20000;
Log4js.Level.DEBUG_INT = 10000;
Log4js.Level.TRACE_INT = 5000;
Log4js.Level.ALL_INT = Number.MIN_VALUE;
Log4js.Level.OFF = new Log4js.Level(Log4js.Level.OFF_INT, "OFF");
Log4js.Level.FATAL = new Log4js.Level(Log4js.Level.FATAL_INT, "FATAL");
Log4js.Level.ERROR = new Log4js.Level(Log4js.Level.ERROR_INT, "ERROR");
Log4js.Level.WARN = new Log4js.Level(Log4js.Level.WARN_INT, "WARN");
Log4js.Level.INFO = new Log4js.Level(Log4js.Level.INFO_INT, "INFO");
Log4js.Level.DEBUG = new Log4js.Level(Log4js.Level.DEBUG_INT, "DEBUG");  
Log4js.Level.TRACE = new Log4js.Level(Log4js.Level.TRACE_INT, "TRACE");  
Log4js.Level.ALL = new Log4js.Level(Log4js.Level.ALL_INT, "ALL"); 
Log4js.CustomEvent = function() {
	this.listeners = [];
};

Log4js.CustomEvent.prototype = {
	addListener : function(method) {
		this.listeners.push(method);
	},
	removeListener : function(method) {
		var foundIndexes = this.findListenerIndexes(method);

		for(var i = 0; i < foundIndexes.length; i++) {
			this.listeners.splice(foundIndexes[i], 1);
		}
	},
	dispatch : function(handler) {
		for(var i = 0; i < this.listeners.length; i++) {
			try {
				this.listeners[i](handler);
			}
			catch (e) {
				log4jsLogger.warn("Could not run the listener " + this.listeners[i] + ". \n" + e);
			}
		}
	},
	findListenerIndexes : function(method) {
		var indexes = [];
		for(var i = 0; i < this.listeners.length; i++) {			
			if (this.listeners[i] == method) {
				indexes.push(i);
			}
		}

		return indexes;
	}
};
Log4js.LoggingEvent = function(categoryName, level, message, exception, logger) {
	this.startTime = new Date();
	this.categoryName = categoryName;
	this.message = message;
	this.exception = exception;
	this.level = level;
	this.logger = logger;
};

Log4js.LoggingEvent.prototype = {
	getFormattedTimestamp: function() {
		if(this.logger) {
			return this.logger.getFormattedTimestamp(this.startTime);
		} else {
			return this.startTime.toGMTString();
		}
	}
};
Log4js.Logger = function(name) {
	this.loggingEvents = [];
	this.appenders = [];
	this.category = name || "";
	this.level = Log4js.Level.FATAL;
	
	this.dateformat = Log4js.DateFormatter.DEFAULT_DATE_FORMAT;
	this.dateformatter = new Log4js.DateFormatter();
	
	this.onlog = new Log4js.CustomEvent();
	this.onclear = new Log4js.CustomEvent();
	
	this.appenders.push(new Log4js.Appender(this));
	try {
		window.onerror = this.windowError.bind(this);
	} catch (e) {
	}
};

Log4js.Logger.prototype = {
	addAppender: function(appender) {
		if (appender instanceof Log4js.Appender) {
			appender.setLogger(this);
			this.appenders.push(appender);			
		} else {
			throw "Not instance of an Appender: " + appender;
		}
	},
	setAppenders: function(appenders) {
		for(var i = 0; i < this.appenders.length; i++) {
			this.appenders[i].doClear();
		}
		
		this.appenders = appenders;
		
		for(var j = 0; j < this.appenders.length; j++) {
			this.appenders[j].setLogger(this);
		}
	},
	setLevel: function(level) {
		this.level = level;
	},
	log: function(logLevel, message, exception) {
		var loggingEvent = new Log4js.LoggingEvent(this.category, logLevel, 
			message, exception, this);
		this.loggingEvents.push(loggingEvent);
		this.onlog.dispatch(loggingEvent);
	},
	clear : function () {
		try{
			this.loggingEvents = [];
			this.onclear.dispatch();
		} catch(e){}
	},
	isTraceEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.TRACE.valueOf()) {
			return true;
		}
		return false;
	},
	trace: function(message) {
		if (this.isTraceEnabled()) {
			this.log(Log4js.Level.TRACE, message, null);
		}
	},
	isDebugEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.DEBUG.valueOf()) {
			return true;
		}
		return false;
	},
	debug: function(message) {
		if (this.isDebugEnabled()) {
			this.log(Log4js.Level.DEBUG, message, null);
		}
	},
	debug: function(message, throwable) {
		if (this.isDebugEnabled()) {
			this.log(Log4js.Level.DEBUG, message, throwable);
		}
	},
	isInfoEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.INFO.valueOf()) {
			return true;
		}
		return false;
	},
	info: function(message) {
		if (this.isInfoEnabled()) {
			this.log(Log4js.Level.INFO, message, null);
		}
	},
	info: function(message, throwable) {
		if (this.isInfoEnabled()) {
			this.log(Log4js.Level.INFO, message, throwable);
		}
	},
	isWarnEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.WARN.valueOf()) {
			return true;
		}
		return false;
	},
	warn: function(message) {
		if (this.isWarnEnabled()) {
			this.log(Log4js.Level.WARN, message, null);
		}
	},
	warn: function(message, throwable) {
		if (this.isWarnEnabled()) {
			this.log(Log4js.Level.WARN, message, throwable);
		}
	},
	isErrorEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.ERROR.valueOf()) {
			return true;
		}
		return false;
	},
	error: function(message) {
		if (this.isErrorEnabled()) {
			this.log(Log4js.Level.ERROR, message, null);
		}
	},
	error: function(message, throwable) {
		if (this.isErrorEnabled()) {
			this.log(Log4js.Level.ERROR, message, throwable);
		}
	},
	isFatalEnabled: function() {
		if (this.level.valueOf() <= Log4js.Level.FATAL.valueOf()) {
			return true;
		}
		return false;
	},
	fatal: function(message) {
		if (this.isFatalEnabled()) {
			this.log(Log4js.Level.FATAL, message, null);
		}
	},
	fatal: function(message, throwable) {
		if (this.isFatalEnabled()) {
			this.log(Log4js.Level.FATAL, message, throwable);
		}
	},
	windowError: function(msg, url, line){
		var message = "Error in (" + (url || window.location) + ") on line "+ line +" with message (" + msg + ")";
		this.log(Log4js.Level.FATAL, message, null);	
	},
	setDateFormat: function(format) {
	 	this.dateformat = format;
	},
	getFormattedTimestamp: function(date) {
	  return this.dateformatter.formatDate(date, this.dateformat);
	}
};
Log4js.Appender = function () {
	 this.logger = null;
};

Log4js.Appender.prototype = {
	doAppend: function(loggingEvent) {
		return;
	},
	doClear: function() {
		return;
	},
	setLayout: function(layout){
		this.layout = layout;
	},
	setLogger: function(logger){
		logger.onlog.addListener(Log4js.bind(this.doAppend, this));
		logger.onclear.addListener(Log4js.bind(this.doClear, this));
	
		this.logger = logger;
	}
};
Log4js.Layout = function(){return;};
Log4js.Layout.prototype = {
	format: function(loggingEvent) {
		return "";
	},
	getContentType: function() {
		return "text/plain";
	},
	getHeader: function() {
		return null;
	},
	getFooter: function() {
		return null;
	},
	getSeparator: function() {
		return "";
	}
};
Log4js.ConsoleAppender = function(isInline) {
	this.layout = new Log4js.PatternLayout(Log4js.PatternLayout.TTCC_CONVERSION_PATTERN);
	this.inline = isInline;
	this.accesskey = "d";
	this.tagPattern = null;
	
	this.commandHistory = [];
  	this.commandIndex = 0;
  	this.popupBlocker = false;
  	
  	this.outputElement = null;
  	
  	this.docReference = null;
	this.winReference = null;		
		
	if(this.inline) {
		Log4js.attachEvent(window, 'load', Log4js.bind(this.initialize, this));
	}
};

Log4js.ConsoleAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	setAccessKey : function(key) {
		this.accesskey = key;
	},
  	initialize : function() {
		if(!this.inline) {
			var doc = null;	
			var win = null;
			window.top.consoleWindow = window.open("", this.logger.category, 
				"left=0,top=0,width=700,height=700,scrollbars=no,status=no,resizable=yes;toolbar=no");
			window.top.consoleWindow.opener = self;
			win = window.top.consoleWindow;
								
			if (!win) { 
				this.popupBlocker=true; 
				alert("Popup window manager blocking the Log4js popup window to bedisplayed.\n\n" 
					+ "Please disabled this to properly see logged events.");  
			} else {	

				doc = win.document;
				doc.open();
				doc.write("<!DOCTYPE html PUBLIC -//W3C//DTD XHTML 1.0 Transitional//EN ");
				doc.write("  http://www.w3.com/TR/xhtml1/DTD/xhtml1-transitional.dtd>\n\n");
				doc.write("<html><head><title>Log4js - " + this.logger.category + "</title>\n");
				doc.write("</head><body style=\"background-color:darkgray\"></body>\n");
				win.blur();
				win.focus();
			}
			
			this.docReference = doc;
			this.winReference = win;
		} else {
			this.docReference = document;
			this.winReference = window;			
		}
				
		this.outputCount = 0;
		this.tagPattern = ".*";
	  
		this.logElement = this.docReference.createElement('div');
		this.docReference.body.appendChild(this.logElement);
		this.logElement.style.display = 'none';
		
		this.logElement.style.position = "absolute";
		this.logElement.style.left = '0px';
		this.logElement.style.width = '100%';
	
		this.logElement.style.textAlign = "left";
		this.logElement.style.fontFamily = "lucida console";
		this.logElement.style.fontSize = "100%";
		this.logElement.style.backgroundColor = 'darkgray';      
		this.logElement.style.opacity = 0.9;
		this.logElement.style.zIndex = 2000; 
	
		this.toolbarElement = this.docReference.createElement('div');
		this.logElement.appendChild(this.toolbarElement);     
		this.toolbarElement.style.padding = "0 0 0 2px";
	    
		this.buttonsContainerElement = this.docReference.createElement('span');
		this.toolbarElement.appendChild(this.buttonsContainerElement); 
	
		if(this.inline) {
			var closeButton = this.docReference.createElement('button');
			closeButton.style.cssFloat = "right";
			closeButton.style.styleFloat = "right";
			closeButton.style.color = "black";
			closeButton.innerHTML = "close";
			closeButton.onclick = Log4js.bind(this.toggle, this);
			this.buttonsContainerElement.appendChild(closeButton);
		}
		
		var clearButton = this.docReference.createElement('button');
		clearButton.style.cssFloat = "right";
		clearButton.style.styleFloat = "right";
		clearButton.style.color = "black";
		clearButton.innerHTML = "clear";
		clearButton.onclick = Log4js.bind(this.logger.clear, this.logger);
		this.buttonsContainerElement.appendChild(clearButton);
	
		this.tagFilterContainerElement = this.docReference.createElement('span');
		this.toolbarElement.appendChild(this.tagFilterContainerElement);
		this.tagFilterContainerElement.style.cssFloat = 'left';
		
		this.tagFilterContainerElement.appendChild(this.docReference.createTextNode("Log4js - " + this.logger.category));
		this.tagFilterContainerElement.appendChild(this.docReference.createTextNode(" | Level Filter: "));
		
		this.tagFilterElement = this.docReference.createElement('input');
		this.tagFilterContainerElement.appendChild(this.tagFilterElement);
		this.tagFilterElement.style.width = '200px';                    
		this.tagFilterElement.value = this.tagPattern;    
		this.tagFilterElement.setAttribute('autocomplete', 'off');
		
		Log4js.attachEvent(this.tagFilterElement, 'keyup', Log4js.bind(this.updateTags, this));
		Log4js.attachEvent(this.tagFilterElement, 'click', Log4js.bind( function() {this.tagFilterElement.select();}, this));
		
		this.outputElement = this.docReference.createElement('div');
		this.logElement.appendChild(this.outputElement);  
		this.outputElement.style.overflow = "auto";              
		this.outputElement.style.clear = "both";
		this.outputElement.style.height = (this.inline) ? ("200px"):("650px");
		this.outputElement.style.width = "100%";
		this.outputElement.style.backgroundColor = 'black'; 
			  
		this.inputContainerElement = this.docReference.createElement('div');
		this.inputContainerElement.style.width = "100%";
		this.logElement.appendChild(this.inputContainerElement);      
		
		this.inputElement = this.docReference.createElement('input');
		this.inputContainerElement.appendChild(this.inputElement);  
		this.inputElement.style.width = '100%';
		this.inputElement.style.borderWidth = '0px';
		this.inputElement.style.margin = '0px';
		this.inputElement.style.padding = '0px';
		this.inputElement.value = 'Type command here'; 
		this.inputElement.setAttribute('autocomplete', 'off');
	
		Log4js.attachEvent(this.inputElement, 'keyup', Log4js.bind(this.handleInput, this));
		Log4js.attachEvent(this.inputElement, 'click', Log4js.bind( function() {this.inputElement.select();}, this));
		
		if(this.inline){
			window.setInterval(Log4js.bind(this.repositionWindow, this), 500);
			this.repositionWindow();
			var accessElement = this.docReference.createElement('button');
			accessElement.style.position = "absolute";
			accessElement.style.top = "-100px";
			accessElement.accessKey = this.accesskey;
			accessElement.onclick = Log4js.bind(this.toggle, this);
			this.docReference.body.appendChild(accessElement);
		} else {
			this.show();
		}
	},
	toggle : function() {
		if (this.logElement.style.display == 'none') {
		 	this.show();
		 	return true;
		} else {
			this.hide();
			return false;
		}
	},
	show : function() {
		this.logElement.style.display = '';
	  	this.outputElement.scrollTop = this.outputElement.scrollHeight;
 	  	this.inputElement.select();
	}, 
	hide : function() {
		this.logElement.style.display = 'none';
	},  	
	output : function(message, style) {		
		var shouldScroll = (this.outputElement.scrollTop + (2 * this.outputElement.clientHeight)) >= this.outputElement.scrollHeight;
		
		this.outputCount++;
	  	style = (style ? style += ';' : '');	  	
	  	style += 'padding:1px;margin:0 0 5px 0';	     
		  
		if (this.outputCount % 2 === 0) {
			style += ";background-color:#101010";
		}
	  	
	  	message = message || "undefined";
	  	message = message.toString();
	  	
	  	this.outputElement.innerHTML += "<pre style='" + style + "'>" + message + "</pre>";
	  	
	  	if (shouldScroll) {				
			this.outputElement.scrollTop = this.outputElement.scrollHeight;
		}
	},
	updateTags : function() {
		
		var pattern = this.tagFilterElement.value;
	
		if (this.tagPattern == pattern) {
			return;
		}
		
		try {
			new RegExp(pattern);
		} catch (e) {
			return;
		}
		
		this.tagPattern = pattern;

		this.outputElement.innerHTML = "";
		this.outputCount = 0;
		for (var i = 0; i < this.logger.loggingEvents.length; i++) {
  			this.doAppend(this.logger.loggingEvents[i]);
		}  
	},
	repositionWindow : function() {
		var offset = window.pageYOffset || this.docReference.documentElement.scrollTop || this.docReference.body.scrollTop;
		var pageHeight = self.innerHeight || this.docReference.documentElement.clientHeight || this.docReference.body.clientHeight;
		this.logElement.style.top = (offset + pageHeight - this.logElement.offsetHeight) + "px";
	},
	doAppend : function(loggingEvent) {
		
		if(this.popupBlocker) {
			return;
		}
		
		if ((!this.inline) && (!this.winReference || this.winReference.closed)) {
			this.initialize();
		}
		
		if (this.tagPattern !== null && 
			loggingEvent.level.toString().search(new RegExp(this.tagPattern, 'igm')) == -1) {
			return;
		}
		
		var style = '';
	  	
		if (loggingEvent.level.toString().search(/ERROR/) != -1) { 
			style += 'color:red';
		} else if (loggingEvent.level.toString().search(/FATAL/) != -1) { 
			style += 'color:red';
		} else if (loggingEvent.level.toString().search(/WARN/) != -1) { 
			style += 'color:orange';
		} else if (loggingEvent.level.toString().search(/DEBUG/) != -1) {
			style += 'color:green';
		} else if (loggingEvent.level.toString().search(/INFO/) != -1) {
			style += 'color:white';
		} else {
			style += 'color:yellow';
		}
	
		this.output(this.layout.format(loggingEvent), style);	
	},
	doClear : function() {
		this.outputElement.innerHTML = "";
	},
	handleInput : function(e) {
		if (e.keyCode == 13 ) {      
			var command = this.inputElement.value;
			
			switch(command) {
				case "clear":
					this.logger.clear();  
					break;
					
				default:        
					var consoleOutput = "";
				
					try {
						consoleOutput = eval(this.inputElement.value);
					} catch (e) {  
						this.logger.error("Problem parsing input <" + command + ">" + e.message);
						break;
					}
						
					this.logger.trace(consoleOutput);
					break;
			}        
		
			if (this.inputElement.value !== "" && this.inputElement.value !== this.commandHistory[0]) {
				this.commandHistory.unshift(this.inputElement.value);
			}
		  
			this.commandIndex = 0;
			this.inputElement.value = "";                                                     
		} else if (e.keyCode == 38 && this.commandHistory.length > 0) {
    		this.inputElement.value = this.commandHistory[this.commandIndex];

			if (this.commandIndex < this.commandHistory.length - 1) {
      			this.commandIndex += 1;
      		}
    	} else if (e.keyCode == 40 && this.commandHistory.length > 0) {
    		if (this.commandIndex > 0) {                                      
      			this.commandIndex -= 1;
	    	}                       

			this.inputElement.value = this.commandHistory[this.commandIndex];
	  	} else {
    		this.commandIndex = 0;
    	}
	},
	 toString: function() {
	 	return "Log4js.ConsoleAppender[inline=" + this.inline + "]"; 
	 }
}); 
Log4js.MetatagAppender = function() {
	this.currentLine = 0;
};
Log4js.MetatagAppender.prototype = Log4js.extend(new Log4js.Appender(), {  
	doAppend: function(loggingEvent) {
		var now = new Date();
		var lines = loggingEvent.message.split("\n");
		var headTag = document.getElementsByTagName("head")[0];

		for (var i = 1; i <= lines.length; i++) {
			var value = lines[i - 1];
			if (i == 1) {
				value = loggingEvent.level.toString() + ": " + value;
			} else {
				value = "> " + value;
			}

			var metaTag = document.createElement("meta");
			metaTag.setAttribute("name", "X-log4js:" + this.currentLine);
			metaTag.setAttribute("content", value);
			headTag.appendChild(metaTag);
			this.currentLine += 1;
		}
	},

	 toString: function() {
	 	return "Log4js.MetatagAppender"; 
	 }
});
Log4js.AjaxAppender = function(loggingUrl) {
	this.isInProgress = false;
	
	this.loggingUrl = loggingUrl || "logging.log4js";
	
	this.threshold = 1;
	
	this.timeout = 2000;
	
	this.loggingEventMap = new Log4js.FifoBuffer();
	this.layout = new Log4js.XMLLayout();
	this.httpRequest = null;
};

Log4js.AjaxAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		log4jsLogger.trace("> AjaxAppender.append");
	
		if (this.loggingEventMap.length() <= this.threshold || this.isInProgress === true) {
			this.loggingEventMap.push(loggingEvent);
		}
		
		if(this.loggingEventMap.length() >= this.threshold && this.isInProgress === false) {
			this.send();
		}
		
		log4jsLogger.trace("< AjaxAppender.append");
	},
	doClear: function() {
		log4jsLogger.trace("> AjaxAppender.doClear" );
		if(this.loggingEventMap.length() > 0) {
			this.send();
		}
		log4jsLogger.trace("< AjaxAppender.doClear" );
	},
	setThreshold: function(threshold) {
		log4jsLogger.trace("> AjaxAppender.setThreshold: " + threshold );
		this.threshold = threshold;
		log4jsLogger.trace("< AjaxAppender.setThreshold" );
	},
	setTimeout: function(milliseconds) {
		this.timeout = milliseconds;
	},
	send: function() {
		if(this.loggingEventMap.length() >0) {
			
			log4jsLogger.trace("> AjaxAppender.send");
			
			
			this.isInProgress = true;
			var a = [];
	
			for(var i = 0; i < this.loggingEventMap.length() && i < this.threshold; i++) {
				a.push(this.layout.format(this.loggingEventMap.pull()));
			} 
					
			var content = this.layout.getHeader();	
			content += a.join(this.layout.getSeparator());
			content += this.layout.getFooter();
			
			var appender = this;
			if(this.httpRequest === null){
				this.httpRequest = this.getXmlHttpRequest();
			}
			this.httpRequest.onreadystatechange = function() {
				appender.onReadyStateChanged.call(appender);
			};
			
			this.httpRequest.open("POST", this.loggingUrl, true);
			this.httpRequest.setRequestHeader("Content-type", this.layout.getContentType());
			this.httpRequest.setRequestHeader("REFERER", location.href);
	 		this.httpRequest.setRequestHeader("Content-length", content.length);
			this.httpRequest.setRequestHeader("Connection", "close");
			this.httpRequest.send( content );
			
			appender = this;
			
			try {
				window.setTimeout(function(){
					log4jsLogger.trace("> AjaxAppender.timeout");
					appender.httpRequest.onreadystatechange = function(){return;};
					appender.httpRequest.abort();
					appender.isInProgress = false;
		
					if(appender.loggingEventMap.length() > 0) {
						appender.send();
					}
					log4jsLogger.trace("< AjaxAppender.timeout");
				}, this.timeout);
			} catch (e) {
				log4jsLogger.fatal(e);
			}
			log4jsLogger.trace("> AjaxAppender.send");
		}
	},
	onReadyStateChanged: function() {
		log4jsLogger.trace("> AjaxAppender.onReadyStateChanged");
		var req = this.httpRequest;
		if (this.httpRequest.readyState != 4) { 
			log4jsLogger.trace("< AjaxAppender.onReadyStateChanged: readyState " + req.readyState + " != 4");
			return; 
		}
		
		var success = ((typeof req.status === "undefined") || req.status === 0 || (req.status >= 200 && req.status < 300));
		
		if (success) {
			log4jsLogger.trace("  AjaxAppender.onReadyStateChanged: success");

			this.isInProgress = false;

		} else {
			var msg = "  AjaxAppender.onReadyStateChanged: XMLHttpRequest request to URL " + this.loggingUrl + " returned status code " + this.httpRequest.status;
			log4jsLogger.error(msg);
		}
		
		log4jsLogger.trace("< AjaxAppender.onReadyStateChanged: readyState == 4");		
	},
	getXmlHttpRequest: function() {
		log4jsLogger.trace("> AjaxAppender.getXmlHttpRequest");
		
		var httpRequest = false;

		try {		
			if (window.XMLHttpRequest) {
					httpRequest = new XMLHttpRequest();
				if (httpRequest.overrideMimeType) {
					httpRequest.overrideMimeType(this.layout.getContentType());
				}
			} else if (window.ActiveXObject) { // IE
				try {
					httpRequest = new ActiveXObject("Msxml2.XMLHTTP");
				} catch (e) {
					httpRequest = new ActiveXObject("Microsoft.XMLHTTP");
				}
			}
		} catch (e) {
			httpRequest = false;
		}
		
		if (!httpRequest) {
			log4jsLogger.fatal("Unfortunatelly your browser does not support AjaxAppender for log4js!");
		}
		
		log4jsLogger.trace("< AjaxAppender.getXmlHttpRequest");
		return httpRequest;
	},
	 toString: function() {
	 	return "Log4js.AjaxAppender[loggingUrl=" + this.loggingUrl + ", threshold=" + this.threshold + "]"; 
	 }
});
Log4js.FileAppender = function(file) {

	this.layout = new Log4js.SimpleLayout();
	this.isIE = 'undefined';
	
	this.file = file || "log4js.log";	
	
	try{
		this.fso = new ActiveXObject("Scripting.FileSystemObject");
		this.isIE = true;
	} catch(e){
		try {
			netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
			this.fso =  Components.classes["@mozilla.com/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
			this.isIE = false;
		} catch (e) {
			log4jsLogger.error(e);
		}
	}
};

Log4js.FileAppender.prototype = Log4js.extend(new Log4js.Appender(), {  
	doAppend: function(loggingEvent) {
		try {
			var fileHandle = null;
			
			if( this.isIE === 'undefined') {
				log4jsLogger.error("Unsupported ")
			}
			else if( this.isIE ){
				fileHandle = this.fso.OpenTextFile(this.file, 8, true);
				fileHandle.WriteLine(this.layout.format(loggingEvent));
				fileHandle.close();   
			} else {
				netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
				this.fso.initWithPath(this.file);
    			if(!this.fso.exists()) {
            		this.fso.create(0x00, 0600);
    			}
				
 				fileHandle = Components.classes["@mozilla.com/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
        		fileHandle.init( this.fso, 0x04 | 0x08 | 0x10, 064, 0);
				var line = this.layout.format(loggingEvent);
        		fileHandle.write(line, line.length); //write data
        		fileHandle.close();
			}
		} catch (e) {
			log4jsLogger.error(e);
		}
	},
	doClear: function() {
		try {
			if( this.isIE ){
				var fileHandle = this.fso.GetFile(this.file);
				fileHandle.Delete();
			} else {
				netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
				this.fso.initWithPath(this.file);
				if(this.fso.exists()) {
					this.fso.remove(false);
				}
			}
		} catch (e) {
			log4jsLogger.error(e);
		}
	},

	 toString: function() {
	 	return "Log4js.FileAppender[file=" + this.file + "]"; 
	 }
});
Log4js.WindowsEventAppender = function() {
	
	this.layout = new Log4js.SimpleLayout();
	
	try {
		this.shell = new ActiveXObject("WScript.Shell");
	} catch(e) {
		log4jsLogger.error(e);
	}
};

Log4js.WindowsEventAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		var winLevel = 4;
		switch (loggingEvent.level) {	
			case Log4js.Level.FATAL:
				winLevel = 1;
				break;
			case Log4js.Level.ERROR:
				winLevel = 1;
				break;
			case Log4js.Level.WARN:
				winLevel = 2;
				break;
			default:
				winLevel = 4;
				break;
		}
		
		try {
			this.shell.LogEvent(winLevel, this.level.format(loggingEvent));
		} catch(e) {
			log4jsLogger.error(e);
		}
	},
	 toString: function() {
	 	return "Log4js.WindowsEventAppender"; 
	 } 
});
Log4js.JSAlertAppender = function() {

	this.layout = new Log4js.SimpleLayout();
};

Log4js.JSAlertAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		alert(this.layout.getHeader() + this.layout.format(loggingEvent) + this.layout.getFooter());
	},
	 toString: function() {
	 	return "Log4js.JSAlertAppender"; 
	 }	
});
Log4js.MozillaJSConsoleAppender = function() {
	this.layout = new Log4js.SimpleLayout();
	try {
		netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
		this.jsConsole = Components.classes["@mozilla.com/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
		this.scriptError = Components.classes["@mozilla.com/scripterror;1"].createInstance(Components.interfaces.nsIScriptError);
	} catch (e) {
		log4jsLogger.error(e);
	}
};

Log4js.MozillaJSConsoleAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		try {
			netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
			this.scriptError.init(this.layout.format(loggingEvent), null, null, null, null, this.getFlag(loggingEvent), loggingEvent.categoryName);
			this.jsConsole.logMessage(this.scriptError);
		} catch (e) {
			log4jsLogger.error(e);
		}
	},
	 toString: function() {
	 	return "Log4js.MozillaJSConsoleAppender"; 
	 },
	getFlag: function(loggingEvent)
	{
		var retval;
		switch (loggingEvent.level) {	
			case Log4js.Level.FATAL:
				retval = 2;
				break;
			case Log4js.Level.ERROR:
				retval = 0;
				break;
			case Log4js.Level.WARN:
				retval = 1;
				break;
			default:
				retval = 1;
				break;
		}
		
		return retval;		
	}
});
Log4js.OperaJSConsoleAppender = function() {
	this.layout = new Log4js.SimpleLayout();
};

Log4js.OperaJSConsoleAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		opera.postError(this.layout.format(loggingEvent));
	},
	 toString: function() {
	 	return "Log4js.OperaJSConsoleAppender"; 
	 }
});
Log4js.SafariJSConsoleAppender = function() {
	this.layout = new Log4js.SimpleLayout();
};

Log4js.SafariJSConsoleAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		window.console.log(this.layout.format(loggingEvent));
	},
	 toString: function() {
	 	return "Log4js.SafariJSConsoleAppender"; 
	 }
});
Log4js.BrowserConsoleAppender = function() {
	this.consoleDelegate = null;
	
	if (window.console) {
		this.consoleDelegate = new Log4js.SafariJSConsoleAppender(); 
	}
    else if (window.opera) {
		this.consoleDelegate = new Log4js.OperaJSConsoleAppender(); 
	}
	else if(netscape) {
		this.consoleDelegate = new Log4js.MozJSConsoleAppender(); 
	}
    else {
       log4jsLogger.error("Unsupported Browser");
    }
};

Log4js.BrowserConsoleAppender.prototype = Log4js.extend(new Log4js.Appender(), {
	doAppend: function(loggingEvent) {
		this.consoleDelegate.doAppend(loggingEvent);
	},
	doClear: function() {
		this.consoleDelegate.doClear();
	},
	setLayout: function(layout){
		this.consoleDelegate.setLayout(layout);
	},
	 toString: function() {
	 	return "Log4js.BrowserConsoleAppender: " + this.consoleDelegate.toString(); 
	 }
});
Log4js.SimpleLayout = function() {
	this.LINE_SEP  = "\n";
	this.LINE_SEP_LEN = 1;
};

Log4js.SimpleLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	format: function(loggingEvent) {
		return loggingEvent.level.toString() + " - " + loggingEvent.message + this.LINE_SEP;
	},
	getContentType: function() {
		return "text/plain";
	},
	getHeader: function() {
		return "";
	},
	getFooter: function() {
		return "";
	}
});
Log4js.BasicLayout = function() {
	this.LINE_SEP  = "\n";
};

Log4js.BasicLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	format: function(loggingEvent) {
		return loggingEvent.categoryName + "~" + loggingEvent.startTime.toLocaleString() + " [" + loggingEvent.level.toString() + "] " + loggingEvent.message + this.LINE_SEP;
	},
	getContentType: function() {
		return "text/plain";
	},
	getHeader: function() {
		return "";
	},
	getFooter: function() {
		return "";
	}
});
Log4js.HtmlLayout = function() {return;};

Log4js.HtmlLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	format: function(loggingEvent) {
		return "<div style=\"" + this.getStyle(loggingEvent) + "\">" + loggingEvent.getFormattedTimestamp() + " - " + loggingEvent.level.toString() + " - " + loggingEvent.message + "</div>\n";
	},
	getContentType: function() {
		return "text/html";
	},
	getHeader: function() {
		return "<html><head><title>log4js</head><body>";
	},
	getFooter: function() {
		return "</body></html>";
	},
	
	getStyle: function(loggingEvent)
	{
		var style;
		if (loggingEvent.level.toString().search(/ERROR/) != -1) { 
			style = 'color:red';
		} else if (loggingEvent.level.toString().search(/FATAL/) != -1) { 
			style = 'color:red';
		} else if (loggingEvent.level.toString().search(/WARN/) != -1) { 
			style = 'color:orange';
		} else if (loggingEvent.level.toString().search(/DEBUG/) != -1) {
			style = 'color:green';
		} else if (loggingEvent.level.toString().search(/INFO/) != -1) {
			style = 'color:white';
		} else {
			style = 'color:yellow';
		}	
		return style;
	}
});

Log4js.XMLLayout = function(){return;};
Log4js.XMLLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	format: function(loggingEvent) {
		var useragent = "unknown";
		try {
			useragent = navigator.userAgent;
		} catch(e){
			useragent = "unknown";
		}
		
		var referer = "unknown";
		try {
			referer = location.href;
		} catch(e){
			referer = "unknown";
		}
				
		var content = "<log4js:event logger=\"";
		content += loggingEvent.categoryName + "\" level=\"";
		content += loggingEvent.level.toString() + "\" useragent=\"";
		content += useragent + "\" referer=\"";
		content += referer.replace(/&/g, "&amp;") + "\" timestamp=\"";
		content += loggingEvent.getFormattedTimestamp() + "\">\n";
		content += "\t<log4js:message><![CDATA[" + this.escapeCdata(loggingEvent.message) + "]]></log4js:message>\n";	
 		
 		if (loggingEvent.exception) {
			content += this.formatException(loggingEvent.exception) ;
		}
 		content += "</log4js:event>\n";
        
      return content;
	},
	getContentType: function() {
		return "text/xml";
	},
	getHeader: function() {
		return "<log4js:eventSet version=\"" + Log4js.version + 
			"\" xmlns:log4js=\"http://log4js.berlios.de/2007/log4js/\">\n";
	},
	getFooter: function() {
		return "</log4js:eventSet>\n";
	},
	
	getSeparator: function() {
		return "\n";
	},
	
	formatException: function(ex) {
		if (ex) {
			var exStr = "\t<log4js:throwable>"; 
			if (ex.message) {
				exStr +=  "\t\t<log4js:message><![CDATA[" + this.escapeCdata(ex.message) + "]]></log4js:message>\n";	
			} 
			if (ex.description) {
				exStr +=  "\t\t<log4js:description><![CDATA[" + this.escapeCdata(ex.description) + "]]></log4js:description>\n";	
			}
			
			exStr +=  "\t\t<log4js:stacktrace>";
			exStr +=  "\t\t\t<log4js:location fileName=\""+ex.fileName+"\" lineNumber=\""+ex.lineNumber+"\" />";
			exStr +=  "\t\t</log4js:stacktrace>";
			exStr = "\t</log4js:throwable>";
			return exStr;
		}
		return null;
	},
	escapeCdata: function(str) {
		return str.replace(/\]\]>/, "]]>]]&gt;<![CDATA[");
	}
});

Log4js.JSONLayout = function() {
	this.df = new Log4js.DateFormatter();
};
Log4js.JSONLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	format: function(loggingEvent) {
		
				var useragent = "unknown";
		try {
			useragent = navigator.userAgent;
		} catch(e){
			useragent = "unknown";
		}
		
		var referer = "unknown";
		try {
			referer = location.href;
		} catch(e){
			referer = "unknown";
		}
		
		var jsonString = "{\n \"LoggingEvent\": {\n";
		
		jsonString += "\t\"logger\": \"" +  loggingEvent.categoryName + "\",\n";
		jsonString += "\t\"level\": \"" +  loggingEvent.level.toString() + "\",\n";
		jsonString += "\t\"message\": \"" +  loggingEvent.message + "\",\n"; 
		jsonString += "\t\"referer\": \"" + referer + "\",\n"; 
		jsonString += "\t\"useragent\": \"" + useragent + "\",\n"; 
		jsonString += "\t\"timestamp\": \"" +  this.df.formatDate(loggingEvent.startTime, "yyyy-MM-ddThh:mm:ssZ") + "\",\n";
		jsonString += "\t\"exception\": \"" +  loggingEvent.exception + "\"\n"; 
		jsonString += "}}";      
        
        return jsonString;
	},
	getContentType: function() {
		return "text/json";
	},
	getHeader: function() {
		return "{\"Log4js\": [\n";
	},
	getFooter: function() {
		return "\n]}";
	},
	
	getSeparator: function() {
		return ",\n";
	}
});

Log4js.PatternLayout = function(pattern) {
	if (pattern) {
		this.pattern = pattern;
	} else {
		this.pattern = Log4js.PatternLayout.DEFAULT_CONVERSION_PATTERN;
	}
};

Log4js.PatternLayout.TTCC_CONVERSION_PATTERN = "%r %p %c - %m%n";
Log4js.PatternLayout.DEFAULT_CONVERSION_PATTERN = "%m%n";
Log4js.PatternLayout.ISO8601_DATEFORMAT = "yyyy-MM-dd HH:mm:ss,SSS";
Log4js.PatternLayout.DATETIME_DATEFORMAT = "dd MMM YYYY HH:mm:ss,SSS";
Log4js.PatternLayout.ABSOLUTETIME_DATEFORMAT = "HH:mm:ss,SSS";

Log4js.PatternLayout.prototype = Log4js.extend(new Log4js.Layout(), {
	getContentType: function() {
		return "text/plain";
	},
	getHeader: function() {
		return null;
	},
	getFooter: function() {
		return null;
	},
	
	format: function(loggingEvent) {
		var regex = /%(-?[0-9]+)?(\.?[0-9]+)?([cdmnpr%])(\{([^\}]+)\})?|([^%]+)/;
		var formattedString = "";
		var result;
		var searchString = this.pattern;

		while ((result = regex.exec(searchString))) {
			var matchedString = result[0];
			var padding = result[1];
			var truncation = result[2];
			var conversionCharacter = result[3];
			var specifier = result[5];
			var text = result[6];

			if (text) {
				formattedString += "" + text;
			} else {
				var replacement = "";
				switch(conversionCharacter) {
					case "c":
						var loggerName = loggingEvent.categoryName;
						if (specifier) {
							var precision = parseInt(specifier, 10);
							var loggerNameBits = loggingEvent.categoryName.split(".");
							if (precision >= loggerNameBits.length) {
								replacement = loggerName;
							} else {
								replacement = loggerNameBits.slice(loggerNameBits.length - precision).join(".");
							}
						} else {
							replacement = loggerName;
						}
						break;
					case "d":
						var dateFormat = Log4js.PatternLayout.ISO8601_DATEFORMAT;
						if (specifier) {
							dateFormat = specifier;
							if (dateFormat == "ISO8601") {
								dateFormat = Log4js.PatternLayout.ISO8601_DATEFORMAT;
							} else if (dateFormat == "ABSOLUTE") {
								dateFormat = Log4js.PatternLayout.ABSOLUTETIME_DATEFORMAT;
							} else if (dateFormat == "DATE") {
								dateFormat = Log4js.PatternLayout.DATETIME_DATEFORMAT;
							}
						}
						replacement = (new Log4js.SimpleDateFormat(dateFormat)).format(loggingEvent.startTime);
						break;
					case "m":
						replacement = loggingEvent.message;
						break;
					case "n":
						replacement = "\n";
						break;
					case "p":
						replacement = loggingEvent.level.toString();
						break;
					case "r":
						replacement = "" + loggingEvent.startTime.toLocaleTimeString();
						break;
					case "%":
						replacement = "%";
						break;
					default:
						replacement = matchedString;
						break;
				}

				var len;

				if (truncation) {
					len = parseInt(truncation.substr(1), 10);
					replacement = replacement.substring(0, len);
				}
				if (padding) {
					if (padding.charAt(0) == "-") {
						len = parseInt(padding.substr(1), 10);
						while (replacement.length < len) {
							replacement += " ";
						}
					} else {
						len = parseInt(padding, 10);
						while (replacement.length < len) {
							replacement = " " + replacement;
						}
					}
				}
				formattedString += replacement;
			}
			searchString = searchString.substr(result.index + result[0].length);
		}
		return formattedString;
	}
});

if (!Array.prototype.push) {
	Array.prototype.push = function() {
		var startLength = this.length;
		for (var i = 0; i < arguments.length; i++) {
			this[startLength + i] = arguments[i];
		}
		return this.length;
	};
}
Log4js.FifoBuffer = function()
{
  this.array = new Array();
};

Log4js.FifoBuffer.prototype = {

	push : function(obj) {
        this.array[this.array.length] = obj;
        return this.array.length;
	},
	
	pull : function() {
		if (this.array.length > 0) {
			var firstItem = this.array[0];
			for (var i = 0; i < this.array.length - 1; i++) {
				this.array[i] = this.array[i + 1];
			}
			this.array.length = this.array.length - 1;
			return firstItem;
		}
		return null;
	},
	
	length : function() {
		return this.array.length;
	}
};
Log4js.DateFormatter = function() {
	return;
};
Log4js.DateFormatter.DEFAULT_DATE_FORMAT = "yyyy-MM-ddThh:mm:ssO";


Log4js.DateFormatter.prototype = {
	formatDate : function(vDate, vFormat) {
	  var vDay = this.addZero(vDate.getDate());
	  var vMonth = this.addZero(vDate.getMonth()+1);
	  var vYearLong = this.addZero(vDate.getFullYear());
	  var vYearShort = this.addZero(vDate.getFullYear().toString().substring(3,4));
	  var vYear = (vFormat.indexOf("yyyy")>-1?vYearLong:vYearShort);
	  var vHour  = this.addZero(vDate.getHours());
	  var vMinute = this.addZero(vDate.getMinutes());
	  var vSecond = this.addZero(vDate.getSeconds());
	  var vTimeZone = this.O(vDate);
	  var vDateString = vFormat.replace(/dd/g, vDay).replace(/MM/g, vMonth).replace(/y{1,4}/g, vYear);
	  vDateString = vDateString.replace(/hh/g, vHour).replace(/mm/g, vMinute).replace(/ss/g, vSecond);
	  vDateString = vDateString.replace(/O/g, vTimeZone);
	  return vDateString;
	},
	addZero : function(vNumber) {
	  return ((vNumber < 10) ? "0" : "") + vNumber;
	},
	O : function (date) {
		var os = Math.abs(date.getTimezoneOffset());
		var h = String(Math.floor(os/60));
		var m = String(os%60);
		h.length == 1? h = "0"+h:1;
		m.length == 1? m = "0"+m:1;
		return date.getTimezoneOffset() < 0 ? "+"+h+m : "-"+h+m;
	}
};

var log4jsLogger = Log4js.getLogger("Log4js");
log4jsLogger.addAppender(new Log4js.ConsoleAppender());
log4jsLogger.setLevel(Log4js.Level.ALL);

var API_Standard_en_US = {
    name: 'API Standard Messages - US English',
    locale: 'en-US',
    messages: {
        "Test"                              : "This is test #{testnumber}",

        "CreditCard.Required.Usr"           : "{context}: Input credit card required",
        "CreditCard.Required.Log"           : "Input credit card required: context={context}, input={input}",
        "CreditCard.Invalid.Usr"            : "{context}: Invalid credit card input",
        "CreditCard.Invalid.Log"            : "Invalid credit card input: context={context}, input={input}",
        "Date.Required.Usr"                 : "{context}: Input date required in {format} format",
        "Date.Required.Log"                 : "Date required: context={context}, input={input}, format={format}",
        "Date.Invalid.Usr"                  : "{context}: Invalid date, please use {format} format",
        "Date.Invalid.Log"                  : "Invalid date: context={context}, input={input}, format={format}",
        "Integer.Required.Usr"              : "{context}: Input number required",
        "Integer.Required.Log"              : "Input number required: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Integer.NaN.Usr"                   : "{context}: Invalid number",
        "Integer.NaN.Log"                   : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Integer.MinValue.Usr"              : "{context}: Invalid number - Must be greater than {minValue}",
        "Integer.MinValue.Log"              : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Integer.MaxValue.Usr"              : "{context}: Invalid number - Must be less than {maxValue}",
        "Integer.MaxValue.Log"              : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Number.Required.Usr"               : "{context}: Input number required",
        "Number.Required.Log"               : "Input number required: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Number.NaN.Usr"                    : "{context}: Invalid number",
        "Number.NaN.Log"                    : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Number.MinValue.Usr"               : "{context}: Invalid number - Must be greater than {minValue}",
        "Number.MinValue.Log"               : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "Number.MaxValue.Usr"               : "{context}: Invalid number - Must be less than {maxValue}",
        "Number.MaxValue.Log"               : "Invalid number: context={context}, input={input}, minValue={minValue}, maxValue={maxValue}",
        "String.Required.Usr"               : "{context}: Input required",
        "String.Required.Log"               : "Input required: context={context}, input={input}, original={orig}",
        "String.Whitelist.Usr"              : "{context}: Invalid input - Conform to regex {pattern}",
        "String.Whitelist.Log"              : "Invalid input - Whitelist validation failed: context={context}, input={input}, original={orig}, pattern={pattern}",
        "String.Blacklist.Usr"              : "{context}: Invalid input - Dangerous input matching {pattern} detected",
        "String.Blacklist.Log"              : "Invalid input - Blacklist validation failed: context={context}, input={input}, original={orig}, pattern={pattern}",
        "String.MinLength.Usr"              : "{context}: Invalid input - Minimum length is {minLength}",
        "String.MinLength.Log"              : "Invalid input - Too short: context={context}, input={input}, original={orig}, minLength={minLength}",
        "String.MaxLength.Usr"              : "{context}: Invalid input - Maximum length is {maxLength}",
        "String.MaxLength.Log"              : "Invalid input - Too long: context={context}, input={input}, original={orig}, maxLength={maxLength}",

        "HTTPUtilities.Cookie.Protocol"     : "Cookies disallowed on non http[s] requests. Current protocol: {protocol}",
        "HTTPUtilities.Cookie.UnsafeData"   : "Attempt to add unsafe data to cookie (skip mode) - Cookie: {name}={value}",
        "HTTPUtilities.Cookie.CantKill"     : "Unable to kill cookie named {name}",
        "Cookie.Name"                       : "Cookie name \"{name}\" is a reserved token",
        "Cookie.Version"                    : "Cookie version \"{version}\" is not a valid version. Version must be 0 or 1."
    }
};

var $namespace = function(name, separator, container){
  var ns = name.split(separator || '.'),
    o = container || window,
    i,
    len;
  for(i = 0, len = ns.length; i < len; i++){
    o = o[ns[i]] = o[ns[i]] || {};
  }
  return o;
};

var $type = function( oVar, oType ) {
    if ( !oVar instanceof oType ) {
        throw new SyntaxError();
    }
};

if (!$) {
    var $ = function( sElementID ) {
        return document.getElementById( sElementID );
    };
}

if (!Array.prototype.each) {
    Array.prototype.each = function(fIterator) {
        if (typeof fIterator != 'function') {
            throw 'Illegal Argument for Array.each';
        }

        for (var i = 0; i < this.length; i ++) {
            fIterator(this[i]);
        }
    };
}

if (!Array.prototype.contains) {
    Array.prototype.contains = function(srch) {
        var found = false;
        this.each(function(e) {
            if ( ( srch.equals && srch.equals(e) ) || e == srch) {
                found = true;
                return;
            }
        });
        return found;
    };
}

if (!Array.prototype.containsKey) {
    Array.prototype.containsKey = function(srch) {
        for ( var key in this ) {
            if ( key.toLowerCase() == srch.toLowerCase() ) {
                return true;
            }
        }
        return false;
    };
}

if (!Array.prototype.getCaseInsensitive) {
    Array.prototype.getCaseInsensitive = function(key) {
        for (var k in this) {
            if (k.toLowerCase() == key.toLowerCase()) {
                return this[k];
            }
        }
        return null;
    };
}

if (!String.prototype.charCodeAt) {
    String.prototype.charCodeAt = function( idx ) {
        var c = this.charAt(idx);
        for ( var i=0;i<65536;i++) {
            var s = String.fromCharCode(i);
            if ( s == c ) { return i; }
        }
        return 0;
    };
}
             
if (!String.prototype.endsWith) {
    String.prototype.endsWith = function( test ) {
        return this.substr( ( this.length - test.length ), test.length ) == test;
    };
}

if ( !Exception ) {
    var Exception = function( sMsg, oException ) {
        this.cause = oException;
        this.errorMessage = sMsg;
    };

    Exception.prototype = Error.prototype;

    Exception.prototype.getCause = function() { return this.cause; };

    Exception.prototype.getMessage = function() { return this.message; };

    Exception.prototype.getStackTrace = function() {
        if ( this.callstack ) {
            return this.callstack;
        }

        if ( this.stack ) {
            var lines = stack.split("\n");
            for ( var i=0, len=lines.length; i<len; i ++ ) {
                if ( lines[i].match( /^\s*[A-Za-z0-9\=+\$]+\(/ ) ) {
                    this.callstack.push(lines[i]);
                }
            }
            this.callstack.shift();
            return this.callstack;
        }
        else if ( window.opera && this.message ) {
            var lines = this.message.split('\n');
            for ( var i=0, len=lines.length; i<len; i++ ) {
                if ( lines[i].match( /^\s*[A-Za-z0-9\=+\$]+\(/ ) ) {
                    var entry = lines[i];
                    if ( lines[i+1] ) {
                        entry += " at " + lines[i+1];
                        i++;
                    }
                    this.callstack.push(entry);
                }
            }
            this.callstack.shift();
            return this.callstack;
        }
        else {
            var currentFunction = arguments.callee.caller;
            while ( currentFunction ) {
                var fn = currentFunction.toString();
                var fname = fn.substring(fn.indexOf("function")+8,fn.indexOf("(")) || "anonymous";
                this.callstack.push(fname);
                currentFunction = currentFunction.caller;
            }
            return this.callstack;
        }
    };

    Exception.prototype.printStackTrace = function( writer ) {
        var out = this.getMessage() + "|||" + this.getStackTrace().join( "|||" );

        if ( this.cause ) {
            if ( this.cause.printStackTrace ) {
                out += "||||||Caused by " + this.cause.printStackTrace().replace( "\n", "|||" );
            }
        }

        if ( !writer ) {
            return writer.replace( "|||", "\n" );
        } else if ( writer.value ) {
            writer.value = out.replace( "|||", "\n" );
        } else if ( writer.writeln ) {
            writer.writeln( out.replace( "|||", "\n" ) );
        } else if ( writer.innerHTML ) {
            writer.innerHTML = out.replace( "|||", "<br/>" );
        } else if ( writer.innerText ) {
            writer.innerText = out.replace( "|||", "<br/>" );
        } else if ( writer.append ) {
            writer.append( out.replace( "|||", "\n" ) );
        } else if ( writer instanceof Function ) {
            writer(out.replace( "|||", "\n" ) );
        }
    };
}

if ( !RuntimeException ) {
    var RuntimeException = Exception;
}

if ( !IllegalArgumentException ) {
    var IllegalArgumentException = Exception;
}

if ( !DateFormat ) {
    var DateFormat = function( sFmt ) {

        var fmt = sFmt;

        var replaceChars = {
            longMonths: [ "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" ],
            shortMonths: [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ],
            longDays: [ "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" ],
            shortDays: [ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" ],

            d: function(date) { return (date.getDate() < 10 ? '0' : '') + date.getDate(); },
            D: function(date) { return replaceChars.shortDays[date.getDay()]; },
            j: function(date) { return date.getDate(); },
            l: function(date) { return replaceChars.longDays[date.getDay()]; },
            N: function(date) { return date.getDay() + 1; },
            S: function(date) { return (date.getDate() % 10 == 1 && date.getDate() != 11 ? 'st' : (date.getDate() % 10 == 2 && date.getDate() != 12 ? 'nd' : (date.getDate() % 10 == 3 && date.getDate() != 13 ? 'rd' : 'th'))); },
            w: function(date) { return date.getDay(); },
            z: function(date) { return "Not Yet Supported"; },

            W: function(date) { return "Not Yet Supported"; },

            F: function(date) { return replaceChars.longMonths[date.getMonth()]; },
            m: function(date) { return (date.getMonth() < 9 ? '0' : '') + (date.getMonth() + 1); },
            M: function(date) { return replaceChars.shortMonths[date.getMonth()]; },
            n: function(date) { return date.getMonth() + 1; },
            t: function(date) { return "Not Yet Supported"; },

            L: function(date) { return (((date.getFullYear()%4==0)&&(date.getFullYear()%100 != 0)) || (date.getFullYear()%400==0)) ? '1' : '0'; },
            o: function(date) { return "Not Supported"; },
            Y: function(date) { return date.getFullYear(); },
            y: function(date) { return ('' + date.getFullYear()).substr(2); },

            a: function(date) { return date.getHours() < 12 ? 'am' : 'pm'; },
            A: function(date) { return date.getHours() < 12 ? 'AM' : 'PM'; },
            B: function(date) { return "Not Yet Supported"; },
            g: function(date) { return date.getHours() % 12 || 12; },
            G: function(date) { return date.getHours(); },
            h: function(date) { return ((date.getHours() % 12 || 12) < 10 ? '0' : '') + (date.getHours() % 12 || 12); },
            H: function(date) { return (date.getHours() < 10 ? '0' : '') + date.getHours(); },
            i: function(date) { return (date.getMinutes() < 10 ? '0' : '') + date.getMinutes(); },
            s: function(date) { return (date.getSeconds() < 10 ? '0' : '') + date.getSeconds(); },

            e: function(date) { return "Not Yet Supported"; },
            I: function(date) { return "Not Supported"; },
            O: function(date) { return (-date.getTimezoneOffset() < 0 ? '-' : '+') + (Math.abs(date.getTimezoneOffset() / 60) < 10 ? '0' : '') + (Math.abs(date.getTimezoneOffset() / 60)) + '00'; },
            P: function(date) { return (-date.getTimezoneOffset() < 0 ? '-' : '+') + (Math.abs(date.getTimezoneOffset() / 60) < 10 ? '0' : '') + (Math.abs(date.getTimezoneOffset() / 60)) + ':' + (Math.abs(date.getTimezoneOffset() % 60) < 10 ? '0' : '') + (Math.abs(date.getTimezoneOffset() % 60)); },
            T: function(date) { var m = date.getMonth(); date.setMonth(0); var result = date.toTimeString().replace(/^.+ \(?([^\)]+)\)?$/, '$1'); date.setMonth(m); return result;},
            Z: function(date) { return -date.getTimezoneOffset() * 60; },
         
            c: function(date) { return date.format("Y-m-d") + "T" + date.format("H:i:sP"); },
            r: function(date) { return date.toString(); },
            U: function(date) { return date.getTime() / 1000; }
        };


        return {
            format: function(oDate) {
                var out = '';
                for(var i=0;i<fmt.length;i++) {
                    var c = fmt.charAt(i);
                    if ( replaceChars[c] ) {
                        out += replaceChars[c].call(oDate);
                    } else {
                        out += c;
                    }
                }
                return out;
            }
        };
    };

    DateFormat.getDateInstance = function() {
        return new DateFormat("M/d/y h:i a");
    };
}

$namespace('com.cmus.antixss');

com.cmus.antixss.API = function( oProperties ) {
    var _properties = oProperties;

    if ( !_properties ) throw new RuntimeException("Configuration Error - Unable to load $API_Properties Object");

    var _encoder = null;
    var _validator = null;
    var _logFactory = null;
    var _resourceBundle = null;
    var _httputilities = null;

    return {
        properties: _properties,

        encoder: function() {
            if (!_encoder) {
                if (!_properties.encoder.Implementation) throw new RuntimeException('Configuration Error - $API.properties.encoder.Implementation object not found.');
                _encoder = new _properties.encoder.Implementation();
            }
            return _encoder;
        },

        logFactory: function() {
            if ( !_logFactory ) {
                if (!_properties.logging.Implementation) throw new RuntimeException('Configuration Error - $API.properties.logging.Implementation object not found.');
                _logFactory = new _properties.logging.Implementation();
            }
            return _logFactory;
        },

        logger: function(sModuleName) {
            return this.logFactory().getLogger(sModuleName);
        },

        locale: function() {
            return com.cmus.antixss.i18n.Locale.getLocale( _properties.localization.DefaultLocale );
        },

        resourceBundle: function() {
            if (!_resourceBundle) {
                if(!_properties.localization.StandardResourceBundle) throw new RuntimeException("Configuration Error - $API.properties.localization.StandardResourceBundle not found.");
                _resourceBundle = new com.cmus.antixss.i18n.ObjectResourceBundle( _properties.localization.StandardResourceBundle );
            }
            return _resourceBundle;
        },

        validator: function() {
            if (!_validator) {
                if (!_properties.validation.Implementation) throw new RuntimeException('Configuration Error - $API.properties.validation.Implementation object not found.');
                _validator = new _properties.validation.Implementation();
            }
            return _validator;
        },

        httpUtilities: function() {
            if (!_httputilities) _httputilities = new com.cmus.antixss.HTTPUtilities();
            return _httputilities;
        }
    };
};

var $API = null;

com.cmus.antixss.API.initialize = function() {
    $API = new com.cmus.antixss.API( Base.antixss.properties );
};

$namespace('com.cmus.antixss');

com.cmus.antixss.Encoder = function() {

}

$namespace('com.cmus.antixss');

com.cmus.antixss.EncoderConstants = {
    CHAR_LOWERS: [ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' ],
    CHAR_UPPERS: [ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' ],
    CHAR_DIGITS: [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ],
    CHAR_SPECIALS: [ '!', '$', '*', '+', '-', '.', '=', '?', '@', '^', '_', '|', '~' ],
    CHAR_LETTERS: [ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' ],
    CHAR_ALNUM: [ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ]
};

$namespace('com.cmus.antixss');

com.cmus.antixss.EnterpriseSecurityException = function(sUserMessage, sLogMessage, oException) {
    var _logMessage = sLogMessage;
    var _super = new Exception(sUserMessage, oException);

    return {
        getMessage: _super.getMessage,
        getUserMessage: _super.getMessage,
        getLogMessage: function() {
            return _logMessage;
        },
        getStackTrace: _super.getStackTrace,
        printStackTrace: _super.printStackTrace
    };
};

$namespace('com.cmus.antixss');

com.cmus.antixss.HTTPUtilities = function() {
    var log = $API.logger("HTTPUtilities");
    var resourceBundle = $API.resourceBundle();
    var EventType = com.cmus.antixss.Logger.EventType;

    return {
        addCookie: function( oCookie ) {
            $type(oCookie,com.cmus.antixss.net.Cookie);

            if ( window.top.location.protocol != 'http:' || window.top.location.protocol != 'https:' )
                throw new RuntimeException(resourceBundle.getString( "HTTPUtilities.Cookie.Protocol", {"protocol":window.top.location.protocol}));

            var name = oCookie.getName(),
                value = oCookie.getValue(),
                maxAge = oCookie.getMaxAge(),
                domain = oCookie.getDomain(),
                path = oCookie.getPath(),
                secure = oCookie.getSecure();

            var validationErrors = new com.cmus.antixss.ValidationErrorList();
            var cookieName = $API.validator().getValidInput("cookie name", name, "HttpCookieName", 50, false, validationErrors );
            var cookieValue = $API.validator().getValidInput("cookie value", value, "HttpCookieValue", 5000, false, validationErrors );

            if (validationErrors.size() == 0) {
                var header = name+'='+escape(value);
                header += maxAge?";expires=" + ( new Date( ( new Date() ).getTime() + ( 1000 * maxAge ) ).toGMTString() ) : "";
                header += path?";path="+path:"";
                header += domain?";domain="+domain:"";
                header += secure||$API.properties.httputilities.cookies.ForceSecure?";secure":"";
                document.cookie=header;
            }
            else
            {
                log.warning(EventType.SECURITY_FAILURE, resourceBundle.getString("HTTPUtilities.Cookie.UnsafeData", { 'name':name, 'value':value } ) );
            }
        },
        getCookie: function(sName) {
            var cookieJar = document.cookie.split("; ");
            for(var i=0,len=cookieJar.length;i<len;i++) {
                var cookie = cookieJar[i].split("=");
                if (cookie[0] == escape(sName)) {
                    return new com.cmus.antixss.net.Cookie( sName, cookie[1]?unescape(cookie[1]):'' );
                }
            }
            return null;
        },
        killAllCookies: function() {
            var cookieJar = document.cookie.split("; ");
            for(var i=0,len=cookieJar.length;i<len;i++) {
                var cookie = cookieJar[i].split("=");
                var name = unescape(cookie[0]);
                if (!this.killCookie(name)) {
                    throw new RuntimeException(resourceBundle.getString("HTTPUtilities.Cookie.CantKill", {"name":name}));
                }
            }
        },
        killCookie: function(sName) {
            var c = this.getCookie(sName);
            if ( c ) {
                c.setMaxAge( -10 );
                this.addCookie(c);
                if (this.getCookie(sName)) {
                    throw new RuntimeException(resourceBundle.getString("HTTPUtilities.Cookie.CantKill", {"name":sName}));
                }
                return true;
            }
            return false;
        },
        getRequestParameter: function( sName ) {
            var url = window.top.location.search.substring(1);
            var pIndex = url.indexOf(sName);
            if (pIndex<0) return null;
            pIndex=pIndex+sName.length;
            var lastIndex=url.indexOf("&",pIndex);
            if (lastIndex<0) lastIndex=url.length;
            return unescape(url.substring(pIndex,lastIndex));
        }
    };
};

$namespace('com.cmus.antixss');

com.cmus.antixss.IntrusionException = function(sUserMessage, sLogMessage, oCause) {
    var _super = new com.cmus.antixss.EnterpriseSecurityException(sUserMessage, sLogMessage, oCause);

    return {
        getMessage: _super.getMessage,
        getUserMessage: _super.getMessage,
        getLogMessage: _super.getLogMessage,
        getStackTrace: _super.getStackTrace,
        printStackTrace: _super.printStackTrace
    };
};

$namespace('com.cmus.antixss');

com.cmus.antixss.LogFactory = function() {
    return {
        getLogger: false
    };
}

$namespace('com.cmus.antixss');

com.cmus.antixss.Logger = function() {
    return {
        setLevel: false,
        fatal: false,
        error: false,
        isErrorEnabled: false,
        warning: false,
        isWarningEnabled: false,
        info: false,
        isInfoEnabled: false,
        debug: false,
        isDebugEnabled: false,
        trace: false,
        isTraceEnabled: false
    };
};

com.cmus.antixss.Logger.EventType = function( sName, bNewSuccess ) {
    var type = sName;
    var success = bNewSuccess;

    return {
        isSuccess: function() {
            return success;
        },

        toString: function() {
            return type;
        }
    };
};

with(com.cmus.antixss.Logger) {

    EventType.SECURITY_SUCCESS = new EventType( "SECURITY SUCCESS", true );
    EventType.SECURITY_FAILURE = new EventType( "SECURITY FAILURE", false );
    EventType.EVENT_SUCCESS    = new EventType( "EVENT SUCCESS", true );
    EventType.EVENT_FAILURE    = new EventType( "EVENT FAILURE", false );

    OFF = Number.MAX_VALUE;
    FATAL = 1000;
    ERROR = 800;
    WARNING = 600;
    INFO = 400;
    DEBUG = 200;
    TRACE = 100;
    ALL = Number.MIN_VALUE;
}

$namespace('com.cmus.antixss');

com.cmus.antixss.PreparedString = function(sTemplate, oCodec, sParameterCharacter) {
    var parts = [];
    var parameters = [];

    function split(s) {
        var idx = 0, pcount = 0;
        for (var i = 0; i < s.length; i ++) {
            if (s.charAt(i) == sParameterCharacter) {
                pcount ++;
                parts.push(s.substr(idx, i));
                idx = i + 1;
            }
        }
        parts.push(s.substr(idx));
        parameters = new Array(pcount);
    }

    ;

    if (!sParameterCharacter) {
        sParameterCharacter = '?';
    }

    split(sTemplate);

    return {
        set: function(iIndex, sValue, codec) {
            if (iIndex < 1 || iIndex > parameters.length) {
                throw new IllegalArgumentException("Attempt to set parameter: " + iIndex + " on a PreparedString with only " + parameters.length + " placeholders");
            }
            if (!codec) {
                codec = oCodec;
            }
            parameters[iIndex - 1] = codec.encode([], sValue);
        },

        toString: function() {
            for (var ix = 0; ix < parameters.length; ix ++) {
                if (parameters[ix] == null) {
                    throw new RuntimeException("Attempt to render PreparedString without setting parameter " + (ix + 1));
                }
            }
            var out = '', i = 0;
            for (var p = 0; p < parts.length; p ++) {
                out += parts[p];
                if (i < parameters.length) {
                    out += parameters[i++];
                }
            }
            return out;
        }
    };
};


$namespace('com.cmus.antixss');

com.cmus.antixss.ValidationErrorList = function() {
    var errorList = Array();

    return {
        addError: function( sContext, oValidationException ) {
            if ( sContext == null ) throw new RuntimeException( "Context cannot be null: " + oValidationException.getLogMessage(), oValidationException );
            if ( oValidationException == null ) throw new RuntimeException( "Context (" + sContext + ") - Error cannot be null" );
            if ( errorList[sContext] ) throw new RuntimeException( "Context (" + sContext + ") already exists. must be unique." );
            errorList[sContext] = oValidationException;
        },

        errors: function() {
            return errorList;
        },

        isEmpty: function() {
            return errorList.length == 0;
        },

        size: function() {
            return errorList.length;
        }
    };
};


$namespace('com.cmus.antixss');

com.cmus.antixss.ValidationRule = function() {
    return {
        getValid: false,
        setAllowNull: false,
        getTypeName: false,
        setTypeName: false,
        setEncoder: false,
        assertValid: false,
        getSafe: false,
        isValid: false,
        whitelist: false
    };
};


$namespace('com.cmus.antixss');

com.cmus.antixss.Validator = function() {
    return {
        addRule: false,
        getRule: false,
        getValidInput: false,
        isValidDate: false,
        getValidDate: false,
        isValidSafeHTML: false,
        getValidSafeHTML: false,
        isValidCreditCard: false,
        getValidCreditCard: false,
        isValidFilename: false,
        getValidFilename: false,
        isValidNumber: false,
        getValidNumber: false,
        isValidPrintable: false,
        getValidPrintable: false
    };
};


$namespace('com.cmus.antixss.codec.Base64');

com.cmus.antixss.codec.Base64 = {
    _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    encode: function(sInput) {
        if (!sInput) {
            return null;
        }

        var out = '';
        var ch1,ch2,ch3,enc1,enc2,enc3,enc4;
        var i = 0;

        var input = com.cmus.antixss.codec.UTF8.encode(sInput);

        while (i < input.length) {
            ch1 = input.charCodeAt(i++);
            ch2 = input.charCodeAt(i++);
            ch3 = input.charCodeAt(i++);

            enc1 = ch1 >> 2;
            enc2 = ((ch1 & 3) << 4) | (ch2 >> 4);
            enc3 = ((ch2 & 15) << 2) | (ch3 >> 6);
            enc4 = ch3 & 63;

            if (isNaN(ch2)) {
                enc3 = enc4 = 64;
            }
            else if (isNaN(ch3)) {
                enc4 = 64;
            }

            out += this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) + this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
        }

        return out;
    },

    decode: function(sInput) {
        if (!sInput) {
            return null;
        }

        var out = '';
        var ch1, ch2, ch3, enc1, enc2, enc3, enc4;
        var i = 0;

        var input = sInput.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        while (i < input.length) {
            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));

            ch1 = (enc1 << 2) | (enc2 >> 4);
            ch2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            ch3 = ((enc3 & 3) << 6) | enc4;

            out += String.fromCharCode(ch1);
            if (enc3 != 64) {
                out += String.fromCharCode(ch2);
            }
            if (enc4 != 64) {
                out += String.fromCharCode(ch3);
            }
        }

        out = com.cmus.antixss.codec.UTF8.decode(out);
        return out;
    }
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.CSSCodec = function() {
    var _super = new com.cmus.antixss.codec.Codec();

    return {
        encode: _super.encode,

        decode: _super.decode,

        encodeCharacter: function(aImmune, c) {
            if (aImmune.contains(c)) {
                return c;
            }

            var hex = com.cmus.antixss.codec.Codec.getHexForNonAlphanumeric(c);
            if (hex == null) {
                return c;
            }

            return "\\" + hex + " ";
        },

        decodeCharacter: function(oPushbackString) {
            oPushbackString.mark();
            var first = oPushbackString.next();
            if (first == null) {
                oPushbackString.reset();
                return null;
            }

            if (first != '\\') {
                oPushbackString.reset();
                return null;
            }

            var second = oPushbackString.next();
            if (second == null) {
                oPushbackString.reset();
                return null;
            }

            if (oPushbackString.isHexDigit(second)) {
                var out = second;
                for (var i = 0; i < 6; i ++) {
                    var c = oPushbackString.next();
                    if (c == null || c.charCodeAt(0) == 0x20) {
                        break;
                    }
                    if (oPushbackString.isHexDigit(c)) {
                        out += c;
                    } else {
                        input.pushback(c);
                        break;
                    }
                }

                try {
                    var n = parseInt(out, 16);
                    return String.fromCharCode(n);
                } catch (e) {
                    oPushbackString.reset();
                    return null;
                }
            }

            return second;
        }
    };
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.Codec = function() {
    return {
        encode: function(aImmune, sInput) {
            var out = '';
            for (var i = 0; i < sInput.length; i ++) {
                var c = sInput.charAt(i);
                out += this.encodeCharacter(aImmune, c);
            }
            return out;
        },
        encodeCharacter: function(aImmune, c) {
            return c;
        },
        decode: function(sInput) {
            var out = '';
            var pbs = new com.cmus.antixss.codec.PushbackString(sInput);
            while (pbs.hasNext()) {
                var c = this.decodeCharacter(pbs);
                if (c != null) {
                    out += c;
                } else {
                    out += pbs.next();
                }
            }
            return out;
        },
        decodeCharacter: function(oPushbackString) {
            return oPushbackString.next();
        }
    };
};

com.cmus.antixss.codec.Codec.getHexForNonAlphanumeric = function(c) {
    if (c.charCodeAt(0) < 256) {
        return com.cmus.antixss.codec.Codec.hex[c.charCodeAt(0)];
    }
    return c.charCodeAt(0).toString(16);
};

com.cmus.antixss.codec.Codec.hex = [];
for ( var c = 0; c < 0xFF; c ++ ) {
    if ( c >= 0x30 && c <= 0x39 || c>= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
        com.cmus.antixss.codec.Codec.hex[c] = null;
    } else {
        com.cmus.antixss.codec.Codec.hex[c] = c.toString(16);
    }
};

var entityToCharacterMap = [];
entityToCharacterMap["&quot"]        = "34";      
entityToCharacterMap["&amp"]         = "38";      
entityToCharacterMap["&lt"]          = "60";      
entityToCharacterMap["&gt"]          = "62";      
entityToCharacterMap["&nbsp"]        = "160";     
entityToCharacterMap["&iexcl"]       = "161";     
entityToCharacterMap["&cent"]			= "162";	
entityToCharacterMap["&pound"]			= "163";	
entityToCharacterMap["&curren"]			= "164";	
entityToCharacterMap["&yen"]			= "165";	
entityToCharacterMap["&brvbar"]			= "166";	
entityToCharacterMap["&sect"]			= "167";	
entityToCharacterMap["&uml"]			= "168";	
entityToCharacterMap["&copy"]			= "169";	
entityToCharacterMap["&ordf"]			= "170";	
entityToCharacterMap["&laquo"]          = "171";
entityToCharacterMap["&not"]			= "172";	
entityToCharacterMap["&shy"]			= "173";	
entityToCharacterMap["&reg"]			= "174";	
entityToCharacterMap["&macr"]			= "175";	
entityToCharacterMap["&deg"]			= "176";	
entityToCharacterMap["&plusmn"]         = "177";  
entityToCharacterMap["&sup2"]			= "178";	
entityToCharacterMap["&sup3"]			= "179";	
entityToCharacterMap["&acute"]			= "180";	
entityToCharacterMap["&micro"]			= "181";	
entityToCharacterMap["&para"]			= "182";	
entityToCharacterMap["&middot"]			= "183";	
entityToCharacterMap["&cedil"]			= "184";	
entityToCharacterMap["&sup1"]			= "185";	
entityToCharacterMap["&ordm"]			= "186";	
entityToCharacterMap["&raquo"]          = "187"; 
entityToCharacterMap["&frac14"]			= "188";	
entityToCharacterMap["&frac12"]			= "189";	
entityToCharacterMap["&frac34"]			= "190";	
entityToCharacterMap["&iquest"]			= "191";	
entityToCharacterMap["&Agrave"]			= "192";	
entityToCharacterMap["&Aacute"]			= "193";	
entityToCharacterMap["&Acirc"]			= "194";	
entityToCharacterMap["&Atilde"]			= "195";	
entityToCharacterMap["&Auml"]			= "196";	
entityToCharacterMap["&Aring"]			= "197";	
entityToCharacterMap["&AElig"]			= "198";	
entityToCharacterMap["&Ccedil"]			= "199";	
entityToCharacterMap["&Egrave"]			= "200";	
entityToCharacterMap["&Eacute"]			= "201";	
entityToCharacterMap["&Ecirc"]			= "202";	
entityToCharacterMap["&Euml"]			= "203";	
entityToCharacterMap["&Igrave"]			= "204";	
entityToCharacterMap["&Iacute"]			= "205";	
entityToCharacterMap["&Icirc"]			= "206";	
entityToCharacterMap["&Iuml"]			= "207";	
entityToCharacterMap["&ETH"]			    = "208";
entityToCharacterMap["&Ntilde"]			= "209";	
entityToCharacterMap["&Ograve"]			= "210";	
entityToCharacterMap["&Oacute"]			= "211";	
entityToCharacterMap["&Ocirc"]           = "212";
entityToCharacterMap["&Otilde"]			= "213";	
entityToCharacterMap["&Ouml"]			= "214";	
entityToCharacterMap["&times"]			= "215";	
entityToCharacterMap["&Oslash"]			= "216";	
entityToCharacterMap["&Ugrave"]			= "217";	
entityToCharacterMap["&Uacute"]			= "218";	
entityToCharacterMap["&Ucirc"]			= "219";	
entityToCharacterMap["&Uuml"]			= "220";	
entityToCharacterMap["&Yacute"]			= "221";	
entityToCharacterMap["&THORN"]			= "222";	
entityToCharacterMap["&szlig"]           = "223";   
entityToCharacterMap["&agrave"]			= "224";	
entityToCharacterMap["&aacute"]			= "225";	
entityToCharacterMap["&acirc"]			= "226";	
entityToCharacterMap["&atilde"]			= "227";	
entityToCharacterMap["&auml"]			= "228";	
entityToCharacterMap["&aring"]			= "229";	
entityToCharacterMap["&aelig"]			= "230";	
entityToCharacterMap["&ccedil"]			= "231";	
entityToCharacterMap["&egrave"]			= "232";	
entityToCharacterMap["&eacute"]			= "233";	
entityToCharacterMap["&ecirc"]			= "234";	
entityToCharacterMap["&euml"]			= "235";	
entityToCharacterMap["&igrave"]			= "236";	
entityToCharacterMap["&iacute"]			= "237";	
entityToCharacterMap["&icirc"]			= "238";	
entityToCharacterMap["&iuml"]			= "239";	
entityToCharacterMap["&eth"]			    = "240";
entityToCharacterMap["&ntilde"]			= "241";	
entityToCharacterMap["&ograve"]			= "242";	
entityToCharacterMap["&oacute"]			= "243";	
entityToCharacterMap["&ocirc"]			= "244";	
entityToCharacterMap["&otilde"]			= "245";	
entityToCharacterMap["&ouml"]			= "246";	
entityToCharacterMap["&divide"]			= "247";	
entityToCharacterMap["&oslash"]			= "248";	
entityToCharacterMap["&ugrave"]			= "249";	
entityToCharacterMap["&uacute"]			= "250";	
entityToCharacterMap["&ucirc"]			= "251";	
entityToCharacterMap["&uuml"]			= "252";	
entityToCharacterMap["&yacute"]			= "253";	
entityToCharacterMap["&thorn"]			= "254";	
entityToCharacterMap["&yuml"]			= "255";	
entityToCharacterMap["&OElig"]			= "338";	
entityToCharacterMap["&oelig"]			= "339";	
entityToCharacterMap["&Scaron"]			= "352";	
entityToCharacterMap["&scaron"]			= "353";	
entityToCharacterMap["&Yuml"]			= "376";	
entityToCharacterMap["&fnof"]			= "402";	
entityToCharacterMap["&circ"]			= "710";	
entityToCharacterMap["&tilde"]			= "732";	
entityToCharacterMap["&Alpha"]			= "913";	
entityToCharacterMap["&Beta"]			= "914";	
entityToCharacterMap["&Gamma"]			= "915";	
entityToCharacterMap["&Delta"]			= "916";	
entityToCharacterMap["&Epsilon"]			= "917";
entityToCharacterMap["&Zeta"]			= "918";	
entityToCharacterMap["&Eta"]			    = "919";
entityToCharacterMap["&Theta"]			= "920";	
entityToCharacterMap["&Iota"]			= "921";	
entityToCharacterMap["&Kappa"]			= "922";	
entityToCharacterMap["&Lambda"]			= "923";	
entityToCharacterMap["&Mu"]			= "924";	
entityToCharacterMap["&Nu"]			= "925";	
entityToCharacterMap["&Xi"]			= "926";	
entityToCharacterMap["&Omicron"]			= "927";
entityToCharacterMap["&Pi"]			= "928";	 
entityToCharacterMap["&Rho"]			= "929";	 
entityToCharacterMap["&Sigma"]			= "931";	 
entityToCharacterMap["&Tau"]			= "932";	 
entityToCharacterMap["&Upsilon"]			= "933";
entityToCharacterMap["&Phi"]			= "934";	 
entityToCharacterMap["&Chi"]			= "935";	 
entityToCharacterMap["&Psi"]			= "936";	 
entityToCharacterMap["&Omega"]			= "937";	 
entityToCharacterMap["&alpha"]			= "945";	 
entityToCharacterMap["&beta"]			= "946";	 
entityToCharacterMap["&gamma"]			= "947";	 
entityToCharacterMap["&delta"]			= "948";	 
entityToCharacterMap["&epsilon"]			= "949";
entityToCharacterMap["&zeta"]			= "950";	 
entityToCharacterMap["&eta"]			= "951";	 
entityToCharacterMap["&theta"]			= "952";	 
entityToCharacterMap["&iota"]			= "953";	 
entityToCharacterMap["&kappa"]			= "954";	 
entityToCharacterMap["&lambda"]			= "955";	 
entityToCharacterMap["&mu"]			= "956";	
entityToCharacterMap["&nu"]			= "957";	
entityToCharacterMap["&xi"]			= "958";	
entityToCharacterMap["&omicron"]			= "959";
entityToCharacterMap["&pi"]			= "960";	
entityToCharacterMap["&rho"]			= "961";	 
entityToCharacterMap["&sigmaf"]			= "962";	 
entityToCharacterMap["&sigma"]			= "963";	 
entityToCharacterMap["&tau"]			= "964";	 
entityToCharacterMap["&upsilon"]			= "965";
entityToCharacterMap["&phi"]			= "966";	 
entityToCharacterMap["&chi"]			= "967";	 
entityToCharacterMap["&psi"]			= "968";	 
entityToCharacterMap["&omega"]			= "969";	 
entityToCharacterMap["&thetasym"]			= "977";
entityToCharacterMap["&upsih"]			= "978";	 
entityToCharacterMap["&piv"]			= "982";	
entityToCharacterMap["&ensp"]			= "8194";	
entityToCharacterMap["&emsp"]			= "8195";	
entityToCharacterMap["&thinsp"]			= "8201";	
entityToCharacterMap["&zwnj"]            = "8204"; 
entityToCharacterMap["&zwj"]			= "8205";	
entityToCharacterMap["&lrm"]             = "8206"; 
entityToCharacterMap["&rlm"]             = "8207"; 
entityToCharacterMap["&ndash"]			= "8211";	
entityToCharacterMap["&mdash"]			= "8212";	
entityToCharacterMap["&lsquo"]			= "8216";	
entityToCharacterMap["&rsquo"]			= "8217";	
entityToCharacterMap["&sbquo"]           = "8218"; 
entityToCharacterMap["&ldquo"]			= "8220";	
entityToCharacterMap["&rdquo"]			= "8221";	
entityToCharacterMap["&bdquo"]           = "8222"; 
entityToCharacterMap["&dagger"]			= "8224";	
entityToCharacterMap["&Dagger"]			= "8225";	
entityToCharacterMap["&bull"]			= "8226";	
entityToCharacterMap["&hellip"]			= "8230";	
entityToCharacterMap["&permil"]			= "8240";	
entityToCharacterMap["&prime"]			= "8242";	
entityToCharacterMap["&Prime"]			= "8243";	
entityToCharacterMap["&lsaquo"]          = "8249"; 
entityToCharacterMap["&rsaquo"]          = "8250"; 
entityToCharacterMap["&oline"]			= "8254";	
entityToCharacterMap["&frasl"]			= "8260";	
entityToCharacterMap["&euro"]			= "8364";	
entityToCharacterMap["&image"]           = "8365"; 
entityToCharacterMap["&weierp"]          = "8472"; 
entityToCharacterMap["&real"]            = "8476"; 
entityToCharacterMap["&trade"]			= "8482";	
entityToCharacterMap["&alefsym"]			= "8501";	 
entityToCharacterMap["&larr"]			= "8592";
entityToCharacterMap["&uarr"]			= "8593";
entityToCharacterMap["&rarr"]			= "8594";
entityToCharacterMap["&darr"]			= "8595";
entityToCharacterMap["&harr"]			= "8596";
entityToCharacterMap["&crarr"]			= "8629";
entityToCharacterMap["&lArr"]			= "8656";
entityToCharacterMap["&uArr"]			= "8657";
entityToCharacterMap["&rArr"]			= "8658";
entityToCharacterMap["&dArr"]			= "8659";
entityToCharacterMap["&hArr"]			= "8660";
entityToCharacterMap["&forall"]			= "8704";
entityToCharacterMap["&part"]			= "8706";
entityToCharacterMap["&exist"]			= "8707";
entityToCharacterMap["&empty"]			= "8709";
entityToCharacterMap["&nabla"]			= "8711";
entityToCharacterMap["&isin"]			= "8712";
entityToCharacterMap["&notin"]			= "8713";
entityToCharacterMap["&ni"]			    = "8715";
entityToCharacterMap["&prod"]            = "8719";
entityToCharacterMap["&sum"]             = "8721";
entityToCharacterMap["&minus"]			= "8722";
entityToCharacterMap["&lowast"]			= "8727";
entityToCharacterMap["&radic"]			= "8730";
entityToCharacterMap["&prop"]			= "8733";
entityToCharacterMap["&infin"]			= "8734";
entityToCharacterMap["&ang"]			= "8736";
entityToCharacterMap["&and"]			= "8743";
entityToCharacterMap["&or"]			= "8744";	 
entityToCharacterMap["&cap"]			= "8745";
entityToCharacterMap["&cup"]			= "8746";
entityToCharacterMap["&int"]			= "8747";
entityToCharacterMap["&there4"]			= "8756";
entityToCharacterMap["&sim"]			= "8764";
entityToCharacterMap["&cong"]			= "8773";
entityToCharacterMap["&asymp"]			= "8776";	
entityToCharacterMap["&ne"]			= "8800";	 
entityToCharacterMap["&equiv"]           = "8801";  
entityToCharacterMap["&le"]              = "8804";
entityToCharacterMap["&ge"]              = "8805";
entityToCharacterMap["&sub"]			= "8834";	
entityToCharacterMap["&sup"]			= "8835";	
entityToCharacterMap["&nsub"]			= "8836";	
entityToCharacterMap["&sube"]			= "8838";	
entityToCharacterMap["&supe"]			= "8839";	
entityToCharacterMap["&oplus"]			= "8853";	
entityToCharacterMap["&otimes"]			= "8855";	
entityToCharacterMap["&perp"]			= "8869";	
entityToCharacterMap["&sdot"]			= "8901";	
entityToCharacterMap["&lceil"]			= "8968";	
entityToCharacterMap["&rceil"]			= "8969";	
entityToCharacterMap["&lfloor"]			= "8970";	
entityToCharacterMap["&rfloor"]			= "8971";	
entityToCharacterMap["&lang"]            = "9001";  
entityToCharacterMap["&rang"]            = "9002";  
entityToCharacterMap["&loz"]			= "9674";	
entityToCharacterMap["&spades"]			= "9824";	
entityToCharacterMap["&clubs"]			= "9827";	
entityToCharacterMap["&hearts"]			= "9829";	
entityToCharacterMap["&diams"]			= "9830";	

var characterToEntityMap = [];

for ( var entity in entityToCharacterMap ) {
    characterToEntityMap[entityToCharacterMap[entity]] = entity;
}

$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.HTMLEntityCodec = function() {
    var _super = new com.cmus.antixss.codec.Codec();

    var getNumericEntity = function(input) {
        var first = input.peek();
        if (first == null) {
            return null;
        }

        if (first == 'x' || first == 'X') {
            input.next();
            return parseHex(input);
        }
        return parseNumber(input);
    };

    var parseNumber = function(input) {
        var out = '';
        while (input.hasNext()) {
            var c = input.peek();
            if (c.match(/[0-9]/)) {
                out += c;
                input.next();
            } else if (c == ';') {
                input.next();
                break;
            } else {
                break;
            }
        }

        try {
            return parseInt(out);
        } catch (e) {
            return null;
        }
    };

    var parseHex = function(input) {
        var out = '';
        while (input.hasNext()) {
            var c = input.peek();
            if (c.match(/[0-9A-Fa-f]/)) {
                out += c;
                input.next();
            } else if (c == ';') {
                input.next();
                break;
            } else {
                break;
            }
        }
        try {
            return parseInt(out, 16);
        } catch (e) {
            return null;
        }
    };

    var getNamedEntity = function(input) {
        var entity = '';
        while (input.hasNext()) {
            var c = input.peek();
            if (c.match(/[A-Za-z]/)) {
                entity += c;
                input.next();
                if (entityToCharacterMap.containsKey('&' + entity)) {
                    if (input.peek(';')) input.next();
                    break;
                }
            } else if (c == ';') {
                input.next();
            } else {
                break;
            }
        }

        return String.fromCharCode(entityToCharacterMap.getCaseInsensitive('&' + entity));
    };

    return {
        encode: _super.encode,

        decode: _super.decode,

        encodeCharacter: function(aImmune, c) {
            if (aImmune.contains(c)) {
                return c;
            }

            var hex = com.cmus.antixss.codec.Codec.getHexForNonAlphanumeric(c);
            if (hex == null) {
                return c;
            }

            var cc = c.charCodeAt(0);
            if (( cc <= 0x1f && c != '\t' && c != '\n' && c != '\r' ) || ( cc >= 0x7f && cc <= 0x9f ) || c == ' ') {
                return " ";
            }

            var entityName = characterToEntityMap[cc];
            if (entityName != null) {
                return entityName + ";";
            }

            return "&#x" + hex + ";";
        },

        decodeCharacter: function(oPushbackString) {
            var input = oPushbackString;
            input.mark();
            var first = input.next();
            if (first == null || first != '&') {
                input.reset();
                return null;
            }

            var second = input.next();
            if (second == null) {
                input.reset();
                return null;
            }

            if (second == '#') {
                var c = getNumericEntity(input);
                if (c != null) {
                    return c;
                }
            } else if (second.match(/[A-Za-z]/)) {
                input.pushback(second);
                c = getNamedEntity(input);
                if (c != null) {
                    return c;
                }
            }
            input.reset();
            return null;
        }
    };
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.JavascriptCodec = function() {
    var _super = new com.cmus.antixss.codec.Codec();

    return {
        encode: function(aImmune, sInput) {
            var out = '';
            for (var idx = 0; idx < sInput.length; idx ++) {
                var ch = sInput.charAt(idx);
                if (aImmune.contains(ch)) {
                    out += ch;
                }
                else {
                    var hex = com.cmus.antixss.codec.Codec.getHexForNonAlphanumeric(ch);
                    if (hex == null) {
                        out += ch;
                    }
                    else {
                        var tmp = ch.charCodeAt(0).toString(16);
                        if (ch.charCodeAt(0) < 256) {
                            var pad = "00".substr(tmp.length);
                            out += "\\x" + pad + tmp.toUpperCase();
                        }
                        else {
                            pad = "0000".substr(tmp.length);
                            out += "\\u" + pad + tmp.toUpperCase();
                        }
                    }
                }
            }
            return out;
        },

        decode: _super.decode,

        decodeCharacter: function(oPushbackString) {
            oPushbackString.mark();
            var first = oPushbackString.next();
            if (first == null) {
                oPushbackString.reset();
                return null;
            }

            if (first != '\\') {
                oPushbackString.reset();
                return null;
            }

            var second = oPushbackString.next();
            if (second == null) {
                oPushbackString.reset();
                return null;
            }

            if (second == 'b') {
                return 0x08;
            } else if (second == 't') {
                return 0x09;
            } else if (second == 'n') {
                return 0x0a;
            } else if (second == 'v') {
                return 0x0b;
            } else if (second == 'f') {
                return 0x0c;
            } else if (second == 'r') {
                return 0x0d;
            } else if (second == '\"') {
                return 0x22;
            } else if (second == '\'') {
                return 0x27;
            } else if (second == '\\') {
                return 0x5c;
            } else if (second.toLowerCase() == 'x') {
                out = '';
                for (var i = 0; i < 2; i++) {
                    var c = oPushbackString.nextHex();
                    if (c != null) {
                        out += c;
                    } else {
                        input.reset();
                        return null;
                    }
                }
                try {
                    n = parseInt(out, 16);
                    return String.fromCharCode(n);
                } catch (e) {
                    oPushbackString.reset();
                    return null;
                }
            } else if (second.toLowerCase() == 'u') {
                out = '';
                for (i = 0; i < 4; i++) {
                    c = oPushbackString.nextHex();
                    if (c != null) {
                        out += c;
                    } else {
                        input.reset();
                        return null;
                    }
                }
                try {
                    var n = parseInt(out, 16);
                    return String.fromCharCode(n);
                } catch (e) {
                    oPushbackString.reset();
                    return null;
                }
            } else if (oPushbackString.isOctalDigit(second)) {
                var out = second;
                var c2 = oPushbackString.next();
                if (!oPushbackString.isOctalDigit(c2)) {
                    oPushbackString.pushback(c2);
                } else {
                    out += c2;
                    var c3 = oPushbackString.next();
                    if (!oPushbackString.isOctalDigit(c3)) {
                        oPushbackString.pushback(c3);
                    } else {
                        out += c3;
                    }
                }

                try {
                    n = parseInt(out, 8);
                    return String.fromCharCode(n);
                } catch (e) {
                    oPushbackString.reset();
                    return null;
                }
            }
            return second;
        }
    };
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.PercentCodec = function() {
    var _super = new com.cmus.antixss.codec.Codec();

    var ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var RFC_NON_ALPHANUMERIC_UNRESERVED_STR = "-._~";
    var ENCODED_NON_ALPHA_NUMERIC_UNRESERVED = true;
    var UNENCODED_STR = ALPHA_NUMERIC_STR + (ENCODED_NON_ALPHA_NUMERIC_UNRESERVED ? "" : RFC_NON_ALPHANUMERIC_UNRESERVED_STR);

    var getTwoUpperBytes = function(b) {
        var out = '';
        if (b < -128 || b > 127) {
            throw new IllegalArgumentException("b is not a byte (was " + b + ")");
        }
        b &= 0xFF;
        if (b < 0x10) {
            out += '0';
        }
        return out + b.toString(16).toUpperCase();
    };

    return {
        encode: _super.encode,

        decode: _super.decode,

        encodeCharacter: function(aImmune, c) {
            if (UNENCODED_STR.indexOf(c) > -1) {
                return c;
            }

            var bytes = com.cmus.antixss.codec.UTF8.encode(c);
            var out = '';
            for (var b = 0; b < bytes.length; b++) {
                out += '%' + getTwoUpperBytes(bytes.charCodeAt(b));
            }
            return out;
        },

        decodeCharacter: function(oPushbackString) {
            oPushbackString.mark();
            var first = oPushbackString.next();
            if (first == null || first != '%') {
                oPushbackString.reset();
                return null;
            }

            var out = '';
            for (var i = 0; i < 2; i++) {
                var c = oPushbackString.nextHex();
                if (c != null) {
                    out += c;
                }
            }
            if (out.length == 2) {
                try {
                    var n = parseInt(out, 16);
                    return String.fromCharCode(n);
                } catch (e) {
                }
            }
            oPushbackString.reset();
            return null;
        }
    };
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.PushbackString = function(sInput) {
    var _input = sInput,
            _pushback = '',
            _temp = '',
            _index = 0,
            _mark = 0;

    return {
        pushback: function(c) {
            _pushback = c;
        },

        index: function() {
            return _index;
        },

        hasNext: function() {
            if (_pushback != null) return true;
            return !(_input == null || _input.length == 0 || _index >= _input.length);

        },

        next: function() {
            if (_pushback != null) {
                var save = _pushback;
                _pushback = null;
                return save;
            }
            if (_input == null || _input.length == 0 || _index >= _input.length) {
                return null;
            }
            return _input.charAt(_index++);
        },

        nextHex: function() {
            var c = this.next();
            if (this.isHexDigit(c)) return c;
            return null;
        },

        nextOctal: function() {
            var c = this.next();
            if (this.isOctalDigit(c)) return c;
            return null;
        },

        isHexDigit: function(c) {
            return c != null && ( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ) || ( c >= 'A' && c <= 'F' ) );
        },

        isOctalDigit: function(c) {
            return c != null && ( c >= '0' && c <= '7' );
        },

        peek: function(c) {
            if (!c) {
                if (_pushback != null) return _pushback;
                if (_input == null || _input.length == 0 || _index >= _input.length) return null;
                return _input.charAt(_index);
            } else {
                if (_pushback != null && _pushback == c) return true;
                if (_input == null || _input.length == 0 || _index >= _input.length) return false;
                return _input.charAt(_index) == c;
            }
        },

        mark: function() {
            _temp = _pushback;
            _mark = _index;
        },

        reset: function() {
            _pushback = _temp;
            _index = _mark;
        },

        remainder: function() {
            var out = _input.substr(_index);
            if (_pushback != null) {
                out = _pushback + out;
            }
            return out;
        }
    };
};


$namespace('com.cmus.antixss.codec');

com.cmus.antixss.codec.UTF8 = {
    encode: function(sInput) {
        var input = sInput.replace(/\r\n/g, "\n");
        var utftext = '';

        for (var n = 0; n < input.length; n ++) {
            var c = input.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if (( c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }

        return utftext;
    }
    ,

    decode: function(sInput) {
        var out = '';
        var i = c = c1 = c2 = 0;

        while (i < sInput.length) {
            c = sInput.charCodeAt(i);

            if (c < 128) {
                out += String.fromCharCode(c);
                i ++;
            }
            else if ((c > 191) && (c < 224)) {
                c2 = sInput.charCodeAt(i + 1);
                out += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i + 1);
                c3 = utftext.charCodeAt(i + 2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
        }

        return out;
    }
};


$namespace('com.cmus.antixss.i18n');

com.cmus.antixss.i18n.ArrayResourceBundle = function( sName, oLocale, aMessages, oParent ) {
    with(com.cmus.antixss.i18n) var _super = new ResourceBundle( sName, oLocale, oParent );

    var messages = aMessages;

    return {
        getParent: _super.getParent,
        getLocale: _super.getLocale,
        getName: _super.getName,
        getString: _super.getString,
        getMessage: function(sKey) {
            return messages[sKey];
        }
    };
};


$namespace('com.cmus.antixss.i18n');

com.cmus.antixss.i18n.Locale = function( sLanguage, sCountry, sVariant ) {
    var language = sLanguage, country = sCountry, variant = sVariant;

    return {
        getLanguage: function() { return language; },
        getCountry: function() { return country; },
        getVariant: function() { return variant; },
        toString: function() { return language + ( country ? "-" + country + ( variant ? "-" + variant : "" ) : "" ); }
    };
};

com.cmus.antixss.i18n.Locale.US = new com.cmus.antixss.i18n.Locale("en","US");
com.cmus.antixss.i18n.Locale.GB = new com.cmus.antixss.i18n.Locale("en","GB");

com.cmus.antixss.i18n.Locale.getLocale = function(sLocale) {
    var l = sLocale.split("-");
    return new com.cmus.antixss.i18n.Locale( l[0], (l.length>1?l[1]:""), (l.length>2?l.length[2]:""));
};

com.cmus.antixss.i18n.Locale.getDefault = function() {
    var l = (navigator['language']?navigator['language']:(navigator['userLanguage']?navigator['userLanguage']:'en-US')).split("-");
    return new com.cmus.antixss.i18n.Locale( l[0], (l.length>1?l[1]:""), (l.length>2?l.length[2]:""));
};


$namespace('com.cmus.antixss.i18n');

com.cmus.antixss.i18n.ObjectResourceBundle = function( oResource, oParent ) {
    var _super = new com.cmus.antixss.i18n.ResourceBundle( oResource.name, com.cmus.antixss.i18n.Locale.getLocale(oResource.locale), oParent );

    var messages = oResource.messages;

    return {
        getParent: _super.getParent,
        getLocale: _super.getLocale,
        getName: _super.getName,
        getString: _super.getString,
        getMessage: function(sKey) {
            return messages[sKey];
        }
    };
};


$namespace('com.cmus.antixss.i18n');

com.cmus.antixss.i18n.ResourceBundle = function( sName, oLocale, oParentResourceBundle ) {
    var parent = oParentResourceBundle;
    var locale = oLocale;
    var name = sName;

    if ( !name ) throw new SyntaxError("Name required for implementations of com.cmus.antixss.i18n.ResourceBundle");
    if ( !locale ) throw new SyntaxError("Locale required for implementations of com.cmus.antixss.i18n.ResourceBundle");

    return {
        getParent: function() { return parent; },
        getLocale: function() { return locale; },
        getName: function() { return name; },
        getMessage: function(sKey) { return sKey; },
        getString: function( sKey, oContextMap ) {
            if ( arguments.length < 1 ) {
                throw new IllegalArgumentException("No key passed to getString");
            }

            var msg = this.getMessage(sKey);
            if ( !msg ) {
                if ( parent ) {
                    return parent.getString( sKey, oContextMap );
                } else {
                    return sKey;
                }
            }

            if ( !msg.match( /\{([A-Za-z]+)\}/ ) || !oContextMap ) {
                return msg;
            }

            var out = '', lastIndex = 0;
            while (true) {
                var nextVarIdx = msg.indexOf( "{", lastIndex );
                var endIndex = msg.indexOf( "}", nextVarIdx );

                if ( nextVarIdx < 0 ) {
                    out += msg.substr( lastIndex, msg.length-lastIndex );
                    break;
                }

                if ( nextVarIdx >= 0 && endIndex < -1 ) {
                    throw new SyntaxError("Invalid Message - Unclosed Context Reference: " + msg );
                }

                out += msg.substring( lastIndex, nextVarIdx );
                var contextKey = msg.substring( nextVarIdx+1, endIndex );
                if ( oContextMap[contextKey] ) {
                    out += oContextMap[contextKey];
                } else {
                    out += msg.substring( nextVarIdx, endIndex+1 );
                }

                lastIndex = endIndex + 1;
            }

            return out;
        }
    };
};

com.cmus.antixss.i18n.ResourceBundle.getResourceBundle = function(sResource, oLocale) {
    var classname = sResource + "_" + oLocale.toString().replace("-","_");

    with( com.cmus.antixss.i18n ) {
        if ( ResourceBundle[classname] instanceof Object ) {
            return ResourceBundle[classname];
        } else {
            return new ResourceBundle[classname]();
        }
    }
};

$namespace('com.cmus.antixss.net');

com.cmus.antixss.net.Cookie = function( sName, sValue ) {
    var name;    
    var value;   

    var comment; 
    var domain;  
    var maxAge;  
    var path;    
    var secure;  
    var version; 

    var _resourceBundle = $API.resourceBundle();

    var tSpecials = ",; ";

    var isToken = function(sValue) {
        for(var i=0,len=sValue.length;i<len;i++) {
            var cc = sValue.charCodeAt(i),c=sValue.charAt(i);
            if (cc<0x20||cc>=0x7F||tSpecials.indexOf(c)!=-1) {
                return false;
            }
        }
        return true;
    };

    if ( !isToken(sName)
            || sName.toLowerCase() == 'comment'
            || sName.toLowerCase() == 'discard'
            || sName.toLowerCase() == 'domain'
            || sName.toLowerCase() == 'expires'
            || sName.toLowerCase() == 'max-age'
            || sName.toLowerCase() == 'path'
            || sName.toLowerCase() == 'secure'
            || sName.toLowerCase() == 'version'
            || sName.charAt(0) == '$' ) {
        var errMsg = _resourceBundle.getString( "Cookie.Name", { 'name':sName } );
        throw new IllegalArgumentException(errMsg);
    }

    name = sName;
    value = sValue;

    return {
        setComment: function(purpose) { comment = purpose; },
        getComment: function() { return comment; },
        setDomain: function(sDomain) { domain = sDomain.toLowerCase(); },
        getDomain: function() { return domain; },
        setMaxAge: function(nExpirey) { maxAge = nExpirey; },
        getMaxAge: function() { return maxAge; },
        setPath: function(sPath) { path = sPath; },
        getPath: function() { return path; },
        setSecure: function(bSecure) { secure = bSecure; },
        getSecure: function() { return secure; },
        getName: function() { return name; },
        setValue: function(sValue) { value = sValue; },
        getValue: function() { return value; },
        setVersion: function(nVersion) {
            if(nVersion<0||nVersion>1)throw new IllegalArgumentException(_resourceBundle.getString("Cookie.Version", { 'version':nVersion } ) );
            version = nVersion;
        },
        getVersion: function() { return version; }
    };
};

$namespace('com.cmus.antixss.reference.encoding');

com.cmus.antixss.reference.encoding.DefaultEncoder = function(aCodecs) {
    var _codec = [],
            _htmlCodec = new com.cmus.antixss.codec.HTMLEntityCodec(),
            _javascriptCodec = new com.cmus.antixss.codec.JavascriptCodec(),
            _cssCodec = new com.cmus.antixss.codec.CSSCodec(),
            _percentCodec = new com.cmus.antixss.codec.PercentCodec();

    if (!aCodecs) {
        _codec.push(_htmlCodec);
        _codec.push(_javascriptCodec);
        _codec.push(_cssCodec);
        _codec.push(_percentCodec);
    } else {
        _codec = aCodecs;
    }

    var IMMUNE_HTML = new Array(',', '.', '-', '_', ' ');
    var IMMUNE_HTMLATTR = new Array(',', '.', '-', '_');
    var IMMUNE_CSS = new Array();
    var IMMUNE_JAVASCRIPT = new Array(',', '.', '_');

    return {
        cananicalize: function(sInput, bStrict) {
            if (!sInput) {
                return null;
            }
            var working = sInput, codecFound = null, mixedCount = 1, foundCount = 0, clean = false;
            while (!clean) {
                clean = true;

                _codec.each(function(codec) {
                    var old = working;
                    working = codec.decode(working);

                    if (old != working) {
                        if (codecFound != null && codecFound != codec) {
                            mixedCount ++;
                        }
                        codecFound = codec;
                        if (clean) {
                            foundCount ++;
                        }
                        clean = false;
                    }
                });
            }

            if (foundCount >= 2 && mixedCount > 1) {
                if (bStrict) {
                    throw new com.cmus.antixss.IntrusionException("Input validation failure", "Multiple (" + foundCount + "x) and mixed encoding (" + mixedCount + "x) detected in " + sInput);
                }
            }
            else if (foundCount >= 2) {
                if (bStrict) {
                    throw new com.cmus.antixss.IntrusionException("Input validation failure", "Multiple (" + foundCount + "x) encoding detected in " + sInput);
                }
            }
            else if (mixedCount > 1) {
                    if (bStrict) {
                        throw new com.cmus.antixss.IntrusionException("Input validation failure", "Mixed (" + mixedCount + "x) encoding detected in " + sInput);
                    }
                }
            return working;
        },

        normalize: function(sInput) {
            return sInput.replace(/[^\x00-\x7F]/g, '');
        },

        encodeForHTML: function(sInput) {
            return !sInput ? null : _htmlCodec.encode(IMMUNE_HTML, sInput);
        },

        decodeForHTML: function(sInput) {
            return !sInput ? null : _htmlCodec.decode(sInput);
        },

        encodeForHTMLAttribute: function(sInput) {
            return !sInput ? null : _htmlCodec.encode(IMMUNE_HTMLATTR, sInput);
        },

        encodeForCSS: function(sInput) {
            return !sInput ? null : _cssCodec.encode(IMMUNE_CSS, sInput);
        },

        encodeForJavaScript: function(sInput) {
            return !sInput ? null : _javascriptCodec.encode(IMMUNE_JAVASCRIPT, sInput);
        },

        encodeForJavascript: this.encodeForJavaScript,

        encodeForURL: function(sInput) {
            return !sInput ? null : escape(sInput);
        },

        decodeFromURL: function(sInput) {
            return !sInput ? null : unescape(sInput);
        },

        encodeForBase64: function(sInput) {
            return !sInput ? null : com.cmus.antixss.codec.Base64.encode(sInput);
        },

        decodeFromBase64: function(sInput) {
            return !sInput ? null : com.cmus.antixss.codec.Base64.decode(sInput);
        }
    };
};


$namespace('com.cmus.antixss.reference.logging');

com.cmus.antixss.reference.logging.Log4JSLogFactory = function() {
    var loggersMap = Array();

    var Log4JSLogger = function( sModuleName ) {
        var jsLogger = null;
        var moduleName = sModuleName?sModuleName:null;
        var Level = Log4js.Level;

        var logUrl = false, logApplicationName = false, encodingRequired = false, encodingFunction = $API.encoder().encodeForHTML;

        jsLogger = Log4js.getLogger( moduleName );

        var convertAPILevel = function( nLevel ) {
            var Logger = com.cmus.antixss.Logger;
            switch (nLevel) {
                case Logger.OFF:        return Log4js.Level.OFF;
                case Logger.FATAL:      return Log4js.Level.FATAL;
                case Logger.ERROR:      return Log4js.Level.ERROR;
                case Logger.WARNING:    return Log4js.Level.WARN;
                case Logger.INFO:       return Log4js.Level.INFO;
                case Logger.DEBUG:      return Log4js.Level.DEBUG;
                case Logger.TRACE:      return Log4js.Level.TRACE;
                case Logger.ALL:        return Log4js.Level.ALL;
            }
        };

        return {
            setLevel: function( nLevel ) {
                try {
                    jsLogger.setLevel( convertAPILevel( nLevel ) );
                } catch (e) {
                    this.error( com.cmus.antixss.Logger.SECURITY_FAILURE, "", e );
                }
            },

            trace: function( oEventType, sMessage, oException ) {
                this.log( Level.TRACE, oEventType, sMessage, oException );
            },

            debug: function( oEventType, sMessage, oException ) {
                this.log( Level.DEBUG, oEventType, sMessage, oException );
            },

            info: function( oEventType, sMessage, oException ) {
                this.log( Level.INFO, oEventType, sMessage, oException );
            },

            warning: function( oEventType, sMessage, oException ) {
                this.log( Level.WARN, oEventType, sMessage, oException );
            },

            error: function( oEventType, sMessage, oException ) {
                this.log( Level.ERROR, oEventType, sMessage, oException );
            },

            fatal: function( oEventType, sMessage, oException ) {
                this.log( Level.FATAL, oEventType, sMessage, oException );
            },

            log: function( oLevel, oEventType, sMessage, oException ) {
                switch(oLevel) {
                    case Level.TRACE:       if ( !jsLogger.isTraceEnabled() ) { return; } break;
                    case Level.DEBUG:       if ( !jsLogger.isDebugEnabled() ) { return; } break;
                    case Level.INFO:        if ( !jsLogger.isInfoEnabled()  ) { return; } break;
                    case Level.WARNING:     if ( !jsLogger.isWarnEnabled()  ) { return; } break;
                    case Level.ERROR:       if ( !jsLogger.isErrorEnabled() ) { return; } break;
                    case Level.FATAL:       if ( !jsLogger.isFatalEnabled() ) { return; } break;
                }

                if ( !sMessage ) {
                    sMessage = "";
                }

                sMessage = '[' + oEventType.toString() + '] - ' + sMessage;

                var clean = sMessage.replace("\n","_").replace("\r","_");
                if ( encodingRequired ) {
                    clean = encodingFunction(clean);
                    if ( clean != sMessage) {
                        clean += " [Encoded]";
                    }
                }

                var appInfo =   ( logUrl ? window.location.href : "" ) +
                                ( logApplicationName ? "/" + $API.properties.application.Name : "" );

                jsLogger.log( oLevel, ( appInfo != "" ? "[" + appInfo + "] " : "" ) + clean, oException );
            },

            addAppender: function( oAppender ) {
                jsLogger.addAppender( oAppender );
            },

            isLogUrl: function()                { return logUrl; },
            setLogUrl: function(b)              { logUrl = b; },
            isLogApplicationName: function()    { return logApplicationName; },
            setLogApplicationName: function(b)  { logApplicationName = b; },
            isEncodingRequired: function()      { return encodingRequired; },
            setEncodingRequired: function(b)    { encodingRequired = b; },
            setEncodingFunction: function(f)    { encodingFunction = f; },
            isDebugEnabled: function()          { return jsLogger.isDebugEnabled(); },
            isErrorEnabled: function()          { return jsLogger.isErrorEnabled(); },
            isFatalEnabled: function()          { return jsLogger.isFatalEnabled(); },
            isInfoEnabled: function()           { return jsLogger.isInfoEnabled(); },
            isTraceEnabled: function()          { return jsLogger.isTraceEnabled(); },
            isWarningEnabled: function()        { return jsLogger.isWarnEnabled(); }
        };
    };

    var getLoggerConfig = function( moduleName ) {
        var logConfig = $API.properties.logging;
        if ( logConfig[moduleName] ) {
            logConfig = logConfig[moduleName];
        }
        return logConfig;
    };

    return {
        getLogger: function ( moduleName ) {
            var key = ( typeof moduleName == 'string' ) ? moduleName : moduleName.constructor.toString();
            var logger = loggersMap[key];
            if ( !logger ) {
                logger = new Log4JSLogger(key);

                var logConfig = getLoggerConfig(moduleName);

                logger.setLevel( logConfig.Level );
                logger.setLogUrl( logConfig.LogUrl );
                logger.setLogApplicationName( logConfig.LogApplicationName );
                logger.setEncodingRequired( logConfig.EncodingRequired );

                if ( logConfig.EncodingFunction ) {
                    logger.setEncodingFunction( logConfig.EncodingFunction );
                }

                logConfig.Appenders.each(function(e){
                    if ( logConfig.Layout ) {
                        e.setLayout( logConfig.Layout );
                    }
                    logger.addAppender(e);
                });

                loggersMap[key] = logger;
            }
            return logger;
        }
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.BaseValidationRule = function( sTypeName, oEncoder, oLocale ) {
    var log = $API.logger( "Validation" );
    var EventType = com.cmus.antixss.Logger.EventType;

    var typename = sTypeName;
    var encoder = oEncoder?oEncoder:$API.encoder();
    var allowNull = false;

    var ResourceBundle = com.cmus.antixss.i18n.ResourceBundle;

    var locale = oLocale?oLocale:$API.locale();
    var resourceBundle;

    if ( $API.properties.validation.ResourceBundle ) {
        resourceBundle = ResourceBundle.getResourceBundle( $API.properties.validation.ResourceBundle, locale );
    }

    if ( !resourceBundle ) {
        resourceBundle = $API.resourceBundle();
        log.info( EventType.EVENT_FAILURE, "No Validation ResourceBundle - Defaulting to " + resourceBundle.getName() + "(" + resourceBundle.getLocale().toString() + ")" );
    }

    log.info( EventType.EVENT_SUCCESS, "Validation Rule Initialized with ResourceBundle: " + resourceBundle.getName() );

    return {
        setAllowNull: function(b) { allowNull = b; },

        isAllowNull: function() { return allowNull; },

        getTypeName: function() { return typename; },

        setTypeName: function(s) { typename = s; },

        setEncoder: function(oEncoder) { encoder = oEncoder; },

        getEncoder: function() { return encoder; },

        assertValid: function( sContext, sInput ) {
            this.getValid( sContext, sInput );
        },

        getValid: function( sContext, sInput, oValidationErrorList ) {
            var valid = null;
            try {
                valid = this.getValidInput( sContext, sInput );
            } catch (oValidationException) {
                return this.sanitize( sContext, sInput );
            }
            return valid;
        },

        getValidInput: function( sContext, sInput ) {
            return sInput;
        },

        getSafe: function( sContext, sInput ) {
            var valid = null;
            try {
                valid = this.getValidInput( sContext, sInput );
            } catch (oValidationException) {
                return this.sanitize( sContext, sInput );
            }
            return valid;
        },
        sanitize: function( sContext, sInput ) {
            return sInput;
        },

        isValid: function( sContext, sInput ) {
            var valid = false;
            try {
                this.getValidInput( sContext, sInput );
                valid = true;
            } catch (oValidationException) {
                return false;
            }
            return valid;
        },
        whitelist: function( sInput, aWhitelist ) {
            var stripped = '';
            for ( var i=0;i<sInput.length;i++ ) {
                var c = sInput.charAt(i);
                if ( aWhitelist.contains(c) ) {
                    stripped += c;
                }
            }
            return stripped;
        },

        getUserMessage: function( sContext, sDefault, oContextValues ) {
            return this.getMessage( sContext+".Usr", sDefault+".Usr", oContextValues );
        },

        getLogMessage: function( sContext, sDefault, oContextValues ) {
            return this.getMessage( sContext+".Log", sDefault+".Log", oContextValues );
        },

        getMessage: function( sContext, sDefault, oContextValues ) {
            return resourceBundle.getString( sContext, oContextValues ) ? resourceBundle.getString( sContext, oContextValues ) : resourceBundle.getString( sDefault, oContextValues );
        },

        validationException: function( sContext, sDefault, sValidation, oContextValues ) {
            throw new com.cmus.antixss.reference.validation.ValidationException(
                    this.getUserMessage( sContext+"."+sValidation, sDefault+"."+sValidation, oContextValues ),
                    this.getLogMessage( sContext+"."+sValidation, sDefault+"."+sValidation, oContextValues ),
                    sContext
            );
        }
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.CreditCardValidationRule = function( sTypeName, oEncoder, oLocale ) {
    var _super = new com.cmus.antixss.reference.validation.BaseValidationRule( sTypeName, oEncoder, oLocale );
    var _validationType = "CreditCard";

    var maxCardLength = 19;
    var ccrule;

    var readDefaultCreditCardRule = function() {
        var p = new RegExp( $API.properties.validation.CreditCard );
        var ccr = new com.cmus.antixss.reference.validation.StringValidationRule( "ccrule", _super.getEncoder(), oLocale, p );
        ccr.setMaxLength( maxCardLength );
        ccr.setAllowNull( false );
        return ccr;
    };

    ccRule = readDefaultCreditCardRule();

    var validCreditCardFormat = function( ccNum ) {
        var digitsonly = '';
        var c;
        for (var i=0;o<ccNum.length;i++) {
            c = ccNum.charAt(i);
            if ( c.match( /[0-9]/ ) ) digitsonly += c;
        }

        var sum = 0, digit = 0, addend = 0, timesTwo = false;

        for (var j=digitsonly.length-1; j>=0; j--) {
            digit = parseInt(digitsonly.substring(j,i+1));
            if ( timesTwo ) {
                addend = digit * 2;
                if ( addend > 9 ) addend -= 9;
            } else {
                addend = digit;
            }
            sum += addend;
            timesTwo = !timesTwo;
        }
        return sum % 10 == 0;
    };

    return {
        getMaxCardLength: function() { return maxCardLength; },

        setMaxCardLength: function(n) { maxCardLength = n; },

        setAllowNull: _super.setAllowNull,

        isAllowNull: _super.isAllowNull,

        getTypeName: _super.getTypeName,

        setTypeName: _super.setTypeName,

        setEncoder: _super.setEncoder,

        getEncoder: _super.getEncoder,

        assertValid: _super.assertValid,

        getValid: _super.getValid,

        getValidInput: function( sContext, sInput ) {
            if ( !sInput || sInput.trim() == '' ) {
                if ( this.isAllowNull() ) {
                    return null;
                }
                _super.validationException( sContext, _validationType, "Required", { "context":sContext, "input":sInput } );
            }

            var canonical = ccrule.getValid( sContext, sInput );

            if ( !validCreditCardFormat(canonical) ) {
                _super.validationException( sContext, _validationType, "Invalid", { "context":sContext, "input":sInput } );
            }

            return canonical;
        },

        getSafe: _super.getSafe,

        sanitize: function( sContext, sInput ) {
            return this.whitelist( sInput, com.cmus.antixss.EncoderConstants.CHAR_DIGITS );
        },

        isValid: _super.isValid,

        whitelist: _super.whitelist
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.DateValidationRule = function( sTypeName, oEncoder, oLocale ) {
    var _super = new com.cmus.antixss.reference.validation.BaseValidationRule( sTypeName, oEncoder, oLocale );
    var _validationTarget = "Date";

    var format = DateFormat.getDateInstance();

    var safelyParse = function(sContext,sInput) {
        if ( !sContext || sContext.trim() == '' ) {
            if ( _super.isAllowNull() ) {
                return null;
            }
            _super.validationException( sContext, _validationTarget, "Required", { "context":sContext, "input":sInput, "format":format } );
        }

        var canonical = _super.getEncoder().cananicalize(sInput);

        try {
            return format.parse(canonical);
        } catch (e) {
            _super.validationException( sContext, _validationTarget, "Invalid", { "context":sContext, "input":sInput, "format":format } );
        }
    };

    return {
        setDateFormat: function(fmt) {
            if ( !fmt ) {
                throw new IllegalArgumentException("DateValidationRule.setDateFormat requires a non-null DateFormat");
            }
            format = fmt;
        },

        setAllowNull: _super.setAllowNull,

        isAllowNull: _super.isAllowNull,

        getTypeName: _super.getTypeName,

        setTypeName: _super.setTypeName,

        setEncoder: _super.setEncoder,

        getEncoder: _super.getEncoder,

        assertValid: _super.assertValid,

        getValid: _super.getValid,

        getValidInput: function( sContext, sInput ) {
            return safelyParse(sContext,sInput);
        },

        getSafe: _super.getSafe,

        sanitize: function( sContext, sInput ) {
            var date = new Date(0);
            try {
                date = safelyParse(sContext,sInput);
            } catch (e) { }
            return date;
        },

        isValid: _super.isValid,

        whitelist: _super.whitelist
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.DefaultValidator = function( oEncoder, oLocale ) {
    var rules = Array();
    var encoder = oEncoder?oEncoder:$API.encoder();
    var locale = oLocale?oLocale:com.cmus.antixss.i18n.Locale.getDefault();

    var p = com.cmus.antixss.reference.validation;

    return {
        addRule: function( oValidationRule ) {
            rules[oValidationRule.getName()] = oValidationRule;
        },

        getRule: function( sName ) {
            return rules[sName];
        },

        isValidInput: function( sContext, sInput, sType, nMaxLength, bAllowNull ) {
            try {
                this.getValidInput( sContext, sInput, sType, nMaxLength, bAllowNull );
                return true;
            } catch (e) {
                return false;
            }
        },

        getValidInput: function( sContext, sInput, sType, nMaxLength, bAllowNull, oValidationErrorList ) {
            var rvr = new com.cmus.antixss.reference.validation.StringValidationRule( sType, encoder, locale );
            var p = new RegExp($API.properties.validation[sType]);
            if ( p && p instanceof RegExp ) {
                rvr.addWhitelistPattern( p );
            } else {
                throw new IllegalArgumentException("Invalid Type: " + sType + " not found.");
            }
            rvr.setMaxLength( nMaxLength );
            rvr.setAllowNull( bAllowNull );

            try {
                return rvr.getValid(sContext,sInput);
            } catch (e) {
                if ( e instanceof p.ValidationErrorList && oValidationErrorList ) {
                    oValidationErrorList.addError( sContext, e );
                }
                throw e;
            }
        },

        isValidDate: function( sContext, sInput, oDateFormat, bAllowNull ) {
            try {
                this.getValidDate( sContext, sInput, oDateFormat, bAllowNull );
                return true;
            } catch (e) {
                return false;
            }
        },

        getValidDate: function( sContext, sInput, oDateFormat, bAllowNull, oValidationErrorList ) {
            var dvr = new p.DateValidationRule( sContext, encoder, locale );
            dvr.setAllowNull( bAllowNull );
            dvr.setDateFormat(oDateFormat);
            try {
                return dvr.getValid( sContext, sInput );
            } catch (e) {
                if ( e instanceof p.ValidationErrorList && oValidationErrorList ) {
                    oValidationErrorList.addError( sContext, e );
                }
                throw e;
            }
        },

        getValidCreditCard: function( sContext, sInput, bAllowNull, oValidationErrorList ) {
            var ccr = new p.CreditCardValidationRule( sContext, encoder, locale );
            ccr.setAllowNull(bAllowNull);

            try {
                return ccr.getValid(sContext,sInput);
            } catch (e) {
                if ( e instanceof p.ValidationErrorList && oValidationErrorList ) {
                    oValidationErrorList.addError( sContext, e );
                }
                throw e;
            }
        },

        isValidCreditCard: function( sContext, sInput, bAllowNull ) {
            try {
                this.getValidCreditCard( sContext,sInput,bAllowNull );
                return true;
            } catch (e) {
                return false;
            }
        },

        getValidNumber: function( sContext, sInput, bAllowNull, nMinValue, nMaxValue, oValidationErrorList ) {
            var nvr = new p.NumberValidationRule( sContext, encoder, locale, nMinValue, nMaxValue );
            nvr.setAllowNull(bAllowNull);

            try {
                return nvr.getValid(sContext, sInput);
            } catch(e) {
                if ( e instanceof p.ValidationErrorList && oValidationErrorList ) {
                    oValidationErrorList.addError( sContext, e );
                }
                throw e;
            }
        },

        isValidNumber: function( sContext, sInput, bAllowNull, nMinValue, nMaxValue ) {
            try {
                this.getValidNumber(sContext,sInput,bAllowNull,nMinValue,nMaxValue);
                return true;
            } catch (e) {
                return false;
            }
        },

        getValidInteger: function( sContext, sInput, bAllowNull, nMinValue, nMaxValue, oValidationErrorList ) {
            var nvr = new p.IntegerValidationRule( sContext, encoder, locale, nMinValue, nMaxValue );
            nvr.setAllowNull(bAllowNull);

            try {
                return nvr.getValid(sContext, sInput);
            } catch(e) {
                if ( e instanceof p.ValidationErrorList && oValidationErrorList ) {
                    oValidationErrorList.addError( sContext, e );
                }
                throw e;
            }
        },

        isValidInteger: function( sContext, sInput, bAllowNull, nMinValue, nMaxValue ) {
            try {
                this.getValidInteger(sContext,sInput,bAllowNull,nMinValue,nMaxValue);
                return true;
            } catch (e) {
                return false;
            }
        }
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.IntegerValidationRule = function( sTypeName, oEncoder, oLocale, nMinValue, nMaxValue ) {
    var _super = new com.cmus.antixss.reference.validation.BaseValidationRule( sTypeName, oEncoder, oLocale );
    var _validationTarget = "Integer";

    var minValue = nMinValue?nMinValue:Number.MIN_VALUE;
    var maxValue = nMaxValue?nMaxValue:Number.MAX_VALUE;

    if ( minValue >= maxValue ) {
        throw new IllegalArgumentException( "minValue must be less than maxValue" );
    }

    var safelyParse = function(sContext,sInput) {
        if ( !sInput || sInput.trim() == '' ) {
            if ( _super.allowNull() ) {
                return null;
            }
            _super.validationException( sContext, _validationTarget, "Required", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }

        var canonical = _super.getEncoder().cananicalize(sInput);

        var n = parseInt(canonical);
        if ( n == 'NaN' ) {
            _super.validationException( sContext, _validationTarget, "NaN", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        if ( n < minValue ) {
            _super.validationException( sContext, _validationTarget, "MinValue", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        if ( n > maxValue ) {
            _super.validationException( sContext, _validationTarget, "MaxValue", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        return n;
    };

    return {
        setMinValue: function(n) { minValue = n; },

        getMinValue: function() { return minValue; },

        setMaxValue: function(n) { maxValue = n; },

        getMaxValue: function() { return maxValue; },

        setAllowNull: _super.setAllowNull,

        isAllowNull: _super.isAllowNull,

        getTypeName: _super.getTypeName,

        setTypeName: _super.setTypeName,

        setEncoder: _super.setEncoder,

        getEncoder: _super.getEncoder,

        assertValid: _super.assertValid,

        getValid: _super.getValid,

        getValidInput: function( sContext, sInput ) {
            return safelyParse(sContext,sInput);
        },

        getSafe: _super.getSafe,

        sanitize: function( sContext, sInput ) {
            var n = 0;
            try {
                n = safelyParse(sContext,sInput);
            } catch (e) { }
            return n;
        },

        isValid: _super.isValid,

        whitelist: _super.whitelist
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.NumberValidationRule = function( sTypeName, oEncoder, oLocale, fMinValue, fMaxValue ) {
    var _super = new com.cmus.antixss.reference.validation.BaseValidationRule( sTypeName, oEncoder, oLocale );
    var _validationTarget = 'Number';

    var minValue = fMinValue?fMinValue:Number.MIN_VALUE;
    var maxValue = fMaxValue?fMaxValue:Number.MAX_VALUE;

    if ( minValue >= maxValue ) throw new IllegalArgumentException("MinValue must be less that MaxValue");

    var safelyParse = function( sContext, sInput ) {
        if ( !sInput || sInput.trim() == '' ) {
            if ( _super.isAllowNull() ) {
                return null;
            }
            _super.validationException( sContext, _validationTarget, "Required", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }

        var canonical = _super.getEncoder().cananicalize( sInput );

        var f = 0.0;
        try {
            f = parseFloat( canonical );
        } catch (e) {
            _super.validationException( sContext, _validationTarget, "Invalid", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }

        if ( f == 'NaN' ) {
            _super.validationException( sContext, _validationTarget, "NaN", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        if ( f < minValue ) {
            _super.validationException( sContext, _validationTarget, "MinValue", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        if ( f > maxValue ) {
            _super.validationException( sContext, _validationTarget, "MaxValue", { "context":sContext, "input":sInput, "minValue":minValue, "maxValue":maxValue } );
        }
        return f;
    };

    return {
        setMinValue: function(n) { minValue = n; },

        getMinValue: function() { return minValue; },

        setMaxValue: function(n) { maxValue = n; },

        getMaxValue: function() { return maxValue; },

        setAllowNull: _super.setAllowNull,

        isAllowNull: _super.isAllowNull,

        getTypeName: _super.getTypeName,

        setTypeName: _super.setTypeName,

        setEncoder: _super.setEncoder,

        getEncoder: _super.getEncoder,

        assertValid: _super.assertValid,

        getValid: _super.getValid,

        getValidInput: function( sContext, sInput ) {
            return safelyParse(sContext,sInput);
        },

        getSafe: _super.getSafe,

        sanitize: function( sContext, sInput ) {
            var n = 0;
            try {
                n = safelyParse(sContext,sInput);
            } catch (e) { }
            return n;
        },

        isValid: _super.isValid,

        whitelist: _super.whitelist
    };
};

$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.StringValidationRule = function( sTypeName, oEncoder, oLocale, sWhiteListPattern ) {
    var _super = new com.cmus.antixss.reference.validation.BaseValidationRule( sTypeName, oEncoder, oLocale );
    var _validationTarget = 'String';

    var whitelistPatterns = Array();
    var blacklistPatterns = Array();
    var minLength = 0;
    var maxLength = Number.MAX_VALUE;
    var validateInputAndCanonical = true;

    if ( sWhiteListPattern ) {
        if ( sWhiteListPattern instanceof String ) {
            whitelistPatterns.push( new RegExp(sWhiteListPattern) );
        } else if ( sWhiteListPattern instanceof RegExp ) {
            whitelistPatterns.push( sWhiteListPattern );
        } else {
            throw new IllegalArgumentException("sWhiteListPattern must be a string containing RegExp or a RegExp Object");
        }
    }

    var checkWhitelist = function( sContext, sInput, sOrig ) {
        whitelistPatterns.each(function(p){
            if ( sInput.match(p) ) {
                _super.validationException( sContext, _validationTarget, "Whitelist", { "context":sContext, "input":sInput, "orig":sOrig, "pattern":p.toString(), "minLength":minLength, "maxLength":maxLength, "validateInputAndCanonical":validateInputAndCanonical } );
            }
        });
    };

    var checkBlacklist = function( sContext, sInput, sOrig ) {
        blacklistPatterns.each(function(p){
            if ( sInput.match(p) ) {
                _super.validationException( sContext, _validationTarget, "Blacklist", { "context":sContext, "input":sInput, "orig":sOrig, "pattern":p.toString(), "minLength":minLength, "maxLength":maxLength, "validateInputAndCanonical":validateInputAndCanonical } );
            }
        });
    };

    var checkLength = function( sContext, sInput, sOrig ) {
        if ( sInput.length < minLength ) {
            _super.validationException( sContext, _validationTarget, "MinLength", { "context":sContext, "input":sInput, "orig":sOrig, "minLength":minLength, "maxLength":maxLength, "validateInputAndCanonical":validateInputAndCanonical } );
        }
        if ( sInput.length > maxLength ) {
            _super.validationException( sContext, _validationTarget, "MaxLength", { "context":sContext, "input":sInput, "orig":sOrig, "minLength":minLength, "maxLength":maxLength, "validateInputAndCanonical":validateInputAndCanonical } );
        }
        return sInput;
    };

    var checkEmpty = function( sContext, sInput, sOrig ) {
        if ( !sInput || sInput.trim() == '' ) {
            if ( _super.isAllowNull() ) {
                return null;
            }
            _super.validationException( sContext, _validationTarget, "Required", { "context":sContext, "input":sInput, "orig":sOrig, "minLength":minLength, "maxLength":maxLength, "validateInputAndCanonical":validateInputAndCanonical } );
        }
    };

    return {
        addWhitelistPattern: function(p) {
            if ( p instanceof String ) {
                whitelistPatterns.push( new RegExp(p) );
            } else if ( p instanceof RegExp ) {
                whitelistPatterns.push(p);
            } else {
                throw new IllegalArgumentException("p must be a string containing RegExp or a RegExp Object");
            }
        },

        addBlacklistPattern: function(p) {
            if ( p instanceof String ) {
                blacklistPatterns.push( new RegExp(p) );
            } else if ( p instanceof RegExp ) {
                blacklistPatterns.push(p);
            } else {
                throw new IllegalArgumentException("p must be a string containing RegExp or a RegExp Object");
            }
        },

        setMinLength: function(n) { minLength = n; },

        getMinLength: function() { return minLength; },

        setMaxLength: function(n) { maxLength = n; },

        getMaxLength: function() { return maxLength; },

        setValidateInputAndCanonical: function(b) { validateInputAndCanonical = b; },

        isValidateInputAndCanonical: function() { return validateInputAndCanonical; },

        setAllowNull: _super.setAllowNull,

        isAllowNull: _super.isAllowNull,

        getTypeName: _super.getTypeName,

        setTypeName: _super.setTypeName,

        setEncoder: _super.setEncoder,

        getEncoder: _super.getEncoder,

        assertValid: _super.assertValid,

        getValid: _super.getValid,

        getValidInput: function( sContext, sInput ) {
            var canonical = null;

            if ( checkEmpty( sContext, sInput ) == null ) {
                return null;
            }

            if ( validateInputAndCanonical ) {
                checkLength(sContext, sInput);
                checkWhitelist(sContext,sInput);
                checkBlacklist(sContext,sInput);
            }

            canonical = this.getEncoder().cananicalize(sInput);

            if ( checkEmpty( sContext, canonical, sInput ) == null ) {
                return null;
            }

            checkLength( sContext, canonical, sInput );
            checkWhitelist( sContext, canonical, sInput );
            checkBlacklist( sContext, canonical, sInput );

            return canonical;
        },

        getSafe: _super.getSafe,

        sanitize: function( sContext, sInput ) {
            return this.whitelist( sInput, com.cmus.antixss.EncoderConstants.CHAR_ALNUM );
        },

        isValid: _super.isValid,

        whitelist: _super.whitelist
    };
};


$namespace('com.cmus.antixss.reference.validation');

com.cmus.antixss.reference.validation.ValidationException = function( sUserMessage, sLogMessage ) {
    var oException, sContext;
    if ( arguments[2] && arguments[2] instanceof Exception ) {
        oException = arguments[2];
        if ( arguments[3] && arguments[3] instanceof String ) {
            sContext = arguments[3];
        }
    } else if ( arguments[2] && arguments[2] instanceof String ) {
        sContext = arguments[2];
    }

    var _super = new com.cmus.antixss.EnterpriseSecurityException( sUserMessage, sLogMessage, oException );

    return {
        setContext: function(s) { sContext = s; },
        getContext: function() { return sContext; },
        getMessage: _super.getMessage,
        getUserMessage: _super.getMessage,
        getLogMessage: _super.getLogMessage,
        getStackTrace: _super.getStackTrace,
        printStackTrace: _super.printStackTrace
    };
};

$namespace('Base.antixss.properties');

Base.antixss.properties = {
    application: {
        Name: 'API4JS Base Application'
    },

    httputilities: {
        cookies: {
            ForceSecure: true
        }
    },

    logging: {
        Implementation: com.cmus.antixss.reference.logging.Log4JSLogFactory,
        Level: com.cmus.antixss.Logger.ERROR,
        Appenders: [  ],
        LogUrl: false,
        LogApplicationName: false,
        EncodingRequired: true
    },

    encoder: {
        Implementation: com.cmus.antixss.reference.encoding.DefaultEncoder,
        AllowMultipleEncoding: false
    },

    localization: {
        StandardResourceBundle: API_Standard_en_US,
        DefaultLocale: 'en-US'
    },

    validation: {
        Implementation: com.cmus.antixss.reference.validation.DefaultValidator,
        AccountName: '^[a-zA-Z0-9]{3,20}$',
        SafeString: '[a-zA-Z0-9\\-_+]*',
        Email: '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$',
        IPAddress: '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        URL: '^(ht|f)tp(s?)\\:\\/\\/[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\:\\\'\\/\\\\\\+=&amp;%\\$#_]*)?$',
        CreditCard: '^(\\d{4}[- ]?){3}\\d{4}$',
        SSN: '^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012]))([ -]?)(?!00)\\d\\d\\3(?!0000)\\d{4}$',
        HttpScheme: '^(http|https)$',
        HttpServerName: '^[a-zA-Z0-9_.\\-]*$',
        HttpParameterName: '^[a-zA-Z0-9_]{1,32}$',
        HttpParameterValue: '^[a-zA-Z0-9.\\-\\/+=_ ]*$',
        HttpCookieName: '^[a-zA-Z0-9\\-_]{1,32}$',
        HttpCookieValue: '^[a-zA-Z0-9\\-\\/+=_ ]*$'
    }
};

$API = new com.cmus.antixss.API( Base.antixss.properties );
function encode_HTML(param){
	try
	{
	return $API.encoder().encodeForHTML(param);
	}
	catch(err)
	{
	return param;
	}
};

function encode_JS(param){
	try
	{
	return $API.encoder().encodeForJavaScript(param);
	}
	catch(err)
	{
	return param;
	}
};

function encode_CSS(param){
	try
	{
	return $API.encoder().encodeForCSS(param);
	}
	catch(err)
	{
	return param;
	}
};

function encode_HTMLATTR(parma){
	try
	{
	return $API.encoder().encodeForHTMLAttribute(parma);
	}
	catch(err)
	{
	return param;
	}
};

function encode_URL(parma){
	try
	{
	return $API.encoder().encodeForURL(parma);
	}
	catch(err)
	{
	return param;
	}
};
