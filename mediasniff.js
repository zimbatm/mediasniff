#!/usr/bin/env node
/****** MediaSniffer *****\

=> Get the content you browse on the disk

TODO:
 * target directory
 * detect for complete files

\*************************/

/*
 * sudo sysctl -w net.inet.tcp.tso=0
 */
var pcap = require('pcap'),
  sys = require('sys'),
  fs = require('fs'),
  buffer = require('buffer'),
  path = require('path'),
  growl, ID3File;

try {
  growl = require('growl');
  growl.binVersion(function(err, version) {
    if (err) {
      _p(err);
      growl = null;
    }
  });
} catch(e) {
  _p("Growl not available. `npm install growl`");
}

try {
  ID3File = require('id3');
} catch(e) {
  _p("ID3 lib not available. `npm install id3`");
}

function MediaSniffer() { }
exports.MediaSniffer = MediaSniffer;

MediaSniffer.defaults = {
  iface: '', // auto
  filter: "tcp port 80",
  session: null,
  outdir: ".",
  mime_types: {
  //  "image/png" : ".png",
  //  "text/css"  : ".css",
  //  "image/jpeg": ".jpeg",
    "audio/mpeg": ".mp3",   // grooveshark.com
    "video/x-flv": ".flv",  // youtube, youporn :-p
    "video/webm" : ".webm", // youtube HTMl5 mode
    "video/mp4"  : ".mp4"   // vimeo.com HD
  }
  //debug: false
}

MediaSniffer.prototype.start = function(options) {
  if (this._started) return false;
  
  var opts = _merge(MediaSniffer.defaults, options || {}),
    tracker = new pcap.TCP_tracker();

  if (opts.debug) _p(opts);

  if (!opts.session) {
     opts.session = pcap.createSession(opts.iface, opts.filter);
  }
  
  // Link
  opts.session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    tracker.track_packet(packet);
  });
  
  
  tracker.on('http response', function (session, http) {
    var head = http.response.headers["Content-Type"],
      encoding = http.response.headers["Content-Encoding"],
      clength = http.response.headers["Content-Length"],
      ext;

    if (head) {
      head = head.split(';')[0]
      ext = opts.mime_types[head];
      session._ext = ext;
    }

    //_p([http.request.headers.Host, http.request.url]);
    if (opts.debug) _p([head, ext, encoding]);//, http.request.headers.Host]);

    // TODO: handle gzip Content-Encoding
    if (encoding || !ext) { return }

    // Missing Content-Lenght
    if (!clength) { _p("Missing content-length"); return }

    session._writerBuffer = new buffer.Buffer(parseInt(clength));
    session._writerBuffer._pos = 0; // where to write
    session._path = path.join(opts.outdir, (new Date).getTime() + ext);
    _p(session._path + " buffering " + clength + " bytes");
  });

  tracker.on('http response body', function (session, http, data) {
    if (session._writerBuffer) {
      if (session._writerBuffer.length - session._writerBuffer._pos < data.length) {
        _p("ERROR: buffer überflow");
      }
      data.copy(session._writerBuffer, session._writerBuffer._pos);
      session._writerBuffer._pos += data.length;
      _p(session._path + " < " + session._writerBuffer._pos + '/' + session._writerBuffer.length);
    }
  });

  tracker.on('http response complete', function (session, http) {
    // TODO: depending on the media type, move the file to a more sensitive name ?
    if (session._writerBuffer) {
      if (session._writerBuffer._pos != session._writerBuffer.length) {
        _p("ËRRÖR: wtf ?");
      }
      var filepath = session._path;

      if (ID3File && session._ext == ".mp3") {
        var id3 = new ID3File(session._writerBuffer);
        id3.parse();
        filepath = id3.get("album") + '-' + id3.get("artist") + '-' + id3.get("title") + '.mp3';
      }

      _p("Writing " + filepath);
      writer = fs.createWriteStream(filepath);
      writer.write(session._writerBuffer);
      writer.on("drain", function() {
        writer.end();
        _p("Done with " + filepath);
        delete session._writerBuffer;
      });
    }
  });

  this._started = opts;
  _p("MediaSniff started");
  return true;
}

MediaSniffer.prototype.stop = function() {
  if (this._started) {
    // FIXME: is this enough ?
    this._stated.session.removeAllListeners('packet');
    this._stated.session.end();
    delete this._started;
  }
}

function _p(obj) {
  var str = sys.inspect(obj);
  sys.puts(str);
  /*if (growl) {
    growl.notify(str);
  }*/
}

function _merge(a, b) {
  var obj = {};
  
  Object.keys(a).forEach(function(key) {
    obj[key] = a[key];
  });
  
  Object.keys(b).forEach(function(key) {
    obj[key] = b[key];
  });
  
  return obj;
}

function bufferClone(b1) {
  var b2 = new buffer.Buffer(b1.length);
  b1.copy(b2, 0, 0);
  return b2;
}

// Run the code, this should go in a cli
var ms = new MediaSniffer();
ms.start();
