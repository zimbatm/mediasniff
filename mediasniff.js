#!/usr/bin/env node
/****** MediaSniffer *****\
 *
 * Get the content you browse on the disk
 *
 */

/*
 * sudo sysctl -w net.inet.tcp.tso=0
 */
var pcap = require('pcap'),
  sys = require('sys'),
  fs = require('fs'),
  buffer = require('buffer'),
  path = require('path');

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
      ext;

    if (head) {
      head = head.split(';')[0]
      ext = opts.mime_types[head];
    }

    //_p([http.request.headers.Host, http.request.url]);
    if (opts.debug) _p([head, ext, encoding]);//, http.request.headers.Host]);

    // TODO: handle gzip Content-Encoding
    if (encoding || !ext) { return }

    session._writer = fs.createWriteStream(path.join(opts.outdir, (new Date).getTime() + ext));
    _p(session._writer.path + " opened");
  });

  tracker.on('http response body', function (session, http, data) {
    if (session._writer) {
      var d2 = bufferClone(data);
      // FIXME: writer throttling ?
      session._writer.write(d2);
    }
  });

  tracker.on('http response complete', function (session, http, data) {
    // TODO: depending on the media type, move the file to a more sensitive name ?
    if (session._writer) {
      _p(session._writer.path + " written");
      session._writer.end();
      delete session._writer;
    }
  });

  this._started = opts;
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
  sys.puts(sys.inspect(obj));
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