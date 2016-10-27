import axios from 'axios';
import $ from 'jquery'
import React ,{Component} from 'react'

let url = 'http://api.kankanews.com/kkweb/kkstu/cast/'
let outhtml  = '';
let linkPic  = 'http://skin.kankanews.com/onlive/mline/images/link.png';
let journPic = 'http://skin.kankanews.com/onlive/mline/images/xiaowen.jpg'
let loadingPic = 'http://skin.kankanews.com/onlive/mline/images/place.jpg'

function getData(id) {
  var timestamp = Date.parse(new Date());
  let u = url+id+'.json?ord=asc?'+timestamp+'&jsoncallback=?';
  return $.getJSON(u)
}

function getNextData(pid,cid) {
  let url = 'http://api.kankanews.com/kkweb/kkstu/next/'+pid+'/'+cid+'.json?ord=desc&jsoncallback=?'
  return $.getJSON(url)
}

function test(pid,cid) {
  var promise = new Promise(function(resolve, reject) {
    window.setTimeout(function() {
      getNextData(pid,cid).then((data)=>{
        resolve(data);
      })
    },2000);
  });
  return promise;
}

function regBr(txt) {
  return txt.replace(/\r\n/g,"<br>")
}


var  b = {
  //streamid:streamid,
  eid:eid, isclose : isclose, page : 0, flag :false, timefalg :0,
  win : $(window), loading : $('.feed-card-loading'), winWidth : document.documentElement.clientWidth,
  loadpic :'http://skin.kankanews.com/onlive/mline/images/place.jpg',
  color :color, date:[], headDate:[], videoSt:'on', done:true, load :false,
  vidoepic:'http://act.shanghaicity.openservice.kankanews.com/iloveshanghai/2015/live/images/play.png',
  uc:false
}

var util = {
  param:{
    cid:0
  },
  viewData :function(){
      var e = 0, l = 0, i = 0, g = 0, f = 0, m = 0;
      var j = window, h = document, k = h.documentElement;
      e = k.clientWidth || h.body.clientWidth || 0;
      l = j.innerHeight || k.clientHeight || h.body.clientHeight || 0;
      g = h.body.scrollTop || k.scrollTop || j.pageYOffset || 0;
      i = h.body.scrollLeft || k.scrollLeft || j.pageXOffset || 0;
      f = Math.max(h.body.scrollWidth, k.scrollWidth || 0);
      m = Math.max(h.body.scrollHeight, k.scrollHeight || 0, l);
      return {scrollTop: g,scrollLeft: i,documentWidth: f,documentHeight: m,viewWidth: e,viewHeight: l};
  },
  _initScrollEnd: function(cid){
    this.param.cid = cid
    var that = this;
    var timeout = null;
    $('.more_btn_loading').css('display','block');
    if(parseInt(streamid) ){
      if(b.flag) return;
      if(timeout) {
        clearTimeout(timeout);
      }
      return
    }
    $('.more_btn_loading').css('display','block');
    if(b.flag) return;
    if(timeout) {
      clearTimeout(timeout);
    }
    var vd = that.viewData();
    that.ald = 0;
    if(vd.viewHeight + vd.scrollTop + that.ald >= vd.documentHeight){
      return that._loadNews().then((data)=>{
        b.done = true;
        if(data.length == 0){
          $('.more_btn').html('已经加载全部');$('.loadingbtn').css('opacity',0);
          b.flag = true;
        }else{
          $('.more_btn').html('上拉加载更多');$('.loadingbtn').css('opacity',0);
          return data
        }
      });
    }
  },
  _loadNews: function() {
    var scrolltime = $('.allnews').last().attr('data-time');
    if(scrolltime == null){
      return;
    }
    $('.more_btn').html('加载中……');$('.loadingbtn').css('opacity',1);
    var that = this;
    return that._setLoadingState(true);
  },
  _setLoadingState: function(isLoading){
    var that = this;
    that.isLoading = isLoading;
    if(isLoading){
      var scrolltime = $('.allnews').last().attr('data-time');
      $('.more_btnbox').css('display','block');
      if(b.isclose == 1){
        var od = 'asc';
      }else{
        var od = 'desc';
      }
      var url = 'http://api.kankanews.com/kkweb/kkstu/next/'+scrolltime+'/'+this.param.cid+'.json?ord='+od;
      return that.render(scrolltime,this.param.cid);
    }
  },
  render: function(pid,cid) {
    b.done = false;
    if(b.flag){
      $('.more_btn').html('已经加载全部');$('.loadingbtn').css('opacity',0);
      b.done = true;
      return false
    }
    $('.more_btn').html('加载中……');$('.loadingbtn').css('opacity',1);
    return getNextData(pid,cid)
  },
}

function render(data) {
  var journalistintro = data.journalistintro?'['+data.journalistintro+']':'[看看新闻主持人]';
  var journalist = data.journalist?data.journalist:' ';

  if(data.videoframe){
      if(parseInt(streamid)){
        var picontent = <div className="pics video before" data-src={data.videoframe}>
                          <div className="poster">
                              <img src={data.titlepic} />
                              <div className="playbut"></div>
                          </div>
                          <video id="Video{data.timestamp}"  width="100%" height="100%" preload="none" controls="true" poster={data.titlepic} webkit-playsinline="true"><source src={data.videourl} type="video/mp4" /></video>
                      </div>
      }else{
        //console.log('videoframe',data.videoframe)
        var patt = /http(.*?)"/gi;
        var str = data.videoframe
        var iUrl = str.match(patt)[0].split('\"')[0]
        var picontent = <div className="pics video before" data-src={str}>
                          <iframe height='450' width='530' src={iUrl} frameBorder='0' allowFullScreen />
                        </div>
      }
  }else{
    var piclist = data.titlepic?data.titlepic.split("|"):'';
    if(piclist.length >1){
        var pictwo = '';
        if(piclist.length == 2){pictwo = 'two';}
        var style = {
          'backgroundImage':'url({loadingPic})'
        }
        var picontent = <div className="pics more {pictwo} clearfix">
                          {
                            piclist.map(function(obj,i){
                              <li><span><img className="demos-image" style={style}  data-time={data.newstime?data.newstime.split(' ')[1]:''}  data-original={obj} src="'+b.loadpic+'" /></span></li>
                            })
                          }
                        </div>;
    }else{
        if(piclist[0]){
            var picontent = <div className="pics"><li><span><img src={piclist[0]}  width="100%" onload="app.loadImage()" /></span></li></div>;
        }else{
            var picontent ='';
        }
    }
  }
  if(data.outlink){
      var oHtml = data.outlink.map(function (obj) {
          <span className="outlink"><a href={obj.link}>{obj.title}</a></span>
      })
  }else{
      var oHtml = ''
  }

  var html = <div className="live_list allnews" data-time={data.timestamp} data-date={data.newstime?data.newstime.split(' ')[0]:''}>
              <div className="list_con">
                <div className="content">
                  <div className="item">
                      <p className="portrait">
                      {data.journalistpic?<img src={data.journalistpic}/>:<img src={journPic}/>}
                      </p>
                      <div className="itemW">
                          <div className="news">
                              <div className="man">
                                  {data.journalistintro ||  data.journalist?<span className="identity">'+journalistintro+'</span>:<span className="identity">[看看新闻主持人]</span>}
                                  {data.journalistintro ||  data.journalist?<span className="name">'+journalist+'</span>:<span className="name">小文</span>}
                                  <span className="time">{data.newstime?data.newstime.split(' ')[1]:''}</span>
                              </div>
                              <p className="title">
  {data.titleurl?<a href={data.titleurl}>{data.title}<i><img src={linkPic} width="16" height="16" /></i></a>:data.title}
                              </p>
                              {data.newstext && <div className="desc"><p>{regBr(data.newstext)}</p></div> }
                              {picontent}
                              {oHtml}
                          </div>
                      </div>
                  </div>
                </div>
              </div>
            </div>
    return html
}

module.exports = {
  getData : getData,
  util    : util,
  test    : test,
  regBr   : regBr,
  render  : render
}
