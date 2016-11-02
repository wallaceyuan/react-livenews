import axios from 'axios';
import $ from 'jquery'
import React ,{Component} from 'react'
import ReactVideo from 'react.video';

let url = 'http://api.kankanews.com/kkweb/kkstu/cast/'
let linkPic  = 'http://skin.kankanews.com/onlive/mline/images/link.png';
let journPic = 'http://skin.kankanews.com/onlive/mline/images/xiaowen.jpg'
let loadingPic = 'http://skin.kankanews.com/onlive/mline/images/place.jpg'
let date = [], headDate = []
let outhtml  = '';


function getQueryString(name) {
  var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
  var r = window.location.search.substr(1).match(reg);
  if (r != null) return unescape(r[2]); return null;
}

function dataMap(arr,inc=0){
  return arr.map(function(obj,i){
    var objDate = obj.newstime.split(' ')[0]
    obj.timeC = objDate
    if($.inArray(objDate,date) == -1){
      date.push(objDate)
      obj.bar = 1
    }else{
      obj.bar = 0
    }
    inc?obj.inc = 1:obj.inc = 0
    inc?obj.bar = 1:''
  })
}

function getData(id) {
  var timestamp = Date.parse(new Date());
  let u = url+id+'.json?ord=asc?'+timestamp+'&jsoncallback=?';
  return $.getJSON(u).then((data)=>{
    const dataNews = data.news.reverse()
    dataMap(dataNews)
    return data
  })
}

function getNextData(pid,cid) {
  const url = 'http://api.kankanews.com/kkweb/kkstu/next/'+pid+'/'+cid+'.json?ord=desc&jsoncallback=?'
  console.log('url',url)
  return $.getJSON(url).then((data)=>{
    const dataM = data.reverse()
    dataMap(dataM)
    return dataM
  })
}

function _incData(cid) {
  if(!b.done) return
  var time = $('.fresh .allnews').first().attr('data-time');
  if(time == undefined){
    time = 1;
  }
  var timestamp = Date.parse(new Date());
  var request_url = `http://api.kankanews.com/kkweb/kkstu/incre/${time}/${cid}.json?${timestamp}&jsoncallback=?`;
  //console.log(request_url)
  return $.getJSON(request_url).then((data)=>{
/*    data[0].newstime = "10月20日 06:39"
    data[1].newstime = "10月20日 08:10"
    data[2].newstime = "10月20日 18:10"*/
    dataMap(data.reverse(),1)
    return data
  })
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
  more_btn:function(cid){
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
    this.more_btn(cid)
    var vd = this.viewData();
    this.ald = 0;
    if(vd.viewHeight + vd.scrollTop + this.ald >= vd.documentHeight){
      return this._loadNews().then((data)=>{
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
    console.log('_loadNews',scrolltime)
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

var scroll = {
  onscroll:function(scint){
    //app._vidoeTimeBand();
    console.log('scroll', b.done);
    if (!b.done)return
    var $pullDown = $('.pulldown');
    var $pullUp = $('.more_btn_loading');
    if (scint.y > 40) {
      $pullDown.addClass('flip').html('松开后刷新...');
    } else {
      $pullDown.removeClass('flip').find('.more_btn').html('下拉刷新...');
    }
    if (b.flag)return
    if (scint.maxScrollY - scint.y > 40) {
      $pullUp.addClass('flip');
    }
  },
  onscrollEnd:function(scint,cid){
    util.more_btn(cid)
    //app._vidoeTimeBand();
    if (!b.done) return
    var $pullDown = $('.pulldown');
    var $pullUp = $('.more_btn_loading');
    if ($pullDown.hasClass('flip')) {
      $pullDown.removeClass('flip').html('加载中...');
      if(b.done){
        //app._incData('down');  // 0 表示下拉刷新
      }
    }
    if (b.flag) return
    console.log(scint.maxScrollY , scint.y );
    if (scint.maxScrollY - scint.y > -5) {
      console.log('b.done', b.done);
      $pullUp.removeClass('flip').find('.more_btn').html('加载中...');
      // 1 表示上拉刷新
      return util._loadNews().then((data)=>{
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
  }
}

function render(data,streamid,conts) {
  var journalistintro = data.journalistintro?'['+data.journalistintro+']':'[看看新闻主持人]';
  var journalist = data.journalist?data.journalist:' ';

  if(data.videoframe){
      if(parseInt(streamid)){
        var source = [{src: data.videourl,type: 'video/mp4'}]
        var picontent = <div className="pics video before" data-src={data.videoframe}>
                          <div className="poster" onClick={conts.posterClick} ref={'poster'}>
                              <img src={data.titlepic} />
                              <div className="playbut"></div>
                          </div>
                          <ReactVideo
                              id={data.timestamp}
                              ref={'VideoComp'}
                              cls={'custom-video'}
                              height={'100%'} width={'100%'}
                              poster={data.titlepic}
                              source={source}>
                          </ReactVideo>
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
        var pictwo = 'pics more clearfix';
        if(piclist.length == 2){pictwo += ' two';}
        var style = {
          'backgroundImage':'url({loadingPic})'
        }
        var picontent = <div className={pictwo}>
                          {
                            piclist.map(function(obj,i){
                              return <li><span><img className="demos-image" style={style}  data-time={data.newstime?data.newstime.split(' ')[1]:''}  data-original={obj} src={obj} /></span></li>
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
  var outlink = ''
  if(data.outlink && data.outlink.length){
      outlink = data.outlink.map(function(obj,i){
        var style = {
          color:obj.color
        }
        return <span className="outlink" ><a href={obj.link} style={style}>{obj.title}</a></span>
      })
  }

  var dd = data.newstime?data.newstime.split(' ')[0]:''

  var html = <div className="live_list allnews" data-time={data.timestamp} data-date={data.newstime?data.newstime.split(' ')[0]:''}>
              {data.bar? <div className="timeCollection sub" data-time={dd} ref='timeBar'>{dd}</div>:''}
              <div className="list_con">
                <div className="content">
                  <div className="item">
                      <p className="portrait">
                      {data.journalistpic?<img src={data.journalistpic}/>:<img src={journPic}/>}
                      </p>
                      <div className="itemW">
                          <div className="news">
                              <div className="man">
                                  {data.journalistintro ||  data.journalist?<span className="identity">{journalistintro}</span>:<span className="identity">[看看新闻主持人]</span>}
                                  {data.journalistintro ||  data.journalist?<span className="name">{journalist}</span>:<span className="name">小文</span>}
                                  <span className="time">{data.newstime?data.newstime.split(' ')[1]:''}</span>
                              </div>
                              <p className="title">
  {data.titleurl?<a href={data.titleurl}>{data.title}<i><img src={linkPic} width="16" height="16" /></i></a>:data.title}
                              </p>
                              {data.newstext && <div className="desc"><p>{regBr(data.newstext)}</p></div> }
                              {picontent}
                              {outlink}
                          </div>
                      </div>
                  </div>
                </div>
              </div>
            </div>
    return html
}

module.exports = {
  getQueryString : getQueryString,
  viewData       : util.viewData,
  getData        : getData,
  util           : util,
  regBr          : regBr,
  render         : render,
  scroll         : scroll,
  _incData       : _incData
}
