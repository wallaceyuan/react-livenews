import axios from 'axios';
import $ from 'jquery'

const url = 'http://api.kankanews.com/kkweb/kkstu/cast/'

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
var cid = 0
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
      return  that._loadNews();
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
    //console.log('cid',this.param.cid)
    var that = this;
    that.isLoading = isLoading;
    if(isLoading){
      var timestamp = Date.parse(new Date());
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


module.exports = {
  getData : getData,
  util    : util,
  test    : test,
  regBr   : regBr
}
