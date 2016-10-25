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


var util = {
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
  _initScrollEnd: function(){
    var that = this;
    var timeout = null;
    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    $('.more_btn_loading').css('display','block');
    if(parseInt(streamid) ){
      if(b.flag) return;
      if(timeout) {
        clearTimeout(timeout);
      }
      return
    }
    $(window).on('touchmove',function(){
      //that._timeBand();
    });
    $(window).on(scrollEvent, function(){
      //that._timeBand();
      $('.more_btn_loading').css('display','block');
      if(b.flag) return;
      if(timeout) {
        clearTimeout(timeout);
      }
      timeout = setTimeout(function(){
        var vd = this.viewData();
        that.ald = 0;
        if(vd.viewHeight + vd.scrollTop + that.ald >= vd.documentHeight){
          that._loadNews();
        }
      }, 100);
    });
  /*    $(window).on('swipeDown', function(){
      if(b.isclose == '0'){
        var rosHeight = $('.roseLive_head_con ').height();
        var vd = viewData();
        if(vd.scrollTop < rosHeight){
          if(b.done){
            app._incData('down');
          }
        }
      }
    });*/
  },
  _loadNews: function() {
    var scrolltime = $('.allnews').last().attr('time');
    //console.log('_loadNews',scrolltime);
    if(scrolltime == null){
      return;
    }
    $('.more_btn').html('加载中……');$('.loadingbtn').css('opacity',1);
    var that = this;
    that._setLoadingState(true);
  },
  _setLoadingState: function(isLoading){
    var that = this;
    that.isLoading = isLoading;
    if(isLoading){
      var timestamp = Date.parse(new Date());
      var scrolltime = $('.allnews').last().attr('time');
      $('.more_btnbox').css('display','block');
      if(b.isclose == 1){
        var od = 'asc';
      }else{
        var od = 'desc';
      }
      var url = 'http://api.kankanews.com/kkweb/kkstu/next/'+scrolltime+'/'+b.eid+'.json?ord='+od;
      that.render(url);
    }
  },
  render: function(url) {
    console.log('render');
    b.done = false;
    if(b.flag){
      $('.more_btn').html('已经加载全部');$('.loadingbtn').css('opacity',0);
      b.done = true;
      return
    }
    $('.more_btn').html('加载中……');$('.loadingbtn').css('opacity',1);
    var insert =$(".fresh .allnews:last");
    $.ajax({
      type : "get",
      async: false,
      url  : url, //跨域请求的URL
      dataType : "jsonp",
      jsonp: "jsoncallback",
      jsonpCallback: "success_jsonpCallback",
      success : function(response){
        /*2.2.3 初始化下拉*/
        b.done = true;
        if(response ==""){
          $('.more_btn').html('已经加载全部');$('.loadingbtn').css('opacity',0);
          b.flag = true;
          return;
        }
        /*下拉加载*/
        for(var i=0;i<response.length;i++){
          var newhtml = orderList(response[i],i,b.streamid);
          if(insert.length  == 0){
            $(".fresh").append(newhtml);
          }else{
            insert.after(newhtml);
          }
          if(i == response.length-1){
            $('.more_btn').html('上拉加载更多');$('.loadingbtn').css('opacity',0);
          }
        }//for
        if(response.length!=0){
          timeBar();
          if(parseInt(b.streamid)){
            app._vidoeTimeBand();
            app.Refresh();
          }else{
            app._timeBand();
          }
        }
      },
      error: function(XMLHttpRequest, textStatus, errorThrown) {

      }
    });
  },
}


module.exports = {
  getData : getData,
  util    :util,
  test    :test
}
