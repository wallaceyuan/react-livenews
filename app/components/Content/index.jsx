import React ,{Component} from 'react'
import ReactDOM, { findDOMNode } from 'react-dom';
import $ from 'jquery'
import iScroll from 'iscroll/build/iscroll-probe'
import fuc from '../../util/helper.jsx'

let myScroll

let options = {
    preventDefault: false,
    mouseWheel: true,
    scrollbars: false,
    preventDefaultException: {tagName: /^(INPUT|TEXTAREA|BUTTON|SELECT|A|IFRAME|VIDEO)$/},
    probeType: 1,
    fadeScrollbars: false,
    checkDOMChanges:true,
    useTransition:true
}

class ContentS extends Component {
  posterClick = ()=>{
    let poster = findDOMNode(this.refs.poster)
    let ele = findDOMNode(this.refs.VideoComp);
    let id = $(ele).attr('id')
    $(poster).addClass('reClick');
    let video = document.getElementById(id);
    $(video).css('display','block');
    if(video.paused){
      video.style.width = '100%';
      video.style.height = '100%';
      video.play();
      $(poster).css('display','none');
    }
    video.addEventListener("pause", function () {
      $(poster).removeClass('reClick');
      $(poster).css('display','block');
      video.style.width = '1px';
      video.style.height = '1px';
      $(poster).find('.poster').css({
        'height':'100',
        'width':'100%'
      });
    }, false);
  }
  componentWillMount(){
/*    var data = this.props.data
    console.log(data)
    if(data.inc && data.bar){
      console.log('删除')
      $('.fresh .timeCollection').eq(0).remove()
    }*/
  }
  componentWillReceiveProps(nextProps){
    var data = nextProps.data
  }
  render(){
    var stremid = this.props.stremid
    var data = this.props.data
    return (
      <div>{fuc.render(data,stremid,this)}</div>
    )
  }
}

class CommentComp extends Component {
  state = {
    newsList: [],
    date:''
  }
  componentWillReceiveProps(nextProps){
    var that = this,
        newsList = nextProps.newsList
    for(var i = 0;i<newsList.length;i++){
      if(newsList[i].inc){
        if(newsList[i].timeC == newsList[i+1].timeC){
            newsList[i+1].bar = 0
        }
      }
    }
    this.setState({
      newsList : newsList,
    })
  }
  componentWillMount(){
    console.log('CommentComp componentWillMount',this.props)
    this.setState({
      newsList : this.props.newsList,
    })
  }
  render(){
    var streamid = this.props.streamid
    return(
        <div>
          <div className="maskload"></div>
          <div className="pulldown">
              <span className="icon"></span><span className="label">下拉刷新...</span>
          </div>
          <div className="smalltxt">
              <div className="text"><span>核心提示：</span><i>{this.props.intro}</i></div>
          </div>
          <div className="topW">
              <div className="ui-newstips-wrap tipBand">
                  <div className="ui-newstips">
                      <i></i><div>新消息</div><span className="ui-badge-num">123</span>
                  </div>
              </div>
          </div>
          <div className="fresh">
              {
                  this.state.newsList.map(function(object, i){
                      return <ContentS data={object}  key={i} stremid ={streamid}/>
                  })
              }
          </div>
          <div id="j_pullLoader" className="more_btnbox hide">
              <div className="more_btn_loading">
                  <span className="loadingbtn"></span><span className="more_btn">上拉加载更多</span>
              </div>
          </div>
      </div>
    )
  }
}

class WebIScroll extends Component {
  state = {
      newsList : [1],
      intro    : '',
      streamid : '',
      id       : 0
  }
  componentWillMount(){
    //console.log('componentWillMount WebIScroll')
    this.setState({
        newsList : this.props.newsList,
        intro    : this.props.intro,
        streamid : this.props.streamid,
        id       : this.props.id
    });
  }
  componentWillReceiveProps(nextProps){
      //console.log('componentWillReceiveProps ReactIScroll',nextProps)
      var props    = nextProps.newsList
      this.setState({
          newsList : props,
          intro    : nextProps.intro,
          streamid : nextProps.streamid,
          id       : nextProps.id
      });
  }
  render(){
    //console.log('WebIScroll render')
    return (
      <CommentComp newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.streamid} id={this.state.id}/>
    )
  }
  scrollFunc(){
    var rosHeight = $('.roseLive_head_con').height()+$('.smalltxt').height()+2*$('.timeCollection.sub').height();
    var vd = fuc.viewData();
    if(vd.scrollTop>rosHeight){
      $('.timeCollection.tip').css('display','block').html($('.timeCollection.sub').eq(0).html());
    }else{
      $('.timeCollection.tip').css('display','none');
    }
    $('.timeCollection.sub').each(function(i){
      var judgTimeT = $(this).position().top;
      if(judgTimeT<vd.scrollTop){
        $('.timeCollection.tip').html($(this).html());
      }
    });
  }
  componentDidMount(){
    $('.maskload').css('display','none')
    //console.log('componentDidMount WebTScroll')
    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    var that = this
    console.log(176, this.props)
    $(window).on(scrollEvent, function(){
        var ret = fuc.util._initScrollEnd(that.props.id)
        if(ret){
          ret.then((data)=>{
            if(data.length){
              var olddata = that.state.newsList
              var join = olddata.concat(data);
              that.setState({
                newsList:join
              })
            }
          })
        }
        that.scrollFunc()
    });

    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    $(window).on(scrollEvent,function(){

    });

  }
  componentDidUpdate() {
    //console.log('componentDidUpdate WebTScroll')
  }
}

class ReactIScroll extends Component {
  state = {
      newsList : [1],
      intro:'',
      streamid:''
  }
  componentWillMount(){
    //console.log('componentWillMount ReactIScroll')
    this.setState({
        newsList : this.props.newsList,
        intro    : this.props.intro,
        streamid : this.props.streamid
    });
  }
  componentWillUpdate(nextProps,nextState){
    //console.log('componentWillUpdate ReactIScroll');
  }
  componentWillReceiveProps(nextProps){
      //console.log(173,'componentWillReceiveProps ReactIScroll',nextProps)
      this.setState({
          newsList: nextProps.newsList,
          intro:nextProps.intro,
          streamid:nextProps.streamid
      });
  }
  render(){
    //console.log('ReactIScroll render',this.state.newsList)
    var dd = $('.fixeddd').height()
    $('.fixe .ul_content').css({
      'top': dd - 50 + 'px'
    });
    $('.timeCollection.tip').css({
      'top': dd + 'px'
    });
    //console.log('render ReactIScroll')
    return (
      <CommentComp newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.streamid}/>
    )
  }
  scrollFunc(){
		var dd = $('.fixeddd').height();
		if($('.timeCollection.sub').eq(0).length == 0){
			return
		}
		$('.timeCollection.tip').css('display','block');
		var startS = $('.timeCollection.sub').eq(0).offset().top;
		if(startS<dd){
			$('.timeCollection.tip').css('display','block').html($('.timeCollection.sub').html());
		}
		if(startS>dd){
			$('.timeCollection.tip').css('display','none');
		}
		$('.timeCollection.sub').each(function(i){
			var judgTimeT = $(this).offset().top;
			if(judgTimeT<dd){
				$('.timeCollection.tip').html($(this).html());
			}
		});
  }
  componentDidMount(){
    myScroll = new iScroll('.ul_content',options);
    var scroll = fuc.scroll,
        that = this
    myScroll.on('scroll', function () {
      var scint = this
      scroll.onscroll(scint)
      that.scrollFunc()
    });
    myScroll.on('scrollEnd', function () {
      that.scrollFunc()
      var scint = this
      var ret = scroll.onscrollEnd(scint,that.props.id)
      if(ret){
        ret.then((data)=>{
          var olddata = that.state.newsList
          var join = olddata.concat(data);
          that.setState({
            newsList:join
          })
        })
      }
    });
    myScroll.refresh();
    setTimeout(function(){
      $('.maskload').css('display','none')
      myScroll.refresh();
    },500)
  }
  componentDidUpdate() {
    //console.log('componentDidUpdate ReactIScroll')
    myScroll.refresh();
    setTimeout(function(){
      $('.maskload').css('display','none')
      myScroll.refresh();
    },500)
  }
}

class Combine extends Component {
  state = {
    newsList : [],
    intro    : '',
    streamid : '',
  }
  componentWillReceiveProps(nextProps){
    console.log(310,nextProps)
    this.setState({
      newsList : nextProps.newsList,
      intro    : nextProps.intro,
      streamid : nextProps.streamid,
      id       : nextProps.id
    })
  }
  render(){
    var streamid = this.props.streamid
    if(streamid){
      var html = <ReactIScroll newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.streamid} id={this.state.id}/>
    }else{
      var html = <WebIScroll newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.treamid} id={this.props.id}/>
    }
    //console.log('Combine render')
    return(
      <div id="scroller">{html}</div>
    )
  }
}

class Content extends Component {
    state = {
        newsList : [1],
    }
    Props = {
        value: '开始渲染'
    }
    componentWillReceiveProps(nextProps){
        var props    = nextProps.data.newsList
        this.setState({
            newsList: props
        });
    }

    render(){
        console.log('Content render',this.props)
        var props    = this.props.data.data
        var intro    = props!=''?props.studio.intro:''
        var streamid = props!=''?props.studio.streamid:''
        var id       = this.props.data.id
        console.log(230,'streamid',streamid,id)
        return (
            <div>
              <div className="timeCollection tip"></div>
              <div className="ul_content" ref="ul_content">
                <Combine newsList={this.state.newsList} intro={intro} streamid={streamid} id={id}/>
              </div>
            </div>
        )
    }

    componentDidMount (){
      //console.log('componentDidMount Content')
      console.log(365,this.props.data.id)
      var that = this
      var flagtime = setInterval(function(){
        fuc._incData(that.props.data.id).then((data)=>{
          var oldA = that.state.newsList
          data.reverse().map(function(obj,i){
              oldA.unshift(obj)
          })
          that.setState({
            newsList:oldA
          })
          console.log(oldA)
        })
			},1000*60);
    }

    componentDidUpdate() {
      console.log('componentDidUpdate content')
    }
}

export default Content
