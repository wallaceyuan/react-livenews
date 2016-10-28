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
    newsList: []
  }
  componentWillReceiveProps(nextProps){
    this.setState({
      newsList : nextProps.newsList,
    })
  }
  componentWillMount(){
    console.log(this.props,63)
    this.setState({
      newsList : this.props.newsList,
    })
  }
  render(){
    var streamid = this.props.streamid
    return(
        <div >
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
      intro:'',
      streamid:''
  }
  componentWillMount(){

  }
  componentWillReceiveProps(nextProps){
      console.log('componentWillReceiveProps ReactIScroll',nextProps)
      var props    = nextProps.newsList
      this.setState({
          newsList: props
      });
      this.state.intro = nextProps.intro
      this.state.streamid = nextProps.streamid
  }
  render(){
    return (
      <CommentComp newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.streamid}/>
    )
  }
  componentDidMount(){
    $('.maskload').css('display','none')
    console.log('componentDidMount WebTScroll')
    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    var that = this
    $(window).on(scrollEvent, function(){
        var ret = fuc.util._initScrollEnd(254)
        if(ret){
          ret.then((data)=>{
            if(data.length){
              var olddata = that.state.newsList
              var join = olddata.concat(data.reverse());
              that.setState({
                newsList:join
              })
            }
          })
        }
    });
  }
  componentDidUpdate() {
    console.log('componentDidUpdate WebTScroll')
  }
}

class ReactIScroll extends Component {
  state = {
      newsList : [1],
      intro:'',
      streamid:''
  }
  componentWillMount(){
    console.log(this.props)
    console.log('render ReactIScroll')
    var newsList    = this.props.newsList
    var intro    = this.props.intro
    var streamid = this.props.streamid
    console.log(157,newsList)
    this.setState({
        newsList: newsList,
        intro:intro,
        streamid:streamid
    });
  }
  componentWillUpdate(nextProps,nextState){
    console.log('componentWillUpdate ReactIScroll');
  }
  componentWillReceiveProps(nextProps){
      console.log('componentWillReceiveProps ReactIScroll',nextProps)
      var props    = nextProps.newsList
      this.setState({
          newsList: props
      });
      this.state.intro = nextProps.intro
      this.state.streamid = nextProps.streamid
  }
  render(){
    console.log(174,this.state.newsList,'render')
    var dd = $('.fixeddd').height()
    $('.fixe .ul_content').css({
      'top': dd - 50 + 'px'
    });
    $('.timeCollection.tip').css({
      'top': dd + 'px'
    });
    console.log('render ReactIScroll')
    return (
      <CommentComp newsList={this.state.newsList} intro={this.state.intro} streamid={this.state.streamid}/>
    )
  }
  componentDidMount(){
    myScroll = new iScroll('.ul_content',options);
    var scroll = fuc.scroll,
        that = this
    myScroll.on('scroll', function () {
      var scint = this
      scroll.onscroll(scint)
    });
    myScroll.on('scrollEnd', function () {
      var scint = this
      var ret = scroll.onscrollEnd(scint,254)
      if(ret){
        ret.then((data)=>{
          console.log(data)
          var olddata = that.state.newsList
          var join = olddata.concat(data.reverse());
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
    console.log('componentDidUpdate ReactIScroll')
    myScroll.refresh();
    setTimeout(function(){
      $('.maskload').css('display','none')
      myScroll.refresh();
    },500)
  }
}

class Combine extends Component {
  render(){
    var dd = this.props.streamid
    if(dd){
      var aa = <ReactIScroll {...this.props}/>
    }else{
      var aa = <WebIScroll {...this.props}/>
    }
    console.log(225,this.props)
    return(
      <div id="scroller">{aa}</div>
    )
  }
}

class Content extends Component {
    state = {
        newsList : [1]
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
        console.log('render')
        var props    = this.props.data.data
        var intro    = props!=''?props.studio.intro:''
        var streamid = props!=''?props.studio.streamid:''
        console.log(230,'streamid',streamid)
        if(streamid){
          console.log(this.state.newsList)
          var html = <ReactIScroll newsList={this.state.newsList} intro={intro} streamid={streamid}/>
        }else{
          var html = <ReactIScroll newsList={this.state.newsList} intro={intro} streamid={streamid}/>
        }
        return (
            <div className="ul_content" ref="ul_content">
              <Combine newsList={this.state.newsList} intro={intro} streamid={streamid}/>
            </div>
        )
    }
    componentDidMount (){
      console.log('componentDidMount Content')

    }
    componentDidUpdate() {
      console.log('componentDidUpdate content')

    }
}

export default Content
