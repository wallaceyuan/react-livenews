import React ,{Component} from 'react'
import fuc from '../../util/helper.jsx'
import $ from 'jquery'
import iScroll from 'iscroll/build/iscroll-probe'
let myScroll

class ContentS extends Component {
  render(){
    var stremid = this.props.stremid
    var data = this.props.data
    return (
      <div>{fuc.render(data)}</div>
    )
  }
}

class ScrollWeb extends Component {
  state = {
    newsList: []
  }
  componentWillReceiveProps(nextProps){
    console.log(nextProps)
    this.setState({
      newsList : nextProps.newsList,
    })
  }
  render(){
    var streamid = this.props.streamid
    return(
        <div id="scroller">
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

class ReactIScroll extends Component {
  componentWillMount(){
    console.log($('.ul_content'))

  }
  render(){
    console.log(this.props)
    return (
        <div id="scroller">{this.props.children}</div>
    )
  }
}


var options = {
  preventDefault: false,
  mouseWheel: true,
  scrollbars: false,
  preventDefaultException: {tagName: /^(INPUT|TEXTAREA|BUTTON|SELECT|A|IFRAME|VIDEO)$/},
  probeType: 1,
  fadeScrollbars: false,
  checkDOMChanges:true,
  useTransition:true
}

class Content extends Component {
    state = {
        newsList : [1]
    }
    Props = {
        value: '开始渲染'
    }

    componentWillReceiveProps(nextProps){
        //console.log('componentWillReceiveProps',nextProps);
        var props    = nextProps.data.newsList
        this.setState({
            newsList: props
        });
    }

    shouldComponentUpdate(nextProps,nextState){
        //console.log('shouldComponentUpdate',nextProps,nextState);
        return true;
    }

    componentWillUpdate(nextProps,nextState){
        //console.log('componentWillUpdate');
        if (this.refs.iScroll) {
            //this.refs.iScroll.refresh()
        }
    }

    componentWillMount(){
        //console.log('componentWillMount');
    }

    render(){
        //console.log('render')
        var props    = this.props.data.data
        var intro    = props!=''?props.studio.intro:''
        var streamid = props!=''?props.studio.streamid:''
        var dd = $('.fixeddd').height()
				$('.fixe .ul_content').css({
					'top': dd - 50 + 'px'
				});
				$('.timeCollection.tip').css({
					'top': dd + 'px'
				});
        return (
            <div className="ul_content">
              <ScrollWeb newsList={this.state.newsList} intro={intro} streamid={streamid}/>
            </div>
        )
    }
    componentDidUpdate() {
      myScroll = new iScroll('.ul_content', {
        preventDefault: false,
        mouseWheel: true,
        scrollbars: false,
        preventDefaultException: {tagName: /^(INPUT|TEXTAREA|BUTTON|SELECT|A|IFRAME|VIDEO)$/},
        probeType: 1,
        fadeScrollbars: false,
        checkDOMChanges:true,
        useTransition:true
      });
      setTimeout(function(){
        myScroll.refresh();
      },50)
    }
}

export default Content
