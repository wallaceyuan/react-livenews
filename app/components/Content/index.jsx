import React ,{Component} from 'react'
import fuc from '../../util/helper.jsx'

let outhtml  = '';
let linkPic  = 'http://skin.kankanews.com/onlive/mline/images/link.png';
let journPic = 'http://skin.kankanews.com/onlive/mline/images/xiaowen.jpg'
let loadingPic = 'http://skin.kankanews.com/onlive/mline/images/place.jpg'



class ContentS extends Component {
  render(){
    var data = this.props.data
    var stremid = this.props.stremid
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
          piclist.map(function(obj,i){
            console.log(obj)
          })
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
                            {data.newstext && <div className="desc"><p>{fuc.regBr(data.newstext)}</p></div> }
                            {picontent}
                            {oHtml}
                        </div>
                    </div>
                </div>
              </div>
            </div>
          </div>
    return (
      <div>{html}</div>
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
    }

    componentWillMount(){
        //console.log('componentWillMount');
    }

    render(){
        console.log('121',this.state.newsList)
        var props    = this.props.data.data
        var intro    = props!=''?props.studio.intro:''
        var stremid  = props!=''?props.studio.stremid:''

        return (
            <div className="ul_content">
                <div id="scroller">
                    <div className="maskload"></div>
                    <div className="pulldown">
                        <span className="icon"></span><span className="label">下拉刷新...</span>
                    </div>
                    <div className="smalltxt">
                        <div className="text"><span>核心提示：</span><i>{intro}</i></div>
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
                                return <ContentS data={object}  key={i} stremid ={stremid}/>
                            })
                        }
                    </div>
                    <div id="j_pullLoader" className="more_btnbox hide">
                        <div className="more_btn_loading">
                            <span className="loadingbtn"></span><span className="more_btn">上拉加载更多</span>
                        </div>
                    </div>
                </div>
            </div>
        )
    }
}

export default Content
