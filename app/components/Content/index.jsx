import React ,{Component} from 'react'

let outhtml  ='';
let linkPic  = 'http://skin.kankanews.com/onlive/mline/images/link.png';
let journPic = 'http://skin.kankanews.com/onlive/mline/images/xiaowen.jpg'

class ContentS extends Component {
  render(){
    var data = this.props.data
    var journalistintro = data.journalistintro?'['+data.journalistintro+']':'[看看新闻主持人]';
    var journalist = data.journalist?data.journalist:' ';

    console.log(data.newstime)
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

  render(){
    var props = this.props.data.data
    var intro = props!=''?props.studio.intro:''
    var newsList = props!=''?props.news:['']
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
              newsList.map(function(object, i){
                return <ContentS data={object}  key={i}/>
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
