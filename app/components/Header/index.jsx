import React, { Component } from 'react';
import $ from 'jquery'

class Header extends Component {
  constructor(props){
    super(props);
  }
  render() {
    var studio = this.props.data
    if(studio){
      studio.streamid = 144
    }
    if(studio && parseInt(studio.streamid)){
      $('.contentWrapper').addClass('fixe');
      $('.roseLive_head_con').addClass('fixeddd');
      var head = <div className="videoW">
                    <video id="Video"  onwebkitfullscreenchange="OnFullscreen(this)" onresize="OnFullscreen(this)" controls="" width="100%" height="100%" poster="" x-webkit-airplay="true" webkit-playsinline="true"><source src={studio.streamurl} type="video/mp4" /></video>
                 </div>
    }else if(studio && studio.titlepic){
      var head = <div className="head_img"><img className="livebackground pic_ground" src={studio.titlepic} alt="" width="100%" /></div>
    }
    return (
      <div className="roseLive_head_con">
        <div className="roseLive_head">
            {head}
          </div>
      </div>
    );
  }
}

export default Header;
