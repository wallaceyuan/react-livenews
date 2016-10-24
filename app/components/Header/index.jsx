import React, { Component } from 'react';
import $ from 'jquery'

class Header extends Component {
  constructor(props){
    super(props);
  }
  render() {
    var studio = this.props.data
    if(studio && parseInt(studio.streamid)){
      $('.contentWrapper').addClass('fixe');
      $('.roseLive_head_con').addClass('fixeddd');
      var vidoeW  = '<div class="videoW"></div>';
      $('.roseLive_head').append(vidoeW);
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
