import React, { Component } from 'react';
import {Header, Content } from '../../components';
import $ from 'jquery'

import fuc from '../../util/helper.jsx'
import './index.css';


class Compse extends Component {
  render(){
    var props = this.props
    if(props.data){
      props.data.studio.streamid = ''
    }
    return (
      <div>
        <Header data={props.data.studio} />
        <Content data={props} />
      </div>
    )
  }
}

class App extends Component {
  constructor(props) {
    super(props);
  }
  state = {
    data     : '',
    color    : 'blue',
    newsList : [],
  }
  componentWillMount(){
    var idParam = fuc.getQueryString('id')
    idParam = idParam?idParam:254
    var timestamp = Date.parse(new Date());
    var color = this.state.color
    fuc.getData(idParam).then((data) => {
      $('.mask').css('display','none');
      $('.contentWrapper').css('display','block');
      if(data.studio.color == 0){
        color = 'red'
      }
      if(data.studio.color == 1){
        color = 'blue'
      }
      if(data.studio.color == 2){
        color = 'gry'
      }
      this.setState({
        color: color,
        data:data,
        newsList:data.news,
        id:idParam
      })
      $('.contentWrapper').addClass(color)

    }).then(()=>{
      var studio = this.state.data.studio
    });
    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    $('.more_btn_loading').css('display','block');
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

  }
  componentDidMount(){
    //console.log('componentDidMount');
  }
  render() {
    //console.log(83,this.state.data)
    return (
      <Compse data={this.state.data} color={this.state.color} newsList={this.state.newsList} id = {this.state.id}/>
    )
  }
}

export default App;
